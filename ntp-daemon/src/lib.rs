//! This crate contains the main ntp-daemon code for ntpd-rs and is not intended as
//! a public interface at this time. It follows the same version as the main ntpd-rs
//! crate, but that version is not intended to give any stability guarantee. Use at
//! your own risk.
//!
//! Please visit the [ntpd-rs](https://github.com/pendulum-project/ntpd-rs) project
//! for more information.
#![forbid(unsafe_code)]

pub mod config;
mod ipfilter;
pub mod keyexchange;
pub mod nts_key_provider;
pub mod observer;
mod peer;
mod server;
pub mod sockets;
pub mod spawn;
mod system;
pub mod tracing;

use std::{error::Error, sync::Arc};

pub use config::Config;
pub use observer::{ObservablePeerState, ObservableState};
pub use system::spawn;
//#[cfg(fuzz)]
pub use ipfilter::fuzz::fuzz_ipfilter;
use tracing_subscriber::EnvFilter;

use crate::config::NtpDaemonOptions;

const VERSION: &str = env!("CARGO_PKG_VERSION");

pub async fn main() -> Result<(), Box<dyn Error>> {
    let options = NtpDaemonOptions::try_parse_from(std::env::args())?;

    match options.action {
        config::NtpDaemonAction::Help => {
            println!("{}", config::long_help_message());
        }
        config::NtpDaemonAction::Version => {
            eprintln!("ntp-daemon {VERSION}");
        }
        config::NtpDaemonAction::Run => run(options).await?,
    }

    Ok(())
}

async fn run(options: NtpDaemonOptions) -> Result<(), Box<dyn Error>> {
    let has_log_override = options.log_filter.is_some();
    let log_filter = options
        .log_filter
        // asserts that the arc is not shared. There is no reason it would be,
        // we just use Arc to work around EnvFilter not implementing Clone
        .map(|this| Arc::try_unwrap(this).unwrap())
        .unwrap_or_else(|| EnvFilter::new("info"));

    // Setup some basic tracing now so we are able
    // to log errors when loading the full configuration.
    let finish_tracing_init = crate::tracing::init(log_filter);

    let mut config = match Config::from_args(options.config, vec![], vec![]).await {
        Ok(c) => c,
        Err(e) => {
            // print to stderr because tracing is not yet setup
            eprintln!("There was an error loading the config: {e}");
            std::process::exit(exitcode::CONFIG);
        }
    };

    // make sure to only drop at the end of this scope
    let _tracing_state = match finish_tracing_init(&mut config, has_log_override) {
        Ok(s) => s,
        Err(e) => {
            // print to stderr because tracing was not correctly initialized
            eprintln!("Failed to complete logging setup: {e}");
            std::process::exit(exitcode::CONFIG);
        }
    };

    // Warn/error if the config is unreasonable. We do this after finishing
    // tracing setup to ensure logging is fully configured.
    config.check();

    // we always generate the keyset (even if NTS is not used)
    let keyset = crate::nts_key_provider::spawn(config.keyset).await;

    #[cfg(feature = "hardware-timestamping")]
    let clock_config = config.clock;

    #[cfg(not(feature = "hardware-timestamping"))]
    let clock_config = ClockConfig::default();

    ::tracing::debug!("Configuration loaded, spawning daemon jobs");
    let (main_loop_handle, channels) = crate::spawn(
        config.system,
        clock_config,
        &config.peers,
        &config.servers,
        keyset.clone(),
    )
    .await?;

    if let Some(nts_ke_config) = config.nts_ke {
        let _join_handle = crate::keyexchange::spawn(nts_ke_config, keyset);
    }

    crate::observer::spawn(
        &config.observe,
        channels.peer_snapshots_receiver,
        channels.server_data_receiver,
        channels.system_snapshot_receiver,
    )
    .await;

    Ok(main_loop_handle.await??)
}

pub(crate) mod exitcode {
    /// An internal software error has been detected.  This
    /// should be limited to non-operating system related
    /// errors as possible.
    pub const SOFTWARE: i32 = 70;

    /// You did not have sufficient permission to perform
    /// the operation.  This is not intended for file system
    /// problems, which should use `NOINPUT` or `CANTCREAT`,
    /// but rather for higher level permissions.
    pub const NOPERM: i32 = 77;

    /// Something was found in an unconfigured or misconfigured state.
    pub const CONFIG: i32 = 78;
}
