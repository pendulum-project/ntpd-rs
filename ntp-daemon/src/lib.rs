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

use std::error::Error;

pub use config::Config;
pub use observer::{ObservablePeerState, ObservableState};
pub use system::spawn;
//#[cfg(fuzz)]
use ::tracing::info;
pub use ipfilter::fuzz::fuzz_ipfilter;
use tracing_subscriber::util::SubscriberInitExt;

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
    let mut log_filter = options.log_filter.unwrap_or_default();

    let config_tracing = crate::tracing::tracing_init(log_filter);
    let config = ::tracing::subscriber::with_default(config_tracing, || {
        async {
            match Config::from_args(options.config, vec![], vec![]).await {
                Ok(c) => c,
                Err(e) => {
                    // print to stderr because tracing is not yet setup
                    eprintln!("There was an error loading the config: {e}");
                    std::process::exit(exitcode::CONFIG);
                }
            }
        }
    })
    .await;

    if let Some(config_log_filter) = config.log_filter {
        if options.log_filter.is_none() {
            log_filter = config_log_filter;
        }
    }

    // set a default global subscriber from now on
    let tracing_inst = crate::tracing::tracing_init(log_filter);
    tracing_inst.init();

    // give the user a warning that we use the command line option
    if config.log_filter.is_some() && options.log_filter.is_some() {
        info!("Log filter override from command line arguments is active");
    }

    // Warn/error if the config is unreasonable. We do this after finishing
    // tracing setup to ensure logging is fully configured.
    config.check();

    // we always generate the keyset (even if NTS is not used)
    let keyset = crate::nts_key_provider::spawn(config.keyset).await;

    #[cfg(feature = "hardware-timestamping")]
    let clock_config = config.clock;

    #[cfg(not(feature = "hardware-timestamping"))]
    let clock_config = config::ClockConfig::default();

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
