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

use ::tracing::info;
pub use config::Config;
#[cfg(feature = "__internal-fuzz")]
pub use ipfilter::fuzz::fuzz_ipfilter;
pub use observer::{ObservablePeerState, ObservableState, ObservedPeerState};
pub use system::spawn;
use tracing_subscriber::util::SubscriberInitExt;

use config::NtpDaemonOptions;

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
    let mut log_level = options.log_level.unwrap_or_default();

    let config_tracing = self::tracing::tracing_init(log_level);
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

    if let Some(config_log_level) = config.observability.log_level {
        if options.log_level.is_none() {
            log_level = config_log_level;
        }
    }

    // set a default global subscriber from now on
    let tracing_inst = self::tracing::tracing_init(log_level);
    tracing_inst.init();

    // give the user a warning that we use the command line option
    if config.observability.log_level.is_some() && options.log_level.is_some() {
        info!("Log level override from command line arguments is active");
    }

    // Warn/error if the config is unreasonable. We do this after finishing
    // tracing setup to ensure logging is fully configured.
    config.check();

    // we always generate the keyset (even if NTS is not used)
    let keyset = nts_key_provider::spawn(config.keyset).await;

    #[cfg(feature = "hardware-timestamping")]
    let clock_config = config.clock;

    #[cfg(not(feature = "hardware-timestamping"))]
    let clock_config = config::ClockConfig::default();

    ::tracing::debug!("Configuration loaded, spawning daemon jobs");
    let (main_loop_handle, channels) = spawn(
        config.synchronization,
        config.peer_defaults,
        clock_config,
        &config.peers,
        &config.servers,
        keyset.clone(),
    )
    .await?;

    for nts_ke_config in config.nts_ke {
        let _join_handle = keyexchange::spawn(nts_ke_config, keyset.clone());
    }

    observer::spawn(
        &config.observability.observe,
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
