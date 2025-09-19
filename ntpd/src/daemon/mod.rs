mod clock;
pub mod config;
pub mod keyexchange;
mod local_ip_provider;
mod ntp_source;
pub mod nts_key_provider;
pub mod observer;
#[cfg(feature = "pps")]
mod pps_source;
#[cfg(feature = "ptp")]
mod ptp_source;
#[cfg(feature = "ptp")]
mod ptp_integration_test;
#[cfg(feature = "ptp")]
mod ptp_source_integration_test;
mod server;
mod sock_source;
pub mod sockets;
pub mod spawn;
mod system;
pub mod tracing;
mod util;

use std::{error::Error, path::PathBuf};

use ::tracing::info;
pub use config::Config;
use ntp_proto::KalmanClockController;
pub use observer::ObservableState;
pub use system::spawn;
use tokio::runtime::Builder;
use tracing_subscriber::util::SubscriberInitExt;

use config::NtpDaemonOptions;

use self::tracing::LogLevel;

const VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn main() -> Result<(), Box<dyn Error>> {
    let options = NtpDaemonOptions::try_parse_from(std::env::args())?;

    match options.action {
        config::NtpDaemonAction::Help => {
            println!("{}", config::long_help_message());
        }
        config::NtpDaemonAction::Version => {
            eprintln!("ntp-daemon {VERSION}");
        }
        config::NtpDaemonAction::Run => run(options)?,
    }

    Ok(())
}

// initializes the logger so that logs during config parsing are reported. Then it overrides the
// log level based on the config if required.
pub(crate) fn initialize_logging_parse_config(
    initial_log_level: Option<LogLevel>,
    config_path: Option<PathBuf>,
) -> Config {
    let mut log_level = initial_log_level.unwrap_or_default();

    let config_tracing = crate::daemon::tracing::tracing_init(log_level, true);
    let config = ::tracing::subscriber::with_default(config_tracing, || {
        match Config::from_args(config_path, vec![], vec![]) {
            Ok(c) => c,
            Err(e) => {
                // print to stderr because tracing is not yet setup
                eprintln!("There was an error loading the config: {e}");
                std::process::exit(exitcode::CONFIG);
            }
        }
    });

    if let Some(config_log_level) = config.observability.log_level {
        if initial_log_level.is_none() {
            log_level = config_log_level;
        }
    }

    // set a default global subscriber from now on
    let tracing_inst = self::tracing::tracing_init(log_level, config.observability.ansi_colors);
    tracing_inst.init();

    config
}

fn run(options: NtpDaemonOptions) -> Result<(), Box<dyn Error>> {
    let config = initialize_logging_parse_config(options.log_level, options.config);

    let runtime = if config.servers.is_empty() && config.nts_ke.is_empty() {
        Builder::new_current_thread().enable_all().build()?
    } else {
        Builder::new_multi_thread().enable_all().build()?
    };

    runtime.block_on(async {
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
        let clock = clock_config.clock;
        let (main_loop_handle, channels) = spawn::<KalmanClockController<_, _>>(
            config.synchronization.synchronization_base,
            config.synchronization.algorithm,
            config.source_defaults,
            clock_config,
            &config.sources,
            &config.servers,
            keyset.clone(),
        )
        .await?;

        for nts_ke_config in config.nts_ke {
            let _join_handle = keyexchange::spawn(nts_ke_config, keyset.clone());
        }

        observer::spawn(
            &config.observability,
            channels.source_snapshots,
            channels.server_data_receiver,
            channels.system_snapshot_receiver,
            clock,
        );

        Ok(main_loop_handle.await??)
    })
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
