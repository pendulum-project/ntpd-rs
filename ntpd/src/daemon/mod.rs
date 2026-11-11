// TODO: Eliminate allow.
#![allow(unused)]

mod clock;
pub mod config;
#[cfg(target_os = "linux")]
mod csptp_server;
#[cfg(target_os = "linux")]
mod csptp_source;
mod dns;
pub mod keyexchange;
mod local_ip_provider;
mod ntp_source;
pub mod nts_key_provider;
pub mod observer;
#[cfg(feature = "pps")]
mod pps_source;
mod server;
mod sock_source;
pub mod sockets;
pub mod spawn;
mod system;
pub mod tracing;

use std::sync::Arc;
use std::{error::Error, io::IsTerminal, path::Path};

use ::tracing::{info, warn};
use clock_steering::unix::UnixClock;
pub use config::Config;
use ntp_proto::{NtpConfig, SourceConfig};
pub use observer::ObservableState;
use statime_algo::{ClockConfig, ControllerConfig, StdKalmanStorage};
use statime_base::Duration;
use tokio::runtime::Builder;
use tracing_subscriber::util::SubscriberInitExt;

use config::NtpDaemonOptions;

use crate::daemon::clock::NtpClockWrapper;
#[cfg(target_os = "linux")]
use crate::daemon::csptp_server::CsptpServerTask;
use crate::daemon::nts_key_provider::KeysetConfig;
use crate::daemon::spawn::ntp::{NtpSpawner, NtpSpawnerConfig};
use crate::daemon::spawn::ntp_nts::NtpNtsSpawner;
use crate::daemon::spawn::ntp_nts_pool::NtpNtsPoolSpawner;
use crate::daemon::spawn::ntp_pool::{NtpPoolSpawner, NtpPoolSpawnerConfig};
use crate::daemon::system::{System, SystemConfig};
use crate::daemon::tracing::LogReloadTaskStarter;
use crate::notify::notify_ready;

use self::tracing::LogLevel;

const VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn main() -> Result<(), Box<dyn Error>> {
    let options = NtpDaemonOptions::try_parse_from(std::env::args())?;

    #[cfg(feature = "openssl")]
    rustls_openssl::default_provider()
        .install_default()
        .expect("Failed to use rustls_openssl");

    match options.action {
        config::NtpDaemonAction::Help => {
            println!("{}", config::long_help_message());
        }
        config::NtpDaemonAction::Version => {
            eprintln!("ntp-daemon {VERSION}");
        }
        config::NtpDaemonAction::Run => run(&options).map_err(|e| e as Box<dyn Error>)?,
    }

    Ok(())
}

#[derive(Debug, Copy, Clone)]
pub(crate) enum Application {
    Deamon,
    MetricsExporter,
    #[expect(unused)]
    Ctl,
}

// initializes the logger so that logs during config parsing are reported. Then it overrides the
// log level based on the config if required.
pub(crate) fn initialize_logging_parse_config(
    initial_log_level: Option<LogLevel>,
    config_path: Option<&Path>,
    no_clock_steering: bool,
    app: Application,
) -> (Config, Option<LogReloadTaskStarter>) {
    let mut log_level = initial_log_level.unwrap_or_default();

    let (config_tracing, _) = crate::daemon::tracing::tracing_init(log_level, None, true);
    let (config, tracing_inst, task_starter) =
        ::tracing::subscriber::with_default(config_tracing, || {
            let config =
                match Config::from_args(config_path.as_ref(), no_clock_steering, vec![], vec![]) {
                    Ok(c) => c,
                    Err(e) => {
                        // print to stderr because tracing is not yet setup
                        eprintln!("There was an error loading the config: {e}");
                        std::process::exit(exitcode::CONFIG);
                    }
                };

            if let Some(config_log_level) = config.observability.log_level
                && initial_log_level.is_none()
            {
                log_level = config_log_level;
            }

            let log_path = match app {
                Application::Deamon => config.observability.log_path.clone(),
                Application::MetricsExporter => {
                    config.observability.log_path_metrics_exporter.clone()
                }
                Application::Ctl => None,
            };

            let ansi_colors = config
                .observability
                .ansi_colors
                .unwrap_or_else(|| log_path.is_none() && std::io::stdout().is_terminal());

            // set a default global subscriber from now on
            let (tracing_inst, task_starter) =
                self::tracing::tracing_init(log_level, log_path, ansi_colors);
            (config, tracing_inst, task_starter)
        });
    tracing_inst.init();

    (config, task_starter)
}

#[expect(
    clippy::too_many_lines,
    reason = "FIXME: Split out configuration handling once we start looking at reloading the configuration."
)]
fn run(options: &NtpDaemonOptions) -> Result<(), Box<dyn Error>> {
    #[cfg(feature = "seccomp")]
    statime_seccomp::Log.enable()?;

    let (config, task_starter) = initialize_logging_parse_config(
        options.log_level,
        options.config.as_deref(),
        options.no_clock_steering,
        Application::Deamon,
    );

    let runtime = if config.servers.is_empty() {
        Builder::new_current_thread().enable_all().build()?
    } else {
        Builder::new_multi_thread().enable_all().build()?
    };

    let result = runtime.block_on(async move {
        if let Some(task_starter) = task_starter {
            task_starter.start();
        }

        // give the user a warning that we use the command line option
        if config.observability.log_level.is_some() && options.log_level.is_some() {
            info!("Log level override from command line arguments is active");
        }

        // Warn/error if the config is unreasonable. We do this after finishing
        // tracing setup to ensure logging is fully configured.
        config.check();

        ::tracing::debug!("Configuration loaded, spawning daemon jobs");
        let clock: NtpClockWrapper = if config.system_clock.steered {
            NtpClockWrapper::new_utc(UnixClock::CLOCK_REALTIME)
        } else {
            NtpClockWrapper::new_unsteered_utc(UnixClock::CLOCK_REALTIME)?
        };
        // FIXME: Implement proper configuration of controllers.
        let (controller, system_clock_id) =
            statime_algo::KalmanController::<StdKalmanStorage<_>, _>::new(
                clock.clone(),
                config.system_clock.generate_clock_config(),
                config.generate_controller_config(),
            )
            .map_err(|error| std::io::Error::other(format!("{error:?}")))?;
        let system = Arc::new(System::new(
            clock,
            controller,
            system_clock_id,
            SystemConfig {
                minimum_retry_timeout: std::time::Duration::from_secs(1),
                maximum_retry_timeout: std::time::Duration::from_mins(10),
            },
            // FIXME: Add ntp configuration back in.
            NtpConfig::default(),
            config.generate_keyset_config(),
            #[cfg(target_os = "linux")]
            config.generate_csptp_config(),
        ));

        let system_clone = system.clone();
        let main_loop_handle = tokio::spawn(async move { system_clone.run().await });

        for source in &config.sources {
            match source {
                config::SourceConfig::NtpServer(source_config) => {
                    system.add_spawner(Box::new(NtpSpawner::new(
                        source_config.generate_spawner_config(&config),
                    )));
                }
                config::SourceConfig::NtpNtsServer(source_config) => {
                    system.add_spawner(Box::new(NtpNtsSpawner::new(
                        source_config.generate_spawner_config(&config)?,
                    )?));
                }
                config::SourceConfig::NtpPool(source_config) => {
                    system.add_spawner(Box::new(NtpPoolSpawner::new(
                        source_config.generate_spawner_config(&config),
                    )));
                }
                config::SourceConfig::NtpNtsPool(source_config) => {
                    system.add_spawner(Box::new(NtpNtsPoolSpawner::new(
                        source_config.generate_spawner_config(&config)?,
                    )?));
                }
                config::SourceConfig::Sock(config) => todo!(),
                #[cfg(feature = "pps")]
                config::SourceConfig::Pps(source_config) => {
                    use crate::daemon::spawn::pps::PpsSpawner;

                    system.add_spawner(Box::new(PpsSpawner::new(
                        source_config.generate_spawner_config(),
                    )));
                }
                #[cfg(target_os = "linux")]
                config::SourceConfig::Csptp(source_config) => {
                    use crate::daemon::spawn::csptp::CsptpSpawner;
                    system.add_spawner(Box::new(CsptpSpawner::new(
                        source_config.generate_spawner_config(&config),
                    )));
                }
            }
        }

        for server in &config.servers {
            #[expect(clippy::async_yields_async, reason = "Server spawning needs to be async to deal with loading the keyset on demand, but also must yield a joinhandle which is awaitable.")]
            match server {
                config::ServerConfig::Ntp(server_config) => {
                    system
                        .add_server(async |clock, managers| {
                            let server_config = server_config.generate_server_config();
                            let mut keyset_provider = managers.keyset_provider().await;
                            let server = managers.ntp_manager().new_server(
                                ntp_proto::ServerConfig {
                                    denylist: server_config.denylist.clone(),
                                    allowlist: server_config.allowlist.clone(),
                                    rate_limiting_cache_size: server_config
                                        .rate_limiting_cache_size,
                                    rate_limiting_cutoff: server_config.rate_limiting_cutoff,
                                    require_nts: server_config.require_nts,
                                    accepted_versions: server_config.accept_ntp_versions.clone(),
                                },
                                clock,
                                keyset_provider.borrow_and_update().clone(),
                            );
                            server::ServerTask::spawn(server, server_config, keyset_provider)
                        })
                        .await;
                }
                config::ServerConfig::Ntske(server_config) => {
                    system.add_server(async |_clock, managers| {
                        let keyset_provider = managers.keyset_provider().await;
                        keyexchange::spawn(server_config.generate_server_config(), keyset_provider)
                    }).await;
                }
                #[cfg(target_os = "linux")]
                config::ServerConfig::Csptp(server_config) => {
                    system.add_server(async |clock, managers| {
                        match server_config.protocol {
                            config::CsptpCarierProtocol::UdpV4 => {
                                match managers.netptp_ipv4() {
                                    Ok(network) => CsptpServerTask::spawn(managers.csptp_manager(), network, csptp_server::CsptpServerConfig {  }),
                                    Err(e) => {
                                        warn!("Could not start CSPTP server because network is not openable: {e}");
                                        tokio::spawn(async {})
                                    }
                                }
                            }
                            config::CsptpCarierProtocol::UdpV6 => {
                                match managers.netptp_ipv6() {
                                    Ok(network) => CsptpServerTask::spawn(managers.csptp_manager(), network, csptp_server::CsptpServerConfig {  }),
                                    Err(e) => {
                                        warn!("Could not start CSPTP server because network is not openable: {e}");
                                        tokio::spawn(async {})
                                    }
                                }
                            }
                        }
                    }).await;
                }
            }
        }

        // FIXME: Replace with proper new observer code once available.
        /*observer::spawn(
            &config.observability,
            channels.source_snapshots,
            channels.server_data_receiver,
            channels.system_snapshot_receiver,
            clock,
        );*/

        let _ = notify_ready().await;

        main_loop_handle
            .await
            .map_err(|e| Box::new(e) as Box<dyn Error>)?
            .map_err(|e| e as Box<dyn Error>)
    });

    runtime.shutdown_background();

    result
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
