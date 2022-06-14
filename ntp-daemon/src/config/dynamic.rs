use crate::tracing::ReloadHandle;
use ntp_proto::{NtpDuration, SystemConfig};
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use tokio::task::JoinHandle;
use tokio::{net::UnixListener, sync::RwLock};
use tracing_subscriber::EnvFilter;

use clap::Args;
use serde::{Deserialize, Serialize};

use super::ConfigureConfig;

fn parse_env_filter(input: &str) -> Result<String, tracing_subscriber::filter::ParseError> {
    // run the parser to error on any invalid input
    let _ = EnvFilter::builder().with_regex(false).parse(input)?;

    // but we actually send `String` over, because it is (De)Serialize
    Ok(input.to_string())
}

#[derive(Debug, Args, Serialize, Deserialize)]
pub struct ConfigUpdate {
    /// Change the log filter
    #[clap(long, parse(try_from_str = parse_env_filter))]
    pub log_filter: Option<String>,

    /// The maximum duration in seconds the system clock is allowed to change in a single jump
    /// before we conclude something is seriously wrong. This is used to limit
    /// the changes to the clock to reasonable ammounts, and stop issues with
    /// remote servers from causing us to drift too far.
    ///
    /// Note that this is not used during startup. To limit system clock changes
    /// during startup, use startup_panic_threshold
    #[clap(long)]
    pub panic_threshold: Option<f64>,

    /// The maximum duration in seconds the system clock is allowed to change during startup.
    /// This can be used to limit the impact of bad servers if the system clock
    /// is known to be reasonable on startup
    #[clap(long)]
    pub startup_panic_threshold: Option<f64>,
}

pub async fn spawn(
    config: ConfigureConfig,
    system_config: Arc<RwLock<SystemConfig>>,
    log_reload_handle: ReloadHandle,
) -> JoinHandle<std::io::Result<()>> {
    tokio::spawn(dynamic_configuration(
        config,
        system_config,
        log_reload_handle,
    ))
}

async fn dynamic_configuration(
    config: ConfigureConfig,
    system_config: Arc<RwLock<SystemConfig>>,
    log_reload_handle: ReloadHandle,
) -> std::io::Result<()> {
    // must unlink path before the bind below (otherwise we get "address already in use")
    if config.path.exists() {
        std::fs::remove_file(&config.path)?;
    }
    let peers_listener = UnixListener::bind(&config.path)?;

    // this binary needs to run as root to be able to adjust the system clock.
    // by default, the socket inherits root permissions, but the client should not need
    // elevated permissions to read from the socket. So we explicitly set the permissions
    let permissions: std::fs::Permissions = PermissionsExt::from_mode(config.mode);
    std::fs::set_permissions(&config.path, permissions)?;

    let mut msg = Vec::with_capacity(16 * 1024);

    loop {
        let (mut stream, _addr) = peers_listener.accept().await?;

        let operation: ConfigUpdate = crate::sockets::read_json(&mut stream, &mut msg).await?;

        tracing::info!(?operation, "dynamic config update");

        if let Some(filter) = operation.log_filter {
            log_reload_handle
                .modify(|l| *l.filter_mut() = EnvFilter::new(filter))
                .unwrap();
        }

        if let Some(panic_threshold) = operation.panic_threshold {
            let mut config = system_config.write().await;
            config.panic_threshold = Some(NtpDuration::from_seconds(panic_threshold));
        }

        if let Some(startup_panic_threshold) = operation.startup_panic_threshold {
            let mut config = system_config.write().await;
            config.startup_panic_threshold =
                Some(NtpDuration::from_seconds(startup_panic_threshold));
        }
    }
}
