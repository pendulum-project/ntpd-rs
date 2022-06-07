use crate::tracing::ReloadHandle;
use std::os::unix::fs::PermissionsExt;
use tokio::net::UnixListener;
use tokio::task::JoinHandle;
use tracing_subscriber::EnvFilter;

use serde::{Deserialize, Serialize};

use super::ConfigureConfig;

#[derive(Serialize, Deserialize)]
pub enum Configure {
    LogLevel { filter: String },
}

pub async fn spawn(
    config: ConfigureConfig,
    log_reload_handle: ReloadHandle,
) -> JoinHandle<std::io::Result<()>> {
    tokio::spawn(dynamic_configuration(config, log_reload_handle))
}

async fn dynamic_configuration(
    config: ConfigureConfig,
    log_reload_handle: ReloadHandle,
) -> std::io::Result<()> {
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

        let operation: Configure = crate::sockets::read_json(&mut stream, &mut msg).await?;

        match operation {
            Configure::LogLevel { filter } => {
                log_reload_handle
                    .modify(|l| *l.filter_mut() = EnvFilter::new(filter))
                    .unwrap();
            }
        }
    }
}
