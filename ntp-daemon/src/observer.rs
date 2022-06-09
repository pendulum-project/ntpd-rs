use crate::{ObservablePeerState, Peers};
use ntp_proto::SystemSnapshot;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use tokio::net::UnixListener;
use tokio::task::JoinHandle;

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct ObservableState {
    system: SystemSnapshot,
    peers: Vec<ObservablePeerState>,
}

pub async fn spawn(
    config: &crate::config::ObserveConfig,
    peers_reader: Arc<tokio::sync::RwLock<Peers>>,
    system_reader: Arc<tokio::sync::RwLock<SystemSnapshot>>,
) -> JoinHandle<std::io::Result<()>> {
    tokio::spawn(observer(config.clone(), peers_reader, system_reader))
}

async fn observer(
    config: crate::config::ObserveConfig,
    peers_reader: Arc<tokio::sync::RwLock<Peers>>,
    system_reader: Arc<tokio::sync::RwLock<SystemSnapshot>>,
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

    loop {
        let (mut stream, _addr) = peers_listener.accept().await?;

        let observe = ObservableState {
            peers: peers_reader.read().await.observe().collect(),
            system: *system_reader.read().await,
        };

        crate::sockets::write_json(&mut stream, &observe).await?;
    }
}
