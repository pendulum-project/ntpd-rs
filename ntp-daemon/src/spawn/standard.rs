use std::net::SocketAddr;

use thiserror::Error;
use tokio::sync::mpsc;
use tracing::warn;

use crate::config::StandardPeerConfig;

use super::{BasicSpawner, PeerId, PeerRemovedEvent, SpawnAction, SpawnEvent, SpawnerId};

pub struct StandardSpawner {
    id: SpawnerId,
    config: StandardPeerConfig,
    network_wait_period: std::time::Duration,
    resolved: Option<SocketAddr>,
}

#[derive(Error, Debug)]
pub enum StandardSpawnError {
    #[error("Channel send error: {0}")]
    SendError(#[from] mpsc::error::SendError<SpawnEvent>),
}

impl StandardSpawner {
    pub fn new(
        config: StandardPeerConfig,
        network_wait_period: std::time::Duration,
    ) -> StandardSpawner {
        StandardSpawner {
            id: Default::default(),
            config,
            network_wait_period,
            resolved: None,
        }
    }

    async fn do_resolve(&mut self, force_resolve: bool) -> SocketAddr {
        if let (false, Some(addr)) = (force_resolve, self.resolved) {
            addr
        } else {
            let addr = loop {
                match self.config.addr.lookup_host().await {
                    Ok(mut addresses) => match addresses.next() {
                        None => {
                            warn!("Could not resolve peer address, retrying");
                            tokio::time::sleep(self.network_wait_period).await
                        }
                        Some(first) => {
                            break first;
                        }
                    },
                    Err(e) => {
                        warn!(error = ?e, "error while resolving peer address, retrying");
                        tokio::time::sleep(self.network_wait_period).await
                    }
                }
            };
            self.resolved = Some(addr);
            addr
        }
    }

    async fn spawn(
        &mut self,
        action_tx: &mpsc::Sender<SpawnEvent>,
    ) -> Result<(), StandardSpawnError> {
        let addr = self.do_resolve(false).await;
        action_tx
            .send(SpawnEvent::new(
                self.id,
                SpawnAction::create(PeerId::new(), addr, self.config.addr.clone(), None),
            ))
            .await?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl BasicSpawner for StandardSpawner {
    type Error = StandardSpawnError;

    async fn handle_init(
        &mut self,
        action_tx: &mpsc::Sender<SpawnEvent>,
    ) -> Result<(), StandardSpawnError> {
        self.spawn(action_tx).await
    }

    async fn handle_peer_removed(
        &mut self,
        _removed_peer: PeerRemovedEvent,
        action_tx: &mpsc::Sender<SpawnEvent>,
    ) -> Result<(), StandardSpawnError> {
        self.spawn(action_tx).await
    }

    fn get_id(&self) -> SpawnerId {
        self.id
    }

    fn get_addr_description(&self) -> String {
        self.config.addr.to_string()
    }
}
