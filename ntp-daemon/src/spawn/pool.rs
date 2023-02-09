use std::net::SocketAddr;

use thiserror::Error;
use tokio::sync::mpsc;
use tracing::warn;

use crate::{config::PoolPeerConfig, spawn::SpawnAction};

use super::{BasicSpawner, SpawnerId, SpawnEvent, RemovedPeer, PeerId};

struct PoolPeer {
    id: PeerId,
    addr: SocketAddr,
}

pub struct PoolSpawner {
    config: PoolPeerConfig,
    network_wait_period: std::time::Duration,
    id: SpawnerId,
    current_peers: Vec<PoolPeer>,
    known_ips: Vec<SocketAddr>,
}

#[derive(Error, Debug)]
pub enum PoolSpawnError {

}

impl PoolSpawner {
    pub fn new(config: PoolPeerConfig, network_wait_period: std::time::Duration) -> PoolSpawner {
        PoolSpawner {
            config,
            network_wait_period,
            id: SpawnerId::new(),
            current_peers: Default::default(),
            known_ips: Default::default(),
        }
    }

    pub async fn fill_pool(&mut self, action_tx: &mpsc::Sender<SpawnEvent>) -> Result<(), PoolSpawnError> {
        let mut wait_period = self.network_wait_period;

        // early return if there is nothing to do
        if self.current_peers.len() < self.config.max_peers {
            return Ok(());
        }

        loop {
            if self.known_ips.len() < self.config.max_peers - self.current_peers.len() {
                match self.config.addr.lookup_host().await {
                    Ok(addresses) => {
                        // add the addresses looked up to our list of known ips
                        self.known_ips.append(&mut addresses.collect());
                        // remove known ips that we are already connected to
                        self.known_ips.retain(|ip| !self.current_peers.iter().any(|p| p.addr == *ip))
                    }
                    Err(e) => {
                        warn!(error = ?e, "error while resolving peer address, retrying");
                        tokio::time::sleep(wait_period).await;
                        continue;
                    }
                }
            }

            // Try and add peers to our pool
            while self.current_peers.len() < self.config.max_peers {
                if let Some(addr) = self.known_ips.pop() {
                    let id = PeerId::new();
                    self.current_peers.push(PoolPeer { id, addr });
                    let action = SpawnAction::Create(id, addr, self.config.addr.clone(), None);
                    tracing::debug!(?action, "intending to spawn new pool peer at");

                    action_tx.send(SpawnEvent::new(self.id, action)).await.expect("Channel was no longer connected");
                } else {
                    break;
                }
            }


            let wait_period_max = if cfg!(test) {
                std::time::Duration::default()
            } else {
                std::time::Duration::from_secs(60)
            };

            wait_period = Ord::min(2 * wait_period, wait_period_max);
            let peers_needed = self.config.max_peers - self.current_peers.len();
            if peers_needed > 0 {
                warn!(peers_needed, "could not fully fill pool");
                tokio::time::sleep(wait_period).await;
            } else {
                return Ok(());
            }
        }
    }
}

#[async_trait::async_trait]
impl BasicSpawner for PoolSpawner {
    type Error = PoolSpawnError;

    async fn handle_init(&mut self, action_tx: &mpsc::Sender<SpawnEvent>) -> Result<(), PoolSpawnError> {
        self.fill_pool(action_tx).await?;
        Ok(())
    }

    async fn handle_peer_removed(&mut self, removed_peer: RemovedPeer, action_tx: &mpsc::Sender<SpawnEvent>) -> Result<(), PoolSpawnError> {
        self.current_peers.retain(|p| p.id != removed_peer.id);
        self.fill_pool(action_tx).await?;
        Ok(())
    }

    fn get_id(&self) -> SpawnerId {
        self.id
    }
}
