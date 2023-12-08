use std::ops::Deref;

use thiserror::Error;
use tokio::sync::mpsc;
use tracing::warn;

use super::super::{
    config::NtsPoolPeerConfig, keyexchange::key_exchange_client_with_denied_servers,
};

use super::{BasicSpawner, PeerId, PeerRemovedEvent, SpawnAction, SpawnEvent, SpawnerId};

use super::nts::resolve_addr;

struct PoolPeer {
    id: PeerId,
    remote: String,
}

pub struct NtsPoolSpawner {
    config: NtsPoolPeerConfig,
    network_wait_period: std::time::Duration,
    id: SpawnerId,
    current_peers: Vec<PoolPeer>,
}

#[derive(Error, Debug)]
pub enum NtsPoolSpawnError {
    #[error("Channel send error: {0}")]
    SendError(#[from] mpsc::error::SendError<SpawnEvent>),
}

impl NtsPoolSpawner {
    pub fn new(
        config: NtsPoolPeerConfig,
        network_wait_period: std::time::Duration,
    ) -> NtsPoolSpawner {
        NtsPoolSpawner {
            config,
            network_wait_period,
            id: Default::default(),
            current_peers: Default::default(),
            //known_ips: Default::default(),
        }
    }

    fn contains_peer(&self, domain: &str) -> bool {
        self.current_peers.iter().any(|peer| peer.remote == domain)
    }

    pub async fn fill_pool(
        &mut self,
        action_tx: &mpsc::Sender<SpawnEvent>,
    ) -> Result<(), NtsPoolSpawnError> {
        let mut wait_period = self.network_wait_period;

        // early return if there is nothing to do
        if self.current_peers.len() >= self.config.max_peers {
            return Ok(());
        }

        loop {
            // Try and add peers to our pool
            while self.current_peers.len() < self.config.max_peers {
                match key_exchange_client_with_denied_servers(
                    self.config.addr.server_name.clone(),
                    self.config.addr.port,
                    &self.config.certificate_authorities,
                    self.current_peers.iter().map(|peer| peer.remote.clone()),
                )
                .await
                {
                    Ok(ke) if !self.contains_peer(&ke.remote) => {
                        if let Some(address) =
                            resolve_addr(self.network_wait_period, (ke.remote.as_str(), ke.port))
                                .await
                        {
                            let id = PeerId::new();
                            self.current_peers.push(PoolPeer {
                                id,
                                remote: ke.remote,
                            });
                            action_tx
                                .send(SpawnEvent::new(
                                    self.id,
                                    SpawnAction::create(
                                        PeerId::new(),
                                        address,
                                        self.config.addr.deref().clone(),
                                        ke.protocol_version,
                                        Some(ke.nts),
                                    ),
                                ))
                                .await?;
                        }
                    }
                    Ok(_) => {
                        warn!("received an address from pool-ke that we already had, ignoring");
                        break;
                    }
                    Err(e) => {
                        warn!(error = ?e, "error while attempting key exchange");
                        break;
                    }
                };
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
impl BasicSpawner for NtsPoolSpawner {
    type Error = NtsPoolSpawnError;

    async fn handle_init(
        &mut self,
        action_tx: &mpsc::Sender<SpawnEvent>,
    ) -> Result<(), NtsPoolSpawnError> {
        self.fill_pool(action_tx).await?;
        Ok(())
    }

    async fn handle_peer_removed(
        &mut self,
        removed_peer: PeerRemovedEvent,
        action_tx: &mpsc::Sender<SpawnEvent>,
    ) -> Result<(), NtsPoolSpawnError> {
        self.current_peers.retain(|p| p.id != removed_peer.id);
        self.fill_pool(action_tx).await?;
        Ok(())
    }

    fn get_id(&self) -> SpawnerId {
        self.id
    }

    fn get_addr_description(&self) -> String {
        format!("{} ({})", self.config.addr.deref(), self.config.max_peers)
    }

    fn get_description(&self) -> &str {
        "nts-pool"
    }
}
