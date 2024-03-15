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
    id: SpawnerId,
    current_peers: Vec<PoolPeer>,
}

#[derive(Error, Debug)]
pub enum NtsPoolSpawnError {
    #[error("Channel send error: {0}")]
    SendError(#[from] mpsc::error::SendError<SpawnEvent>),
}

impl NtsPoolSpawner {
    pub fn new(config: NtsPoolPeerConfig) -> NtsPoolSpawner {
        NtsPoolSpawner {
            config,
            id: Default::default(),
            current_peers: Default::default(),
            //known_ips: Default::default(),
        }
    }

    fn contains_peer(&self, domain: &str) -> bool {
        self.current_peers.iter().any(|peer| peer.remote == domain)
    }
}

#[async_trait::async_trait]
impl BasicSpawner for NtsPoolSpawner {
    type Error = NtsPoolSpawnError;

    async fn try_spawn(
        &mut self,
        action_tx: &mpsc::Sender<SpawnEvent>,
    ) -> Result<(), NtsPoolSpawnError> {
        for _ in 0..self
            .config
            .max_peers
            .saturating_sub(self.current_peers.len())
        {
            match key_exchange_client_with_denied_servers(
                self.config.addr.server_name.clone(),
                self.config.addr.port,
                &self.config.certificate_authorities,
                self.current_peers.iter().map(|peer| peer.remote.clone()),
            )
            .await
            {
                Ok(ke) if !self.contains_peer(&ke.remote) => {
                    if let Some(address) = resolve_addr((ke.remote.as_str(), ke.port)).await {
                        let id = PeerId::new();
                        self.current_peers.push(PoolPeer {
                            id,
                            remote: ke.remote,
                        });
                        action_tx
                            .send(SpawnEvent::new(
                                self.id,
                                SpawnAction::create(
                                    id,
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
                    continue;
                }
                Err(e) => {
                    warn!(error = ?e, "error while attempting key exchange");
                    break;
                }
            };
        }

        Ok(())
    }

    fn is_complete(&self) -> bool {
        self.current_peers.len() >= self.config.max_peers
    }

    async fn handle_peer_removed(
        &mut self,
        removed_peer: PeerRemovedEvent,
    ) -> Result<(), NtsPoolSpawnError> {
        self.current_peers.retain(|p| p.id != removed_peer.id);
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
