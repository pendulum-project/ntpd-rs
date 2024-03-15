use std::net::SocketAddr;
use std::ops::Deref;

use thiserror::Error;
use tokio::sync::mpsc;
use tracing::warn;

use super::super::{config::NtsPeerConfig, keyexchange::key_exchange_client};

use super::{BasicSpawner, PeerId, PeerRemovedEvent, SpawnAction, SpawnEvent, SpawnerId};

pub struct NtsSpawner {
    config: NtsPeerConfig,
    network_wait_period: std::time::Duration,
    id: SpawnerId,
    has_spawned: bool,
}

#[derive(Error, Debug)]
pub enum NtsSpawnError {
    #[error("Channel send error: {0}")]
    SendError(#[from] mpsc::error::SendError<SpawnEvent>),
}

pub(super) async fn resolve_addr(
    mut network_wait: std::time::Duration,
    address: (&str, u16),
) -> Option<SocketAddr> {
    const MAX_RETRIES: usize = 5;
    const BACKOFF_FACTOR: u32 = 2;

    for i in 0..MAX_RETRIES {
        if i != 0 {
            // Ensure we dont spam dns
            tokio::time::sleep(network_wait).await;
            network_wait *= BACKOFF_FACTOR;
        }
        match tokio::net::lookup_host(address).await {
            Ok(mut addresses) => match addresses.next() {
                Some(address) => return Some(address),
                None => {
                    warn!("received unknown domain name from NTS-ke");
                    return None;
                }
            },
            Err(e) => {
                warn!(error = ?e, "error while resolving peer address, retrying");
            }
        }
    }

    warn!("Could not resolve peer address, restarting NTS initialization");

    None
}

impl NtsSpawner {
    pub fn new(config: NtsPeerConfig, network_wait_period: std::time::Duration) -> NtsSpawner {
        NtsSpawner {
            config,
            network_wait_period,
            id: Default::default(),
            has_spawned: false,
        }
    }
}

#[async_trait::async_trait]
impl BasicSpawner for NtsSpawner {
    type Error = NtsSpawnError;

    async fn try_spawn(
        &mut self,
        action_tx: &mpsc::Sender<SpawnEvent>,
    ) -> Result<(), NtsSpawnError> {
        const MAX_BACKOFF: u32 = 64;
        const BACKOFF_FACTOR: u32 = 2;

        let mut network_wait = self.network_wait_period;

        loop {
            match key_exchange_client(
                self.config.address.server_name.clone(),
                self.config.address.port,
                &self.config.certificate_authorities,
            )
            .await
            {
                Ok(ke) => {
                    if let Some(address) =
                        resolve_addr(self.network_wait_period, (ke.remote.as_str(), ke.port)).await
                    {
                        action_tx
                            .send(SpawnEvent::new(
                                self.id,
                                SpawnAction::create(
                                    PeerId::new(),
                                    address,
                                    self.config.address.deref().clone(),
                                    ke.protocol_version,
                                    Some(ke.nts),
                                ),
                            ))
                            .await?;
                        self.has_spawned = true;
                        return Ok(());
                    }
                }
                Err(e) => {
                    warn!(error = ?e, "error while attempting key exchange");
                }
            };

            tokio::time::sleep(network_wait).await;
            network_wait = std::cmp::min(
                network_wait * BACKOFF_FACTOR,
                self.network_wait_period * MAX_BACKOFF,
            );
        }
    }

    fn is_complete(&self) -> bool {
        self.has_spawned
    }

    async fn handle_peer_removed(
        &mut self,
        _removed_peer: PeerRemovedEvent,
    ) -> Result<(), NtsSpawnError> {
        self.has_spawned = false;
        Ok(())
    }

    fn get_id(&self) -> SpawnerId {
        self.id
    }

    fn get_addr_description(&self) -> String {
        self.config.address.to_string()
    }

    fn get_description(&self) -> &str {
        "nts"
    }
}
