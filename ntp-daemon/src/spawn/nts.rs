use std::ops::Deref;

use thiserror::Error;
use tokio::sync::mpsc;
use tracing::warn;

use crate::{config::NtsPeerConfig, keyexchange::key_exchange_client};

use super::{BasicSpawner, PeerId, PeerRemovedEvent, SpawnAction, SpawnEvent, SpawnerId};

pub struct NtsSpawner {
    config: NtsPeerConfig,
    network_wait_period: std::time::Duration,
    id: SpawnerId,
}

#[derive(Error, Debug)]
pub enum NtsSpawnError {
    #[error("Channel send error: {0}")]
    SendError(#[from] mpsc::error::SendError<SpawnEvent>),
}

impl NtsSpawner {
    pub fn new(config: NtsPeerConfig, network_wait_period: std::time::Duration) -> NtsSpawner {
        NtsSpawner {
            config,
            network_wait_period,
            id: Default::default(),
        }
    }

    async fn spawn(&mut self, action_tx: &mpsc::Sender<SpawnEvent>) -> Result<(), NtsSpawnError> {
        let ke = loop {
            match key_exchange_client(
                self.config.ke_addr.server_name.clone(),
                self.config.ke_addr.port,
                &self.config.certificates,
            )
            .await
            {
                Ok(res) => break res,
                Err(e) => {
                    warn!(error = ?e, "error while attempting key exchange");
                    tokio::time::sleep(self.network_wait_period).await;
                }
            };
        };

        let addr = loop {
            let address = (ke.remote.as_str(), ke.port);
            match tokio::net::lookup_host(address).await {
                Ok(mut addresses) => match addresses.next() {
                    None => {
                        warn!("Could not resolve peer address, retrying");
                        tokio::time::sleep(self.network_wait_period).await;
                    }
                    Some(first) => {
                        break first;
                    }
                },
                Err(e) => {
                    warn!(error = ?e, "error while resolving peer address, retrying");
                    tokio::time::sleep(self.network_wait_period).await;
                }
            }
        };

        action_tx
            .send(SpawnEvent::new(
                self.id,
                SpawnAction::create(
                    PeerId::new(),
                    addr,
                    self.config.ke_addr.deref().clone(),
                    Some(ke.nts),
                ),
            ))
            .await?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl BasicSpawner for NtsSpawner {
    type Error = NtsSpawnError;

    async fn handle_init(
        &mut self,
        action_tx: &mpsc::Sender<SpawnEvent>,
    ) -> Result<(), NtsSpawnError> {
        self.spawn(action_tx).await
    }

    async fn handle_peer_removed(
        &mut self,
        _removed_peer: PeerRemovedEvent,
        action_tx: &mpsc::Sender<SpawnEvent>,
    ) -> Result<(), NtsSpawnError> {
        self.handle_init(action_tx).await
    }

    fn get_id(&self) -> SpawnerId {
        self.id
    }

    fn get_addr_description(&self) -> String {
        self.config.ke_addr.to_string()
    }

    fn get_description(&self) -> &str {
        "nts"
    }
}
