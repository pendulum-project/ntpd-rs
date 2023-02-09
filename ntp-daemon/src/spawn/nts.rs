use thiserror::Error;
use tokio::sync::mpsc;

use crate::config::NtsPeerConfig;

use super::{BasicSpawner, SpawnerId, SpawnEvent, RemovedPeer};

pub struct NtsSpawner {
    config: NtsPeerConfig,
    network_wait_period: std::time::Duration,
    id: SpawnerId,
}

#[derive(Error, Debug)]
pub enum NtsSpawnError {

}

impl NtsSpawner {
    pub fn new(config: NtsPeerConfig, network_wait_period: std::time::Duration) -> NtsSpawner {
        NtsSpawner {
            config,
            network_wait_period,
            id: SpawnerId::new(),
        }
    }
}

#[async_trait::async_trait]
impl BasicSpawner for NtsSpawner {
    type Error = NtsSpawnError;

    async fn handle_init(&mut self, action_tx: &mpsc::Sender<SpawnEvent>) -> Result<(), NtsSpawnError> {
        todo!()
    }

    async fn handle_peer_removed(&mut self, removed_peer: RemovedPeer, action_tx: &mpsc::Sender<SpawnEvent>) -> Result<(), NtsSpawnError> {
        todo!()
    }

    fn get_id(&self) -> SpawnerId {
        self.id
    }
}
