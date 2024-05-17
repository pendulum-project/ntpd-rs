use std::fmt::Display;
use std::{net::SocketAddr, ops::Deref};
use ntp_proto::ProtocolVersion;
use tokio::sync::mpsc;
use tracing::warn;

use super::super::config::PoolSourceConfig;

use super::{BasicSpawner, SourceId, SourceRemovedEvent, SpawnAction, SpawnEvent, SpawnerId};

struct ppsSource {
    id: SourceId,
    device: String,
}

pub struct ppsSpawner {
    config: ppsConfig,
    id: SpawnerId,
    current_sources: Vec<pssSource>,
}

#[derive(Debug)]
pub enum ppsSpawnError {}

impl Display for ppsSpawnError {
    fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ppsSpawnError")
    }
}

impl std::error::Error for ppsSpawnError {}

impl ppsSpawner {
    pub fn new(config: ppsConfig) -> ppsSpawner {
        ppsSpawner {
            config,
            id: Default::default(),
            current_sources: Default::default(),
        }
    }
}

#[async_trait::async_trait]
impl BasicSpawner for ppsSpawner {
    type Error = ppsSpawnError;

    async fn try_spawn(
        &mut self,
        action_tx: &mpsc::Sender<SpawnEvent>,
    ) -> Result<(), ppsSpawnError> {
        // Early return if there is already a pps source
        if !self.current_sources.is_empty() {
            return Ok(());
        }

        let id = SourceId::new();
        self.current_sources.push(ppsSource {
            id,
            device: self.config.device.clone(),
        });

        let action = SpawnAction::create(
            id,
            self.config.device.clone(),
            None,
        );

        tracing::debug!(?action, "intending to spawn new pps source");
        
        action_tx
            .send(SpawnEvent::new(self.id, action))
            .await
            .expect("Channel was no longer connected");



        Ok(())
    }

    fn is_complete(&self) -> bool {
        !self.current_sources.is_empty()
    }

    async fn handle_source_removed(
        &mut self,
        removed_source: SourceRemovedEvent,
    ) -> Result<(), ppsSpawnError> {
        self.current_sources.retain(|p| p.id != removed_source.id);
        Ok(())
    }

    fn get_id(&self) -> SpawnerId {
        self.id
    }

    fn get_device_description(&self) -> String {
        format!("{}", self.config.device)
    }

    fn get_description(&self) -> &str {
        "PPS"
    }
}
