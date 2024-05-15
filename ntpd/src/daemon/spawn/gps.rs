use std::fmt::Display;
use std::{net::SocketAddr, ops::Deref};

use ntp_proto::ProtocolVersion;
use tokio::sync::mpsc;
use tracing::warn;

use super::super::config::PoolSourceConfig;

use super::{BasicSpawner, SourceId, SourceRemovedEvent, SpawnAction, SpawnEvent, SpawnerId};

struct GpsSource {
    id: SourceId,
    device: String,
}

pub struct GpsSpawner {
    config: GpsConfig,
    id: SpawnerId,
    current_sources: Vec<GpsSource>,
}

#[derive(Debug)]
pub enum GpsSpawnError {}

impl Display for GpsSpawnError {
    fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "GpsSpawnError")
    }
}

impl std::error::Error for GpsSpawnError {}

impl GpsSpawner {
    pub fn new(config: GpsConfig) -> GpsSpawner {
        GpsSpawner {
            config,
            id: Default::default(),
            current_sources: Default::default(),
        }
    }
}

#[async_trait::async_trait]
impl BasicSpawner for GpsSpawner {
    type Error = GpsSpawnError;

    async fn try_spawn(
        &mut self,
        action_tx: &mpsc::Sender<SpawnEvent>,
    ) -> Result<(), GpsSpawnError> {
        // Early return if there is already a GPS source
        if !self.current_sources.is_empty() {
            return Ok(());
        }

        let id = SourceId::new();
        self.current_sources.push(GpsSource {
            id,
            device: self.config.device.clone(),
        });

        let action = SpawnAction::create(
            id,
            self.config.device.clone(),
            None,
        );

        tracing::debug!(?action, "intending to spawn new GPS source");
        
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
    ) -> Result<(), GpsSpawnError> {
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
        "GPS"
    }
}