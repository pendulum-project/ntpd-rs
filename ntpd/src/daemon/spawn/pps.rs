use std::fmt::Display;
use std::{net::SocketAddr, ops::Deref};
use ntp_proto::ProtocolVersion;
use tokio::sync::mpsc;
use tracing::warn;


use super::{BasicSpawner, SourceId, SourceRemovedEvent, SpawnAction, SpawnEvent, SpawnerId};

struct PpsSource {
    id: SourceId,
}

pub struct PpsSpawner {
    id: SpawnerId,
    current_sources: Vec<PpsSource>,
}

#[derive(Debug)]
pub enum PpsSpawnError {}

impl Display for PpsSpawnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ppsSpawnError")
    }
}

impl std::error::Error for PpsSpawnError {}

impl PpsSpawner {
    pub fn new() -> PpsSpawner {
        PpsSpawner {
            id: Default::default(),
            current_sources: Default::default(),
        }
    }
}

#[async_trait::async_trait]
impl BasicSpawner for PpsSpawner {
    type Error = PpsSpawnError;

    async fn try_spawn(
        &mut self,
        action_tx: &mpsc::Sender<SpawnEvent>,
    ) -> Result<(), PpsSpawnError> {
        // Early return if there is already a pps source
        if !self.current_sources.is_empty() {
            return Ok(());
        }

        let id = SourceId::new();
        self.current_sources.push(PpsSource {
            id,
        });

        let action = SpawnAction::create_pps(
            id,
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
    ) -> Result<(), PpsSpawnError> {
        self.current_sources.retain(|p| p.id != removed_source.id);
        Ok(())
    }

    fn get_id(&self) -> SpawnerId {
        self.id
    }
    fn get_addr_description(&self) -> String {
        "pps".to_string()
    }

    fn get_description(&self) -> &str {
        "PPS"
    }
}
