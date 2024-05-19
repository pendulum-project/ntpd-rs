use std::fmt::Display;
use tokio::sync::mpsc;
use super::{BasicSpawner, SourceId, SourceRemovedEvent, SpawnAction, SpawnEvent, SpawnerId};

struct GpsSource {
    id: SourceId,
}

pub struct GpsSpawner {
    id: SpawnerId,
    current_sources: Vec<GpsSource>,
}

#[derive(Debug)]
pub enum GpsSpawnError {}

impl Display for GpsSpawnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "GpsSpawnError")
    }
}

impl std::error::Error for GpsSpawnError {}

impl GpsSpawner {
    pub fn new() -> GpsSpawner {
        GpsSpawner {
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

        // Here we just make a GpsSource the device we are using is in the confi
        let id = SourceId::new();
        self.current_sources.push(GpsSource {
            id,
        });

        let action = SpawnAction::create_gps(
            id,
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
    fn get_addr_description(&self) -> String {
        "gps".to_string()
    }

    fn get_description(&self) -> &str {
        "GPS"
    }
}