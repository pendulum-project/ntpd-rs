use tokio::sync::mpsc;

use crate::daemon::config::SockSourceConfig;

use super::{
    standard::StandardSpawnError, SockSourceCreateParameters, SourceCreateParameters, SourceId,
    SourceRemovalReason, SourceRemovedEvent, SpawnAction, SpawnEvent, Spawner, SpawnerId,
};

pub struct SockSpawner {
    config: SockSourceConfig,
    id: SpawnerId,
    has_spawned: bool,
}

impl SockSpawner {
    pub fn new(config: SockSourceConfig) -> SockSpawner {
        SockSpawner {
            config,
            id: Default::default(),
            has_spawned: false,
        }
    }
}

#[async_trait::async_trait]
impl Spawner for SockSpawner {
    type Error = StandardSpawnError;

    async fn try_spawn(
        &mut self,
        action_tx: &mpsc::Sender<SpawnEvent>,
    ) -> Result<(), StandardSpawnError> {
        action_tx
            .send(SpawnEvent::new(
                self.id,
                SpawnAction::Create(SourceCreateParameters::Sock(SockSourceCreateParameters {
                    id: SourceId::new(),
                    path: self.config.path.clone(),
                })),
            ))
            .await?;
        self.has_spawned = true;
        Ok(())
    }

    fn is_complete(&self) -> bool {
        self.has_spawned
    }

    async fn handle_source_removed(
        &mut self,
        removed_source: SourceRemovedEvent,
    ) -> Result<(), StandardSpawnError> {
        if removed_source.reason != SourceRemovalReason::Demobilized {
            self.has_spawned = false;
        }
        Ok(())
    }

    fn get_id(&self) -> SpawnerId {
        self.id
    }

    fn get_addr_description(&self) -> String {
        format!("{}", self.config.path)
    }

    fn get_description(&self) -> &str {
        "sock"
    }
}
