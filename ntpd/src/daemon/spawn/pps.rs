use std::fmt::Display;
use tokio::sync::mpsc;


use crate::daemon::config::PpsConfigSource;

use super::{BasicSpawner, SourceId, SourceRemovedEvent, SpawnAction, SpawnEvent, SpawnerId};

pub struct PpsSource {
    id: SourceId,
}

pub struct PpsSpawner {
    id: SpawnerId,
    current_sources: Vec<PpsSource>,
    config: PpsConfigSource,
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
    pub fn new(config: PpsConfigSource) -> PpsSpawner {
        PpsSpawner {
            id: Default::default(),
            current_sources: Default::default(),
            config,
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
            self.config.address.clone(),
            self.config.measurement_noise,
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


#[cfg(test)]
mod tests {

    use tokio::sync::mpsc::{self};

    use crate::daemon::{
        config::PpsConfigSource,
        spawn::{pps::PpsSpawner, tests::get_create_pps_params, BasicSpawner, SourceRemovalReason, SourceRemovedEvent
        },
        system::MESSAGE_BUFFER_SIZE,
    };

    #[tokio::test]
    async fn creates_a_source() {
        let mut spawner = PpsSpawner::new(PpsConfigSource {
            address: "/dev/example".to_string(),
            measurement_noise: 0.001,
        });
        let spawner_id = spawner.get_id();
        let (action_tx, mut action_rx) = mpsc::channel(MESSAGE_BUFFER_SIZE);

        assert!(!spawner.is_complete());
        spawner.try_spawn(&action_tx).await.unwrap();
        let res = action_rx.try_recv().unwrap();
        assert_eq!(res.id, spawner_id);
        let params = get_create_pps_params(res);
        assert_eq!(params.addr.to_string(), "/dev/example");

        // Should be complete after spawning
        assert!(spawner.is_complete());
    }

    #[tokio::test]
    async fn recreates_a_source() {
        let mut spawner = PpsSpawner::new(PpsConfigSource {
            address: "/dev/example".to_string(),
            measurement_noise: 0.001,
        });
        let (action_tx, mut action_rx) = mpsc::channel(MESSAGE_BUFFER_SIZE);

        assert!(!spawner.is_complete());
        spawner.try_spawn(&action_tx).await.unwrap();
        let res = action_rx.try_recv().unwrap();
        let params = get_create_pps_params(res);
        assert!(spawner.is_complete());

        spawner
            .handle_source_removed(SourceRemovedEvent {
                id: params.id,
                reason: SourceRemovalReason::NetworkIssue,
            })
            .await
            .unwrap();

        assert!(!spawner.is_complete());
        spawner.try_spawn(&action_tx).await.unwrap();
        let res = action_rx.try_recv().unwrap();
        let params = get_create_pps_params(res);
        assert_eq!(params.addr.to_string(), "/dev/example");
        assert!(spawner.is_complete());
    }
}

