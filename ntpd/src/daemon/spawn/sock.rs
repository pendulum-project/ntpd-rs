use ntp_proto::SourceConfig;
use tokio::sync::mpsc;

use crate::daemon::config::SockSourceConfig;

use super::{
    standard::StandardSpawnError, SockSourceCreateParameters, SourceCreateParameters, SourceId,
    SourceRemovalReason, SourceRemovedEvent, SpawnAction, SpawnEvent, Spawner, SpawnerId,
};

pub struct SockSpawner {
    config: SockSourceConfig,
    source_config: SourceConfig,
    id: SpawnerId,
    has_spawned: bool,
}

impl SockSpawner {
    pub fn new(config: SockSourceConfig, source_config: SourceConfig) -> SockSpawner {
        SockSpawner {
            config,
            source_config,
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
                    config: self.source_config,
                    noise_estimate: self.config.precision.powi(2),
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
        self.config.path.display().to_string()
    }

    fn get_description(&self) -> &str {
        "sock"
    }
}

#[cfg(test)]
mod tests {
    use ntp_proto::SourceConfig;
    use tokio::sync::mpsc;

    use crate::{
        daemon::{
            config::SockSourceConfig,
            spawn::{sock::SockSpawner, SourceCreateParameters, SpawnAction, Spawner},
            system::MESSAGE_BUFFER_SIZE,
        },
        test::alloc_port,
    };

    #[tokio::test]
    async fn creates_a_source() {
        let socket_path = std::env::temp_dir().join(format!("ntp-test-stream-{}", alloc_port()));
        let precision = 1e-3;
        let mut spawner = SockSpawner::new(
            SockSourceConfig {
                path: socket_path.clone(),
                precision,
            },
            SourceConfig::default(),
        );
        let spawner_id = spawner.get_id();
        let (action_tx, mut action_rx) = mpsc::channel(MESSAGE_BUFFER_SIZE);

        assert!(!spawner.is_complete());
        spawner.try_spawn(&action_tx).await.unwrap();
        let res = action_rx.try_recv().unwrap();
        assert_eq!(res.id, spawner_id);

        let SpawnAction::Create(create_params) = res.action;
        assert_eq!(create_params.get_addr(), socket_path.display().to_string());

        let SourceCreateParameters::Sock(params) = create_params else {
            panic!("did not receive sock source create parameters!");
        };
        assert_eq!(params.path, socket_path);
        assert!((params.noise_estimate - precision.powi(2)).abs() < 1e-9);

        // Should be complete after spawning
        assert!(spawner.is_complete());
    }
}
