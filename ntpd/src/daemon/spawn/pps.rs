use ntp_proto::SourceConfig;
use tokio::sync::mpsc;

use crate::daemon::config::PpsSourceConfig;

use super::{
    standard::StandardSpawnError, PpsSourceCreateParameters, SourceCreateParameters, SourceId,
    SourceRemovalReason, SourceRemovedEvent, SpawnAction, SpawnEvent, Spawner, SpawnerId,
};

pub struct PpsSpawner {
    config: PpsSourceConfig,
    source_config: SourceConfig,
    id: SpawnerId,
    has_spawned: bool,
}

impl PpsSpawner {
    pub fn new(config: PpsSourceConfig, source_config: SourceConfig) -> PpsSpawner {
        PpsSpawner {
            config,
            source_config,
            id: Default::default(),
            has_spawned: false,
        }
    }
}

#[async_trait::async_trait]
impl Spawner for PpsSpawner {
    type Error = StandardSpawnError;

    async fn try_spawn(
        &mut self,
        action_tx: &mpsc::Sender<SpawnEvent>,
    ) -> Result<(), StandardSpawnError> {
        action_tx
            .send(SpawnEvent::new(
                self.id,
                SpawnAction::Create(SourceCreateParameters::Pps(PpsSourceCreateParameters {
                    id: SourceId::new(),
                    path: self.config.path.clone(),
                    config: self.source_config,
                    noise_estimate: self.config.measurement_noise_estimate,
                    period: self.config.period,
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
        "PPS"
    }
}

#[cfg(test)]
mod tests {
    use ntp_proto::SourceConfig;
    use tokio::sync::mpsc;

    use crate::{
        daemon::{
            config::PpsSourceConfig,
            spawn::{pps::PpsSpawner, SourceCreateParameters, SpawnAction, Spawner},
            system::MESSAGE_BUFFER_SIZE,
        },
        test::alloc_port,
    };

    #[tokio::test]
    async fn creates_a_source() {
        let socket_path = std::env::temp_dir().join(format!("ntp-test-stream-{}", alloc_port()));
        let noise_estimate = 1e-6;
        let mut spawner = PpsSpawner::new(
            PpsSourceConfig {
                path: socket_path.clone(),
                measurement_noise_estimate: noise_estimate,
                period: 1.,
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

        let SourceCreateParameters::Pps(params) = create_params else {
            panic!("did not receive PPS source create parameters!");
        };
        assert_eq!(params.path, socket_path);
        assert!((params.noise_estimate - noise_estimate).abs() < 1e-9);

        // Should be complete after spawning
        assert!(spawner.is_complete());
    }
}
