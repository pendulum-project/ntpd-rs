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
                    noise_estimate: self.config.measurement_noise_estimate.to_seconds(),
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
        self.config.path.to_string()
    }

    fn get_description(&self) -> &str {
        "sock"
    }
}

#[cfg(test)]
mod tests {
    use ntp_proto::NtpDuration;
    use tokio::sync::mpsc;

    use crate::daemon::{
        config::SockSourceConfig,
        spawn::{sock::SockSpawner, SourceCreateParameters, SpawnAction, Spawner},
        system::MESSAGE_BUFFER_SIZE,
    };

    #[tokio::test]
    async fn creates_a_source() {
        let socket_path = "/tmp/test.sock";
        let noise_estimate = 1e-6;
        let mut spawner = SockSpawner::new(SockSourceConfig {
            path: socket_path.to_string(),
            measurement_noise_estimate: NtpDuration::from_seconds(noise_estimate),
        });
        let spawner_id = spawner.get_id();
        let (action_tx, mut action_rx) = mpsc::channel(MESSAGE_BUFFER_SIZE);

        assert!(!spawner.is_complete());
        spawner.try_spawn(&action_tx).await.unwrap();
        let res = action_rx.try_recv().unwrap();
        assert_eq!(res.id, spawner_id);

        let SpawnAction::Create(SourceCreateParameters::Sock(params)) = res.action else {
            panic!("did not receive a sock create event!");
        };
        assert_eq!(params.path, socket_path);
        assert!((params.noise_estimate - noise_estimate).abs() < 1e-9);

        // Should be complete after spawning
        assert!(spawner.is_complete());
    }
}
