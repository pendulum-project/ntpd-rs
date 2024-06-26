use std::{fmt::Display, sync::Arc};
use tokio::sync::mpsc;
use crate::daemon::config::GpsConfigSource;

use super::{BasicSpawner, PortChecker, RealPortChecker, SourceId, SourceRemovedEvent, SpawnAction, SpawnEvent, SpawnerId};

struct GpsSource {
    id: SourceId,
}

pub struct GpsSpawner {
    id: SpawnerId,
    config: GpsConfigSource,
    current_sources: Vec<GpsSource>,
    port_checker: Arc<dyn PortChecker>,
}

#[derive(Debug)]
pub enum GpsSpawnError {
    PortNotOpen,
}

impl Display for GpsSpawnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "GpsSpawnError")
    }
}

impl std::error::Error for GpsSpawnError {}

impl GpsSpawner {
    pub fn new(config: GpsConfigSource) -> GpsSpawner {
        GpsSpawner {
            id: Default::default(),
            config,
            current_sources: Default::default(),
            port_checker: Arc::new(RealPortChecker),
        }
    }

    #[cfg(test)]
    pub fn with_mock_port_checker(mut self) -> Self {
        use super::MockPortChecker;

        self.port_checker = Arc::new(MockPortChecker);
        self
    }
}

#[async_trait::async_trait]
impl BasicSpawner for GpsSpawner {
    type Error = GpsSpawnError;

    async fn try_spawn(
        &mut self,
        action_tx: &mpsc::Sender<SpawnEvent>,
    ) -> Result<(), GpsSpawnError> {
        match self.port_checker.check_port(self.config.address.clone(), self.config.baud_rate).await {
            Ok(_) => println!("Serial port check successful"),
            Err(e) => return Err(e),
        }
        

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
            self.config.address.clone(),
            self.config.measurement_noise,
            self.config.baud_rate, 
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

#[cfg(test)]
mod tests {

    use tokio::sync::mpsc::{self};

    use crate::daemon::{
        config::{GpsConfigSource},
        spawn::{
            gps::GpsSpawner, tests::{get_create_gps_params}, BasicSpawner, SourceRemovalReason, SourceRemovedEvent
        },
        system::MESSAGE_BUFFER_SIZE,
    };

    #[tokio::test]
    async fn creates_a_source() {
        let mut spawner = GpsSpawner::new(GpsConfigSource {
            address: "/dev/example".to_string(),
            baud_rate: 9600,
            measurement_noise: 0.001,
        }).with_mock_port_checker();
        let spawner_id = spawner.get_id();
        let (action_tx, mut action_rx) = mpsc::channel(MESSAGE_BUFFER_SIZE);

        assert!(!spawner.is_complete());
        spawner.try_spawn(&action_tx).await.unwrap();
        let res = action_rx.try_recv().unwrap();
        assert_eq!(res.id, spawner_id);
        let params = get_create_gps_params(res);
        assert_eq!(params.addr.to_string(), "/dev/example");

        // Should be complete after spawning
        assert!(spawner.is_complete());
    }

    #[tokio::test]
    async fn recreates_a_source() {
        let mut spawner = GpsSpawner::new(GpsConfigSource {
            address: "/dev/example".to_string(),
            baud_rate: 9600,
            measurement_noise: 0.001,
        }).with_mock_port_checker();
        let (action_tx, mut action_rx) = mpsc::channel(MESSAGE_BUFFER_SIZE);

        assert!(!spawner.is_complete());
        spawner.try_spawn(&action_tx).await.unwrap();
        let res = action_rx.try_recv().unwrap();
        let params = get_create_gps_params(res);
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
        let params = get_create_gps_params(res);
        assert_eq!(params.addr.to_string(), "/dev/example");
        assert!(spawner.is_complete());
    }
}
