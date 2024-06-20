use std::{fmt::Display, time::Duration};
use tokio::sync::mpsc;
use crate::daemon::config::GpsConfigSource;
use serialport;

use super::{BasicSpawner, SourceId, SourceRemovedEvent, SpawnAction, SpawnEvent, SpawnerId};

struct GpsSource {
    id: SourceId,
}

pub struct GpsSpawner {
    id: SpawnerId,
    config: GpsConfigSource,
    current_sources: Vec<GpsSource>,
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
        }
    }
}

#[async_trait::async_trait]
impl BasicSpawner for GpsSpawner {
    type Error = GpsSpawnError;

    async fn check_port(&self, port_name: String, baud_rate: u32) -> Result<(), GpsSpawnError> {
        let timeout = Duration::from_secs(1);

        let mut port = serialport::new(port_name, baud_rate)
            .timeout(timeout)
            .open()
            .map_err(|e| {
                println!("Error opening serial port: {}", e);
                GpsSpawnError::PortNotOpen
            })?;

        // Example: set timeout after opening
        if let Err(e) = port.set_timeout(timeout) {
            println!("Error setting timeout: {}", e);
            return Err(GpsSpawnError::PortNotOpen)
        }

        drop(port);

        Ok(())
    }


    async fn try_spawn(
        &mut self,
        action_tx: &mpsc::Sender<SpawnEvent>,
    ) -> Result<(), GpsSpawnError> {
        match self.check_port(self.config.address.clone(), self.config.baud_rate).await {
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