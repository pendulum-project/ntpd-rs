use std::{net::SocketAddr, sync::atomic::AtomicU64, time::Duration};

use gps::GpsSpawnError;
use ntp_proto::{ProtocolVersion, SourceNtsData};
use serde::{Deserialize, Serialize};
use tokio::{
    sync::mpsc,
    time::{timeout, Instant},
};

use super::{config::NormalizedAddress, system::NETWORK_WAIT_PERIOD};

#[cfg(test)]
pub mod dummy;
pub mod nts;
#[cfg(feature = "unstable_nts-pool")]
pub mod nts_pool;
pub mod pool;
pub mod standard;
pub mod gps;
pub mod pps;

/// Unique identifier for a spawner.
/// This is used to identify which spawner was used to create a source
#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
pub struct SpawnerId(u64);

impl SpawnerId {
    pub fn new() -> SpawnerId {
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        SpawnerId(COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
    }
}

impl Default for SpawnerId {
    fn default() -> Self {
        Self::new()
    }
}

/// Unique identifier for a source.
/// This soiurce id makes sure that even if the network address is the same
/// that we always know which specific spawned source we are talking about.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash, Serialize, Deserialize)]
pub struct SourceId(u64);

impl SourceId {
    pub fn new() -> SourceId {
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        SourceId(COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
    }
}

impl Default for SourceId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for SourceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A `SpawnEvent` is an event created by the spawner for the system
///
/// The action that the system should execute is encoded in the `action` field.
/// The spawner should make sure that it only ever sends events with its own
/// spawner id.
#[derive(Debug)]
pub struct SpawnEvent {
    pub id: SpawnerId,
    pub action: SpawnAction,
}

impl SpawnEvent {
    pub fn new(id: SpawnerId, action: SpawnAction) -> SpawnEvent {
        SpawnEvent { id, action }
    }
}

/// Events coming from the system are encoded in this enum
#[derive(Debug)]
pub enum SystemEvent {
    SourceRemoved(SourceRemovedEvent),
    SourceRegistered(SourceCreateParameters),
    GpsSourceRegistered(GpsSourceCreateParameters),
    PpsSourceRegistered(PpsSourceCreateParameters),
    Idle,
}

impl SystemEvent {
    pub fn source_removed(id: SourceId, reason: SourceRemovalReason) -> SystemEvent {
        SystemEvent::SourceRemoved(SourceRemovedEvent { id, reason })
    }
}

#[derive(Debug)]
pub struct SourceRemovedEvent {
    pub id: SourceId,
    pub reason: SourceRemovalReason,
}

/// This indicates what the reason was that a source was removed.
#[derive(Debug, PartialEq, Eq)]
pub enum SourceRemovalReason {
    Demobilized,
    NetworkIssue,
    Unreachable,
}

/// The kind of action that the spawner requests to the system.
/// Currently a spawner can only create sources
#[derive(Debug)]
pub enum SpawnAction {
    Create(SourceCreateParameters),
    CreateGps(GpsSourceCreateParameters),
    CreatePps(PpsSourceCreateParameters),
    // Remove(()),
}

impl SpawnAction {
    pub fn create(
        id: SourceId,
        addr: SocketAddr,
        normalized_addr: NormalizedAddress,
        protocol_version: ProtocolVersion,
        nts: Option<Box<SourceNtsData>>,
    ) -> SpawnAction {
        SpawnAction::Create(SourceCreateParameters {
            id,
            addr,
            normalized_addr,
            protocol_version,
            nts,
        })
    }

    pub fn create_gps(
        id: SourceId,
        addr: String,
        measurement_noise: f64,
        baud_rate: u32,

    ) -> SpawnAction{
        SpawnAction::CreateGps(GpsSourceCreateParameters {
            id,
            addr,
            measurement_noise,
            baud_rate,
        })
    }

    pub fn create_pps(
        id: SourceId,
        addr: String,
        measurement_noise: f64,
    ) -> SpawnAction{
        SpawnAction::CreatePps(PpsSourceCreateParameters {
            id,
            addr,
            measurement_noise,
        })
    }
}

#[derive(Debug)]
pub struct SourceCreateParameters {
    pub id: SourceId,
    pub addr: SocketAddr,
    pub normalized_addr: NormalizedAddress,
    pub protocol_version: ProtocolVersion,
    pub nts: Option<Box<SourceNtsData>>,
}

#[derive(Debug)]
pub struct GpsSourceCreateParameters {
    pub id: SourceId,
    pub addr: String,
    pub measurement_noise: f64,
    pub baud_rate: u32,
}

#[derive(Debug)]
pub struct PpsSourceCreateParameters {
    pub id: SourceId,
    pub addr: String,
    pub measurement_noise: f64,
}

#[cfg(test)]
impl SourceCreateParameters {
    pub fn from_new_addr(addr: SocketAddr) -> SourceCreateParameters {
        Self::from_addr(SourceId::new(), addr)
    }

    pub fn from_addr(id: SourceId, addr: SocketAddr) -> SourceCreateParameters {
        SourceCreateParameters {
            id,
            addr,
            normalized_addr: NormalizedAddress::from_string_ntp(format!(
                "{}:{}",
                addr.ip(),
                addr.port()
            ))
            .unwrap(),
            protocol_version: ProtocolVersion::default(),
            nts: None,
        }
    }

    pub fn from_ip_and_port(
        id: SourceId,
        ip: impl Into<String>,
        port: u16,
    ) -> SourceCreateParameters {
        Self::from_addr(
            id,
            SocketAddr::new(
                ip.into().parse().expect("Invalid ip address specified"),
                port,
            ),
        )
    }

    pub fn from_new_ip_and_port(ip: impl Into<String>, port: u16) -> SourceCreateParameters {
        Self::from_ip_and_port(SourceId::new(), ip, port)
    }
}

#[async_trait::async_trait]
pub trait PortChecker: Send + Sync {
    async fn check_port(&self, port_name: String, baud_rate: u32) -> Result<(), GpsSpawnError>;
}

pub struct RealPortChecker;

#[async_trait::async_trait]
impl PortChecker for RealPortChecker {
    async fn check_port(&self, port_name: String, baud_rate: u32) -> Result<(), GpsSpawnError> {
        let timeout = Duration::from_secs(1);

        let mut port = serialport::new(port_name, baud_rate)
            .timeout(timeout)
            .open()
            .map_err(|_e| {
                GpsSpawnError::PortNotOpen
            })?;

        if let Err(_e) = port.set_timeout(timeout) {
            return Err(GpsSpawnError::PortNotOpen)
        }

        drop(port);

        Ok(())
    }
}

pub struct MockPortChecker;

#[async_trait::async_trait]
impl PortChecker for MockPortChecker {
    async fn check_port(&self, _port_name: String, _baud_rate: u32) -> Result<(), GpsSpawnError> {
        Ok(())
    }
}
#[async_trait::async_trait]
pub trait Spawner {
    type Error: std::error::Error + Send;

    /// Run a spawner
    ///
    /// Actions that the system has to execute can be sent through the
    /// `action_tx` channel and event coming in from the system that the spawner
    /// should know about will be sent through the `system_notify` channel.
    async fn run(
        self,
        action_tx: mpsc::Sender<SpawnEvent>,
        system_notify: mpsc::Receiver<SystemEvent>,
    ) -> Result<(), Self::Error>;

    /// Returns the id of this spawner
    fn get_id(&self) -> SpawnerId;

    /// Get a description of the address that this spawner is connected to
    fn get_addr_description(&self) -> String;

    /// Get a description of the type of spawner
    fn get_description(&self) -> &str;
}

#[async_trait::async_trait]
pub trait BasicSpawner {
    type Error: std::error::Error + Send;

    /// Try to create all desired sources. Should return immediately on failure
    ///
    /// It is ok for this function to use some time when spawning a new client.
    /// However, it should not implement it's own retry or backoff feature, but
    /// rather rely on that provided by the basic spawner.
    async fn try_spawn(&mut self, action_tx: &mpsc::Sender<SpawnEvent>) -> Result<(), Self::Error>;

    /// Is there desire to spawn new sources?
    fn is_complete(&self) -> bool;

    /// Event handler for when a source is removed.
    ///
    /// This is called each time the system notifies this spawner that one of
    /// the spawned sources was removed from the system. The spawner can then add
    /// additional sources or do nothing, depending on its configuration and
    /// algorithm.
    ///
    /// This should just do bookkeeping, any adding of sources should be done
    /// in try_add.
    async fn handle_source_removed(&mut self, event: SourceRemovedEvent)
        -> Result<(), Self::Error>;

    /// Event handler for when a source is succesfully registered in the system
    ///
    /// Every time the spawner sends a source to the system this handler will
    /// eventually be called when the system has sucessfully registered the source
    /// and will start polling it for ntp packets.
    ///
    /// This should just do bookkeeping, any adding of sources should be done
    /// in try_add.
    async fn handle_registered(
        &mut self,
        _event: SourceCreateParameters,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn handle_gps_registered(
        &mut self,
        _event: GpsSourceCreateParameters,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn handle_pps_registered(
        &mut self,
        _event: PpsSourceCreateParameters,
    ) -> Result<(), Self::Error> {
        Ok(())
    }


    /// Get the id of the spawner
    fn get_id(&self) -> SpawnerId;

    /// Get a description of the address this spawner is connected to
    fn get_addr_description(&self) -> String;

    /// Get a description of the type of spawner
    fn get_description(&self) -> &str;
}

#[async_trait::async_trait]
impl<T, E> Spawner for T
where
    T: BasicSpawner<Error = E> + Send + 'static,
    E: std::error::Error + Send + 'static,
{
    type Error = E;

    async fn run(
        mut self,
        action_tx: mpsc::Sender<SpawnEvent>,
        mut system_notify: mpsc::Receiver<SystemEvent>,
    ) -> Result<(), E> {
        let mut has_ticket = true;
        let mut last_ticket_time = Instant::now();

        loop {
            if last_ticket_time.elapsed() >= NETWORK_WAIT_PERIOD {
                has_ticket = true;
            }

            if has_ticket && !self.is_complete() {
                self.try_spawn(&action_tx).await?;
                has_ticket = false;
                last_ticket_time = Instant::now();
            }

            let event = if has_ticket {
                system_notify.recv().await
            } else {
                timeout(
                    NETWORK_WAIT_PERIOD - last_ticket_time.elapsed(),
                    system_notify.recv(),
                )
                .await
                .unwrap_or(Some(SystemEvent::Idle))
            };

            let Some(event) = event else {
                break;
            };

            match event {
                SystemEvent::SourceRegistered(source_params) => {
                    self.handle_registered(source_params).await?;
                }
                SystemEvent::SourceRemoved(removed_source) => {
                    self.handle_source_removed(removed_source).await?;
                }
                SystemEvent::GpsSourceRegistered(source_params) => {
                    self.handle_gps_registered(source_params).await?;
                }
                SystemEvent::PpsSourceRegistered(source_params) => {
                    self.handle_pps_registered(source_params).await?;
                }
                SystemEvent::Idle => {}
            }
        }

        Ok(())
    }

    fn get_id(&self) -> SpawnerId {
        self.get_id()
    }

    fn get_addr_description(&self) -> String {
        self.get_addr_description()
    }

    fn get_description(&self) -> &str {
        self.get_description()
    }
}

#[cfg(test)]
mod tests {
    use super::{GpsSourceCreateParameters, PpsSourceCreateParameters, SourceCreateParameters, SpawnAction, SpawnEvent};

    pub fn get_create_params(res: SpawnEvent) -> SourceCreateParameters {
        if let SpawnAction::Create(params) = res.action {
            params
        } else {
            panic!("Expected SpawnAction::Create variant");
        }
    }

    pub fn get_create_gps_params(res: SpawnEvent) -> GpsSourceCreateParameters {
        if let SpawnAction::CreateGps(params) = res.action {
            params
        } else {
            panic!("Expected SpawnAction::Create variant");
        }
    }

    pub fn get_create_pps_params(res: SpawnEvent) -> PpsSourceCreateParameters {
        if let SpawnAction::CreatePps(params) = res.action {
            params
        } else {
            panic!("Expected SpawnAction::Create variant");
        }
    }

   
}