use std::{net::SocketAddr, sync::atomic::AtomicU64};

use ntp_proto::{PeerNtsData, ProtocolVersion};
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

/// Unique identifier for a spawner.
/// This is used to identify which spawner was used to create a peer
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

/// Unique identifier for a peer.
/// This peer id makes sure that even if the network address is the same
/// that we always know which specific spawned peer we are talking about.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash, Serialize, Deserialize)]
pub struct PeerId(u64);

impl PeerId {
    pub fn new() -> PeerId {
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        PeerId(COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
    }
}

impl Default for PeerId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for PeerId {
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
    PeerRemoved(PeerRemovedEvent),
    PeerRegistered(PeerCreateParameters),
    Idle,
}

impl SystemEvent {
    pub fn peer_removed(id: PeerId, reason: PeerRemovalReason) -> SystemEvent {
        SystemEvent::PeerRemoved(PeerRemovedEvent { id, reason })
    }
}

#[derive(Debug)]
pub struct PeerRemovedEvent {
    pub id: PeerId,
    pub reason: PeerRemovalReason,
}

/// This indicates what the reason was that a peer was removed.
#[derive(Debug, PartialEq, Eq)]
pub enum PeerRemovalReason {
    Demobilized,
    NetworkIssue,
    Unreachable,
}

/// The kind of action that the spawner requests to the system.
/// Currently a spawner can only create peers
#[derive(Debug)]
pub enum SpawnAction {
    Create(PeerCreateParameters),
    // Remove(()),
}

impl SpawnAction {
    pub fn create(
        id: PeerId,
        addr: SocketAddr,
        normalized_addr: NormalizedAddress,
        protocol_version: ProtocolVersion,
        nts: Option<Box<PeerNtsData>>,
    ) -> SpawnAction {
        SpawnAction::Create(PeerCreateParameters {
            id,
            addr,
            normalized_addr,
            protocol_version,
            nts,
        })
    }
}

#[derive(Debug)]
pub struct PeerCreateParameters {
    pub id: PeerId,
    pub addr: SocketAddr,
    pub normalized_addr: NormalizedAddress,
    pub protocol_version: ProtocolVersion,
    pub nts: Option<Box<PeerNtsData>>,
}

#[cfg(test)]
impl PeerCreateParameters {
    pub fn from_new_addr(addr: SocketAddr) -> PeerCreateParameters {
        Self::from_addr(PeerId::new(), addr)
    }

    pub fn from_addr(id: PeerId, addr: SocketAddr) -> PeerCreateParameters {
        PeerCreateParameters {
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

    pub fn from_ip_and_port(id: PeerId, ip: impl Into<String>, port: u16) -> PeerCreateParameters {
        Self::from_addr(
            id,
            SocketAddr::new(
                ip.into().parse().expect("Invalid ip address specified"),
                port,
            ),
        )
    }

    pub fn from_new_ip_and_port(ip: impl Into<String>, port: u16) -> PeerCreateParameters {
        Self::from_ip_and_port(PeerId::new(), ip, port)
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

    /// Try to create all desired peers. Should return immediately on failure
    ///
    ///
    async fn try_spawn(&mut self, action_tx: &mpsc::Sender<SpawnEvent>) -> Result<(), Self::Error>;

    /// Is there desire to spawn new peers?
    fn is_complete(&self) -> bool;

    /// Event handler for when a peer is removed.
    ///
    /// This is called each time the system notifies this spawner that one of
    /// the spawned peers was removed from the system. The spawner can then add
    /// additional peers or do nothing, depending on its configuration and
    /// algorithm.
    ///
    /// This should just do bookkeeping, any adding of peers should be done
    /// in try_add.
    async fn handle_peer_removed(&mut self, event: PeerRemovedEvent) -> Result<(), Self::Error>;

    /// Event handler for when a peer is succesfully registered in the system
    ///
    /// Every time the spawner sends a peer to the system this handler will
    /// eventually be called when the system has sucessfully registered the peer
    /// and will start polling it for ntp packets.
    ///
    /// This should just do bookkeeping, any adding of peers should be done
    /// in try_add.
    async fn handle_registered(&mut self, _event: PeerCreateParameters) -> Result<(), Self::Error> {
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
            if Instant::now() - last_ticket_time >= NETWORK_WAIT_PERIOD {
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
                    last_ticket_time + NETWORK_WAIT_PERIOD - Instant::now(),
                    system_notify.recv(),
                )
                .await
                .unwrap_or(Some(SystemEvent::Idle))
            };

            let Some(event) = event else {
                break;
            };

            match event {
                SystemEvent::PeerRegistered(peer_params) => {
                    self.handle_registered(peer_params).await?;
                }
                SystemEvent::PeerRemoved(removed_peer) => {
                    self.handle_peer_removed(removed_peer).await?;
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
    use super::{PeerCreateParameters, SpawnAction, SpawnEvent};

    pub fn get_create_params(res: SpawnEvent) -> PeerCreateParameters {
        let SpawnAction::Create(params) = res.action;
        params
    }
}
