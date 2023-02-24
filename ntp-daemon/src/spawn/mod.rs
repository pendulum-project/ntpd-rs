use std::{net::SocketAddr, sync::atomic::AtomicU64};

use ntp_proto::PeerNtsData;
use tokio::sync::mpsc;

use crate::config::NormalizedAddress;

#[cfg(test)]
pub mod dummy;
pub mod nts;
pub mod pool;
pub mod standard;

/// Unique identifier for a spawner
/// This is used to identify which spawner was used to create a peer
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
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

/// Unique identifier for a peer created by a spawner
/// This peer id makes sure that even if the network address is the same
/// that we always know which specific spawned peer we are talking about.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
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

#[derive(Debug)]
pub struct SpawnEvent {
    pub id: SpawnerId,
    pub action: SpawnAction,
}

#[derive(Debug)]
pub enum SystemEvent {
    PeerRemoved(PeerRemovedEvent),
    PeerRegistered(PeerCreateParameters),
    Shutdown,
}

impl SystemEvent {
    pub fn peer_removed(id: PeerId, reason: PeerRemovalReason) -> SystemEvent {
        SystemEvent::PeerRemoved(PeerRemovedEvent { id, reason })
    }

    pub fn peer_registered(
        id: PeerId,
        addr: SocketAddr,
        normalized_addr: NormalizedAddress,
        nts: Option<PeerNtsData>,
    ) -> SystemEvent {
        SystemEvent::PeerRegistered(PeerCreateParameters {
            id,
            addr,
            normalized_addr,
            nts,
        })
    }
}

#[derive(Debug)]
pub struct PeerRemovedEvent {
    pub id: PeerId,
    pub reason: PeerRemovalReason,
}

#[derive(Debug)]
pub enum PeerRemovalReason {
    Demobilized,
    NetworkIssue,
}

impl SpawnEvent {
    pub fn new(id: SpawnerId, action: SpawnAction) -> SpawnEvent {
        SpawnEvent { id, action }
    }
}

/// The kind of action that the spawner requests to the system
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
        nts: Option<PeerNtsData>,
    ) -> SpawnAction {
        SpawnAction::Create(PeerCreateParameters {
            id,
            addr,
            normalized_addr,
            nts,
        })
    }
}

#[derive(Debug)]
pub struct PeerCreateParameters {
    pub id: PeerId,
    pub addr: SocketAddr,
    pub normalized_addr: NormalizedAddress,
    pub nts: Option<PeerNtsData>,
}

#[cfg(test)]
impl PeerCreateParameters {
    pub fn from_addr(addr: SocketAddr) -> PeerCreateParameters {
        PeerCreateParameters {
            id: PeerId::new(),
            addr,
            normalized_addr: NormalizedAddress::from_string_ntp(format!(
                "{}:{}",
                addr.ip(),
                addr.port()
            ))
            .unwrap(),
            nts: None,
        }
    }

    pub fn from_ip_and_port(ip: impl Into<String>, port: u16) -> PeerCreateParameters {
        Self::from_addr(SocketAddr::new(
            ip.into().parse().expect("Invalid ip address specified"),
            port,
        ))
    }

    pub async fn from_normalized(addr: NormalizedAddress) -> PeerCreateParameters {
        let socket_addr = addr
            .lookup_host()
            .await
            .expect("Lookup failed")
            .next()
            .expect("Lookup unexpectedly returned zero responses");
        PeerCreateParameters {
            id: PeerId::new(),
            addr: socket_addr,
            normalized_addr: addr,
            nts: None,
        }
    }
}

pub trait Spawner {
    fn run(self, action_tx: mpsc::Sender<SpawnEvent>, system_notify: mpsc::Receiver<SystemEvent>);
    fn get_id(&self) -> SpawnerId;
    fn get_addr_description(&self) -> String;
}

#[async_trait::async_trait]
pub trait BasicSpawner {
    type Error: std::error::Error;
    async fn handle_init(
        &mut self,
        action_tx: &mpsc::Sender<SpawnEvent>,
    ) -> Result<(), Self::Error>;
    async fn handle_peer_removed(
        &mut self,
        event: PeerRemovedEvent,
        action_tx: &mpsc::Sender<SpawnEvent>,
    ) -> Result<(), Self::Error>;
    async fn handle_registered(
        &mut self,
        _event: PeerCreateParameters,
        _action_tx: &mpsc::Sender<SpawnEvent>,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn get_id(&self) -> SpawnerId;
    fn get_addr_description(&self) -> String;
}

impl<T, E> Spawner for T
where
    T: BasicSpawner<Error = E> + Send + 'static,
    E: std::error::Error + Send + 'static,
{
    fn run(
        mut self,
        action_tx: mpsc::Sender<SpawnEvent>,
        mut system_notify: mpsc::Receiver<SystemEvent>,
    ) {
        tokio::spawn(async move {
            self.handle_init(&action_tx).await?;
            while let Some(event) = system_notify.recv().await {
                match event {
                    SystemEvent::PeerRegistered(peer_params) => {
                        self.handle_registered(peer_params, &action_tx).await?;
                    }
                    SystemEvent::PeerRemoved(removed_peer) => {
                        self.handle_peer_removed(removed_peer, &action_tx).await?;
                    }
                    SystemEvent::Shutdown => {
                        break;
                    }
                }
            }

            Ok::<(), E>(())
        });
    }

    fn get_id(&self) -> SpawnerId {
        self.get_id()
    }

    fn get_addr_description(&self) -> String {
        self.get_addr_description()
    }
}
