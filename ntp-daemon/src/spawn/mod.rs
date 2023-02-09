use std::{sync::atomic::AtomicU64, net::SocketAddr};

use ntp_proto::PeerNtsData;
use tokio::sync::mpsc;

use crate::config::NormalizedAddress;

pub mod pool;
pub mod standard;
pub mod nts;


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

#[derive(Debug)]
pub struct SpawnEvent {
    pub id: SpawnerId,
    pub action: SpawnAction,
}

#[derive(Debug)]
pub struct RemovedPeer {
    pub id: PeerId,
    pub reason: PeerRemovalReason,
}

impl RemovedPeer {
    pub fn new(id: PeerId, reason: PeerRemovalReason) -> RemovedPeer {
        RemovedPeer {
            id,
            reason,
        }
    }
}

#[derive(Debug)]
pub enum PeerRemovalReason {
    Demobilized,
    NetworkIssue,
}

impl SpawnEvent {
    pub fn new(id: SpawnerId, action: SpawnAction) -> SpawnEvent {
        SpawnEvent {
            id,
            action,
        }
    }
}

/// The kind of action that the spawner requests to the system
/// Currently a spawner can only create peers
#[derive(Debug)]
pub enum SpawnAction {
    Create(PeerId, SocketAddr, NormalizedAddress, Option<PeerNtsData>),
    // Remove(()),
}

pub trait Spawner {
    fn run(self, action_tx: mpsc::Sender<SpawnEvent>, peer_removed_notify: mpsc::Receiver<RemovedPeer>);
    fn get_id(&self) -> SpawnerId;
}

#[async_trait::async_trait]
pub trait BasicSpawner {
    type Error: std::error::Error;
    async fn handle_init(&mut self, action_tx: &mpsc::Sender<SpawnEvent>) -> Result<(), Self::Error>;
    async fn handle_peer_removed(&mut self, removed_peer: RemovedPeer, action_tx: &mpsc::Sender<SpawnEvent>) -> Result<(), Self::Error>;

    fn get_id(&self) -> SpawnerId;
}

impl<E: std::error::Error + Send + 'static, T: BasicSpawner<Error = E> + Send + 'static> Spawner for T {
    fn run(mut self, action_tx: mpsc::Sender<SpawnEvent>, mut peer_removed_notify: mpsc::Receiver<RemovedPeer>) {
        tokio::spawn(async move {
            self.handle_init(&action_tx).await?;
            while let Some(removed_peer) = peer_removed_notify.recv().await {
                self.handle_peer_removed(removed_peer, &action_tx).await?;
            }

            Ok::<(), E>(())
        });
    }

    fn get_id(&self) -> SpawnerId {
        self.get_id()
    }
}
