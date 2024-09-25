use std::{net::SocketAddr, sync::atomic::AtomicU64};

use ntp_proto::{ProtocolVersion, SourceNtsData};
use serde::{Deserialize, Serialize};
use tokio::{
    sync::mpsc,
    time::{timeout, Instant},
};

use super::{config::NormalizedAddress, system::NETWORK_WAIT_PERIOD};

pub mod nts;
#[cfg(feature = "unstable_nts-pool")]
pub mod nts_pool;
pub mod pool;
pub mod sock;
pub mod standard;

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
/// This source id makes sure that even if the network address is the same
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
    // Remove(()),
}

impl SpawnAction {
    pub fn create_ntp(
        id: SourceId,
        addr: SocketAddr,
        normalized_addr: NormalizedAddress,
        protocol_version: ProtocolVersion,
        nts: Option<Box<SourceNtsData>>,
    ) -> SpawnAction {
        SpawnAction::Create(SourceCreateParameters::Ntp(NtpSourceCreateParameters {
            id,
            addr,
            normalized_addr,
            protocol_version,
            nts,
        }))
    }
}

#[derive(Debug)]
pub enum SourceCreateParameters {
    Ntp(NtpSourceCreateParameters),
    Sock(SockSourceCreateParameters),
}

#[derive(Debug)]
pub struct NtpSourceCreateParameters {
    pub id: SourceId,
    pub addr: SocketAddr,
    pub normalized_addr: NormalizedAddress,
    pub protocol_version: ProtocolVersion,
    pub nts: Option<Box<SourceNtsData>>,
}

#[derive(Debug)]
pub struct SockSourceCreateParameters {
    pub id: SourceId,
    pub path: String,
}

#[async_trait::async_trait]
pub trait Spawner {
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

    /// Event handler for when a source is successfully registered in the system
    ///
    /// Every time the spawner sends a source to the system this handler will
    /// eventually be called when the system has successfully registered the source
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

    /// Get the id of the spawner
    fn get_id(&self) -> SpawnerId;

    /// Get a description of the address this spawner is connected to
    fn get_addr_description(&self) -> String;

    /// Get a description of the type of spawner
    fn get_description(&self) -> &str;
}

pub async fn spawner_task<S: Spawner + Send + 'static>(
    mut spawner: S,
    action_tx: mpsc::Sender<SpawnEvent>,
    mut system_notify: mpsc::Receiver<SystemEvent>,
) -> Result<(), S::Error> {
    let mut has_ticket = true;
    let mut last_ticket_time = Instant::now();

    loop {
        if last_ticket_time.elapsed() >= NETWORK_WAIT_PERIOD {
            has_ticket = true;
        }

        if has_ticket && !spawner.is_complete() {
            spawner.try_spawn(&action_tx).await?;
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
                spawner.handle_registered(source_params).await?;
            }
            SystemEvent::SourceRemoved(removed_source) => {
                spawner.handle_source_removed(removed_source).await?;
            }
            SystemEvent::Idle => {}
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{NtpSourceCreateParameters, SourceCreateParameters, SpawnAction, SpawnEvent};

    pub fn get_npt_create_params(res: SpawnEvent) -> Option<NtpSourceCreateParameters> {
        let SpawnAction::Create(SourceCreateParameters::Ntp(params)) = res.action else {
            return None;
        };
        Some(params)
    }
}
