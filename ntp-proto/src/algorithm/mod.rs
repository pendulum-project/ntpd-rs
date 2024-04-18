use std::{fmt::Debug, hash::Hash, time::Duration};

use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::{
    clock::NtpClock,
    config::{SourceDefaultsConfig, SynchronizationConfig},
    peer::Measurement,
    system::TimeSnapshot,
    time_types::{NtpDuration, NtpTimestamp},
};

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ObservablePeerTimedata {
    pub offset: NtpDuration,
    pub uncertainty: NtpDuration,
    pub delay: NtpDuration,

    pub remote_delay: NtpDuration,
    pub remote_uncertainty: NtpDuration,

    pub last_update: NtpTimestamp,
}

#[derive(Debug, Clone)]
pub struct StateUpdate<PeerID: Eq + Copy + Debug> {
    // Update to the time snapshot, if any
    pub time_snapshot: Option<TimeSnapshot>,
    // Update to the used peers, if any
    pub used_peers: Option<Vec<PeerID>>,
    // Requested timestamp for next non-measurement update
    pub next_update: Option<Duration>,
}

// Note: this default implementation is neccessary since the
// derive only works if PeerID is Default (which it isn't
// neccessarily)
impl<PeerID: Eq + Copy + Debug> Default for StateUpdate<PeerID> {
    fn default() -> Self {
        Self {
            time_snapshot: None,
            used_peers: None,
            next_update: None,
        }
    }
}

pub trait TimeSyncController<C: NtpClock, PeerID: Hash + Eq + Copy + Debug>: Sized {
    type AlgorithmConfig: Debug + Copy + DeserializeOwned;

    /// Create a new clock controller controling the given clock
    fn new(
        clock: C,
        synchronization_config: SynchronizationConfig,
        peer_defaults_config: SourceDefaultsConfig,
        algorithm_config: Self::AlgorithmConfig,
    ) -> Result<Self, C::Error>;
    /// Update used system config
    fn update_config(
        &mut self,
        synchronization_config: SynchronizationConfig,
        peer_defaults_config: SourceDefaultsConfig,
        algorithm_config: Self::AlgorithmConfig,
    );
    /// Notify the controller that there is a new peer
    fn peer_add(&mut self, id: PeerID);
    /// Notify the controller that a previous peer has gone
    fn peer_remove(&mut self, id: PeerID);
    /// Notify the controller that the status of a peer (whether
    /// or not it is usable for synchronization) has changed.
    fn peer_update(&mut self, id: PeerID, usable: bool);
    /// Notify the controller of a new measurement from a peer.
    /// The list of peerIDs is used for loop detection, with the
    /// first peerID given considered the primary peer used.
    fn peer_measurement(&mut self, id: PeerID, measurement: Measurement) -> StateUpdate<PeerID>;
    /// Non-measurement driven update (queued via next_update)
    fn time_update(&mut self) -> StateUpdate<PeerID>;
    /// Get a snapshot of the timekeeping state of a peer.
    fn peer_snapshot(&self, id: PeerID) -> Option<ObservablePeerTimedata>;
}

mod kalman;

pub use kalman::config::AlgorithmConfig;
pub use kalman::KalmanClockController;
