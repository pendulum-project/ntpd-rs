use std::{fmt::Debug, hash::Hash};

use serde::{Deserialize, Serialize};

use crate::{
    peer::Measurement, NtpClock, NtpDuration, NtpPacket, NtpTimestamp, SystemConfig, TimeSnapshot,
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

pub trait TimeSyncController<C: NtpClock, PeerID: Hash + Eq + Copy + Debug> {
    /// Create a new clock controller controling the given clock
    fn new(clock: C, config: SystemConfig) -> Self;
    /// Update used system config
    fn update_config(&mut self, config: SystemConfig);
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
    fn peer_measurement(
        &mut self,
        id: PeerID,
        measurement: Measurement,
        packet: NtpPacket<'static>,
    ) -> Option<(Vec<PeerID>, TimeSnapshot)>;
    /// Get a snapshot of the timekeeping state of a peer.
    fn peer_snapshot(&self, id: PeerID) -> Option<ObservablePeerTimedata>;
}

mod standard;

pub type DefaultTimeSyncController<C, PeerID> = standard::StandardClockController<C, PeerID>;
