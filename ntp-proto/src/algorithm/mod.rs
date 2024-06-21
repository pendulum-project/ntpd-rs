use std::{fmt::Debug, hash::Hash, time::Duration};

use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::{
    clock::NtpClock,
    config::{SourceDefaultsConfig, SynchronizationConfig},
    source::Measurement,
    system::TimeSnapshot,
    time_types::{NtpDuration, NtpTimestamp},
};

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ObservableSourceTimedata {
    pub offset: NtpDuration,
    pub uncertainty: NtpDuration,
    pub delay: NtpDuration,

    pub remote_delay: NtpDuration,
    pub remote_uncertainty: NtpDuration,

    pub last_update: NtpTimestamp,
}

#[derive(Debug, Clone)]
pub struct StateUpdate<SourceId: Eq + Copy + Debug> {
    // Update to the time snapshot, if any
    pub time_snapshot: Option<TimeSnapshot>,
    // Update to the used sources, if any
    pub used_sources: Option<Vec<SourceId>>,
    // Requested timestamp for next non-measurement update
    pub next_update: Option<Duration>,
}

// Note: this default implementation is neccessary since the
// derive only works if SourceId is Default (which it isn't
// neccessarily)
impl<SourceId: Eq + Copy + Debug> Default for StateUpdate<SourceId> {
    fn default() -> Self {
        Self {
            time_snapshot: None,
            used_sources: None,
            next_update: None,
        }
    }
}

pub trait TimeSyncController<C: NtpClock, SourceId: Hash + Eq + Copy + Debug>: Sized {
    type AlgorithmConfig: Debug + Copy + DeserializeOwned;

    /// Create a new clock controller controling the given clock
    fn new(
        clock: C,
        synchronization_config: SynchronizationConfig,
        source_defaults_config: SourceDefaultsConfig,
        algorithm_config: Self::AlgorithmConfig,
        pps_source_id: Option<SourceId>,
    ) -> Result<Self, C::Error>;
    /// Update used system config
    fn update_config(
        &mut self,
        synchronization_config: SynchronizationConfig,
        source_defaults_config: SourceDefaultsConfig,
        algorithm_config: Self::AlgorithmConfig,
    );
    /// Notify the controller that there is a new source
    fn add_source(&mut self, id: SourceId);
    /// Notify the controller that a previous source has gone
    fn remove_source(&mut self, id: SourceId);
    /// Notify the controller that the status of a source (whether
    /// or not it is usable for synchronization) has changed.
    fn source_update(&mut self, id: SourceId, usable: bool);
    fn source_pps_update(&mut self, id: SourceId, usable: bool);
    /// Notify the controller of a new measurement from a source.
    /// The list of SourceIds is used for loop detection, with the
    /// first SourceId given considered the primary source used.
    fn source_measurement(
        &mut self,
        id: SourceId,
        measurement: Measurement,
    ) -> StateUpdate<SourceId>;

    fn source_pps_measurement(
        &mut self,
        id: SourceId,
        measurement: Measurement,
    ) -> StateUpdate<SourceId>;
    /// Non-measurement driven update (queued via next_update)
    fn time_update(&mut self) -> StateUpdate<SourceId>;
    /// Get a snapshot of the timekeeping state of a source.
    fn source_snapshot(&self, id: SourceId) -> Option<ObservableSourceTimedata>;
}

pub mod kalman;

pub use kalman::config::AlgorithmConfig;
pub use kalman::KalmanClockController;
