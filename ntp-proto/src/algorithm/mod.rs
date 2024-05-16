use std::{fmt::Debug, hash::Hash, time::Duration};

use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::{
    clock::NtpClock,
    config::{SourceDefaultsConfig, SynchronizationConfig},
    source::Measurement,
    system::TimeSnapshot,
    time_types::{NtpDuration, NtpTimestamp},
    PollInterval,
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
pub struct StateUpdate<SourceId: Eq + Copy + Debug, ControllerMessage: Clone> {
    // Message for all sources, if any
    pub source_message: Option<ControllerMessage>,
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
impl<SourceId: Eq + Copy + Debug, ControllerMessage: Clone> Default
    for StateUpdate<SourceId, ControllerMessage>
{
    fn default() -> Self {
        Self {
            source_message: None,
            time_snapshot: None,
            used_sources: None,
            next_update: None,
        }
    }
}

pub trait TimeSyncController<C: NtpClock, SourceId: Hash + Eq + Copy + Debug>: Sized {
    type AlgorithmConfig: Debug + Copy + DeserializeOwned;
    type ControllerMessage: Debug + Clone;
    type SourceMessage: Debug + Clone;
    type SourceController: SourceController<
        ControllerMessage = Self::ControllerMessage,
        SourceMessage = Self::SourceMessage,
    >;

    /// Create a new clock controller controling the given clock
    fn new(
        clock: C,
        synchronization_config: SynchronizationConfig,
        source_defaults_config: SourceDefaultsConfig,
        algorithm_config: Self::AlgorithmConfig,
    ) -> Result<Self, C::Error>;

    /// Create a new source with given identity
    fn add_source(&mut self, id: SourceId) -> Self::SourceController;
    /// Notify the controller that a previous source has gone
    fn remove_source(&mut self, id: SourceId);
    /// Notify the controller that the status of a source (whether
    /// or not it is usable for synchronization) has changed.
    fn source_update(&mut self, id: SourceId, usable: bool);
    /// Notify the controller of a new measurement from a source.
    /// The list of SourceIds is used for loop detection, with the
    /// first SourceId given considered the primary source used.
    fn source_message(
        &mut self,
        id: SourceId,
        message: Self::SourceMessage,
    ) -> StateUpdate<SourceId, Self::ControllerMessage>;
    /// Non-message driven update (queued via next_update)
    fn time_update(&mut self) -> StateUpdate<SourceId, Self::ControllerMessage>;
}

pub trait SourceController: Sized {
    type ControllerMessage: Debug + Clone;
    type SourceMessage: Debug + Clone;

    fn handle_message(&mut self, message: Self::ControllerMessage);

    fn handle_measurement(&mut self, measurement: Measurement) -> Option<Self::SourceMessage>;

    fn desired_poll_interval(&self) -> PollInterval;

    fn observe(&self) -> ObservableSourceTimedata;
}

mod kalman;

pub use kalman::{
    config::AlgorithmConfig, KalmanClockController, KalmanControllerMessage,
    KalmanSourceController, KalmanSourceMessage,
};
