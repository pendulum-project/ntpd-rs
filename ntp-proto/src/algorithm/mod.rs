use std::{fmt::Debug, time::Duration};

use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::{
    ClockId, NtpLeapIndicator, NtpPacket, PollInterval,
    clock::NtpClock,
    config::{SourceConfig, SynchronizationConfig},
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
pub struct StateUpdate<ControllerMessage> {
    // Message for all sources, if any
    pub source_message: Option<ControllerMessage>,
    // Update to the time snapshot, if any
    pub time_snapshot: Option<TimeSnapshot>,
    // Update to the used sources, if any
    pub used_sources: Option<Vec<ClockId>>,
    // Requested timestamp for next non-measurement update
    pub next_update: Option<Duration>,
}

// Note: this default implementation is necessary since the
// derive only works if ControllerMessage is Default (which it isn't
// necessarily)
impl<ControllerMessage> Default for StateUpdate<ControllerMessage> {
    fn default() -> Self {
        Self {
            source_message: None,
            time_snapshot: None,
            used_sources: None,
            next_update: None,
        }
    }
}

pub trait InternalTimeSyncController: Sized + Send + 'static {
    type Clock: NtpClock;
    type AlgorithmConfig: Debug + Copy + DeserializeOwned + Send;
    type ControllerMessage: Debug + Clone + Send + 'static;
    type SourceMessage: Debug + Clone + Send + 'static;
    type NtpSourceController: InternalSourceController<
            ControllerMessage = Self::ControllerMessage,
            SourceMessage = Self::SourceMessage,
            MeasurementDelay = NtpDuration,
        >;
    type OneWaySourceController: InternalSourceController<
            ControllerMessage = Self::ControllerMessage,
            SourceMessage = Self::SourceMessage,
            MeasurementDelay = (),
        >;

    /// Create a new clock controller controlling the given clock
    fn new(
        clock: Self::Clock,
        synchronization_config: SynchronizationConfig,
        algorithm_config: Self::AlgorithmConfig,
    ) -> Result<Self, <Self::Clock as NtpClock>::Error>;

    /// Take control of the clock (should not be done in new!)
    fn take_control(&mut self) -> Result<(), <Self::Clock as NtpClock>::Error>;

    /// Create a new source with given identity
    fn add_source(&mut self, id: ClockId, source_config: SourceConfig)
    -> Self::NtpSourceController;
    /// Create a new one way source with given identity (used e.g. with GPS sock sources)
    fn add_one_way_source(
        &mut self,
        id: ClockId,
        source_config: SourceConfig,
        measurement_noise_estimate: f64,
        period: Option<f64>,
    ) -> Self::OneWaySourceController;
    /// Notify the controller that a previous source has gone
    fn remove_source(&mut self, id: ClockId);
    /// Notify the controller that the status of a source (whether
    /// or not it is usable for synchronization) has changed.
    fn source_update(&mut self, id: ClockId, usable: bool);
    /// Notify the controller of a new measurement from a source.
    /// The list of SourceIds is used for loop detection, with the
    /// first SourceId given considered the primary source used.
    fn source_message(
        &mut self,
        id: ClockId,
        message: Self::SourceMessage,
    ) -> StateUpdate<Self::ControllerMessage>;
    /// Non-message driven update (queued via next_update)
    fn time_update(&mut self) -> StateUpdate<Self::ControllerMessage>;
}

pub trait InternalSourceController: Sized + Send + 'static {
    type ControllerMessage: Debug + Clone + Send + 'static;
    type SourceMessage: Debug + Clone + Send + 'static;
    type MeasurementDelay: Debug + Copy + Clone;

    fn handle_message(&mut self, message: Self::ControllerMessage);

    fn handle_measurement(
        &mut self,
        measurement: InternalMeasurement<Self::MeasurementDelay>,
    ) -> Option<Self::SourceMessage>;

    fn desired_poll_interval(&self) -> PollInterval;

    fn observe(&self) -> ObservableSourceTimedata;
}

mod kalman;

pub use kalman::{
    KalmanClockController, KalmanControllerMessage, KalmanSourceController, KalmanSourceMessage,
    TwoWayKalmanSourceController, config::AlgorithmConfig,
};

#[derive(Debug, Copy, Clone)]
pub struct InternalMeasurement<D: Debug + Copy + Clone> {
    pub delay: D,
    pub offset: NtpDuration,
    pub localtime: NtpTimestamp,

    pub stratum: u8,
    pub root_delay: NtpDuration,
    pub root_dispersion: NtpDuration,
    pub leap: NtpLeapIndicator,
    pub precision: i8,
}

impl<D: Debug + Copy + Clone> From<Measurement<D>> for InternalMeasurement<D> {
    fn from(value: Measurement<D>) -> Self {
        Self {
            delay: value.delay,
            offset: value.offset,
            localtime: value.localtime,
            stratum: value.stratum,
            root_delay: value.root_delay,
            root_dispersion: value.root_dispersion,
            leap: value.leap,
            precision: value.precision,
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub struct Measurement<D: Debug + Copy + Clone> {
    pub delay: D,
    pub offset: NtpDuration,
    pub localtime: NtpTimestamp,

    pub stratum: u8,
    pub root_delay: NtpDuration,
    pub root_dispersion: NtpDuration,
    pub leap: NtpLeapIndicator,
    pub precision: i8,
}

impl Measurement<NtpDuration> {
    pub(crate) fn from_packet(
        packet: &NtpPacket,
        send_timestamp: NtpTimestamp,
        recv_timestamp: NtpTimestamp,
    ) -> Self {
        Self {
            delay: (recv_timestamp - send_timestamp)
                - (packet.transmit_timestamp() - packet.receive_timestamp()),
            offset: ((packet.receive_timestamp() - send_timestamp)
                + (packet.transmit_timestamp() - recv_timestamp))
                / 2,
            localtime: send_timestamp + (recv_timestamp - send_timestamp) / 2,

            stratum: packet.stratum(),
            root_delay: packet.root_delay(),
            root_dispersion: packet.root_dispersion(),
            leap: packet.leap(),
            precision: packet.precision(),
        }
    }
}

pub trait TimeSyncController: Sized + Send + 'static {
    type Clock: NtpClock;
    type AlgorithmConfig: Debug + Copy + DeserializeOwned + Send;
    type ControllerMessage: Debug + Clone + Send + 'static;
    type SourceMessage: Debug + Clone + Send + 'static;
    type NtpSourceController: SourceController<
            ControllerMessage = Self::ControllerMessage,
            SourceMessage = Self::SourceMessage,
            MeasurementDelay = NtpDuration,
        >;
    type OneWaySourceController: SourceController<
            ControllerMessage = Self::ControllerMessage,
            SourceMessage = Self::SourceMessage,
            MeasurementDelay = (),
        >;

    /// Create a new clock controller controlling the given clock
    fn new(
        clock: Self::Clock,
        synchronization_config: SynchronizationConfig,
        algorithm_config: Self::AlgorithmConfig,
    ) -> Result<Self, <Self::Clock as NtpClock>::Error>;

    /// Take control of the clock (should not be done in new!)
    fn take_control(&mut self) -> Result<(), <Self::Clock as NtpClock>::Error>;

    /// Create a new source with given identity
    fn add_source(&mut self, id: ClockId, source_config: SourceConfig)
    -> Self::NtpSourceController;
    /// Create a new one way source with given identity (used e.g. with GPS sock sources)
    fn add_one_way_source(
        &mut self,
        id: ClockId,
        source_config: SourceConfig,
        measurement_noise_estimate: f64,
        period: Option<f64>,
    ) -> Self::OneWaySourceController;
    /// Notify the controller that a previous source has gone
    fn remove_source(&mut self, id: ClockId);
    /// Notify the controller that the status of a source (whether
    /// or not it is usable for synchronization) has changed.
    fn source_update(&mut self, id: ClockId, usable: bool);
    /// Notify the controller of a new measurement from a source.
    /// The list of SourceIds is used for loop detection, with the
    /// first SourceId given considered the primary source used.
    fn source_message(
        &mut self,
        id: ClockId,
        message: Self::SourceMessage,
    ) -> StateUpdate<Self::ControllerMessage>;
    /// Non-message driven update (queued via next_update)
    fn time_update(&mut self) -> StateUpdate<Self::ControllerMessage>;
}

impl<T: InternalTimeSyncController> TimeSyncController for T {
    type Clock = T::Clock;
    type AlgorithmConfig = T::AlgorithmConfig;
    type ControllerMessage = T::ControllerMessage;
    type SourceMessage = T::SourceMessage;
    type NtpSourceController = T::NtpSourceController;
    type OneWaySourceController = T::OneWaySourceController;

    fn new(
        clock: Self::Clock,
        synchronization_config: SynchronizationConfig,
        algorithm_config: Self::AlgorithmConfig,
    ) -> Result<Self, <Self::Clock as NtpClock>::Error> {
        T::new(clock, synchronization_config, algorithm_config)
    }

    fn take_control(&mut self) -> Result<(), <Self::Clock as NtpClock>::Error> {
        T::take_control(self)
    }

    fn add_source(
        &mut self,
        id: ClockId,
        source_config: SourceConfig,
    ) -> Self::NtpSourceController {
        T::add_source(self, id, source_config)
    }

    fn add_one_way_source(
        &mut self,
        id: ClockId,
        source_config: SourceConfig,
        measurement_noise_estimate: f64,
        period: Option<f64>,
    ) -> Self::OneWaySourceController {
        T::add_one_way_source(self, id, source_config, measurement_noise_estimate, period)
    }

    fn remove_source(&mut self, id: ClockId) {
        T::remove_source(self, id);
    }

    fn source_update(&mut self, id: ClockId, usable: bool) {
        T::source_update(self, id, usable);
    }

    fn source_message(
        &mut self,
        id: ClockId,
        message: Self::SourceMessage,
    ) -> StateUpdate<Self::ControllerMessage> {
        T::source_message(self, id, message)
    }

    fn time_update(&mut self) -> StateUpdate<Self::ControllerMessage> {
        T::time_update(self)
    }
}

pub trait SourceController: Sized + Send + 'static {
    type ControllerMessage: Debug + Clone + Send + 'static;
    type SourceMessage: Debug + Clone + Send + 'static;
    type MeasurementDelay: Debug + Copy + Clone;

    fn handle_message(&mut self, message: Self::ControllerMessage);

    fn handle_measurement(
        &mut self,
        measurement: Measurement<Self::MeasurementDelay>,
    ) -> Option<Self::SourceMessage>;

    fn desired_poll_interval(&self) -> PollInterval;

    fn observe(&self) -> ObservableSourceTimedata;
}

impl<T: InternalSourceController> SourceController for T {
    type ControllerMessage = T::ControllerMessage;
    type SourceMessage = T::SourceMessage;
    type MeasurementDelay = T::MeasurementDelay;

    fn handle_message(&mut self, message: Self::ControllerMessage) {
        T::handle_message(self, message);
    }

    fn handle_measurement(
        &mut self,
        measurement: Measurement<Self::MeasurementDelay>,
    ) -> Option<Self::SourceMessage> {
        T::handle_measurement(self, measurement.into())
    }

    fn desired_poll_interval(&self) -> PollInterval {
        T::desired_poll_interval(self)
    }

    fn observe(&self) -> ObservableSourceTimedata {
        T::observe(self)
    }
}
