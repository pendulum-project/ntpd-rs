use std::{fmt::Debug, time::Duration};

use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::{
    ClockId, NtpLeapIndicator, PollInterval,
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

#[derive(Debug, Copy, Clone)]
pub struct Measurement {
    pub sender_id: ClockId,
    pub receiver_id: ClockId,
    pub sender_ts: NtpTimestamp,
    pub receiver_ts: NtpTimestamp,

    pub stratum: u8,
    pub root_delay: NtpDuration,
    pub root_dispersion: NtpDuration,
    pub leap: NtpLeapIndicator,
    pub precision: i8,
}

pub trait TimeSyncController: Sized + Send + 'static {
    type Clock: NtpClock;
    type AlgorithmConfig: Debug + Copy + DeserializeOwned + Send;
    type ControllerMessage: Debug + Clone + Send + 'static;
    type SourceMessage: Debug + Clone + Send + 'static;
    type NtpSourceController: SourceController<
            ControllerMessage = Self::ControllerMessage,
            SourceMessage = Self::SourceMessage,
        >;
    type OneWaySourceController: SourceController<
            ControllerMessage = Self::ControllerMessage,
            SourceMessage = Self::SourceMessage,
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
    type NtpSourceController = TwoWaySourceControllerWrapper<T::NtpSourceController>;
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
        TwoWaySourceControllerWrapper {
            inner: T::add_source(self, id, source_config),
            last_outgoing_measurement: None,
        }
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

    fn handle_message(&mut self, message: Self::ControllerMessage);

    fn handle_measurement(&mut self, measurement: Measurement) -> Option<Self::SourceMessage>;

    fn desired_poll_interval(&self) -> PollInterval;

    fn observe(&self) -> ObservableSourceTimedata;
}

impl<T: InternalSourceController<MeasurementDelay = ()>> SourceController for T {
    type ControllerMessage = T::ControllerMessage;
    type SourceMessage = T::SourceMessage;

    fn handle_message(&mut self, message: Self::ControllerMessage) {
        T::handle_message(self, message);
    }

    fn handle_measurement(&mut self, measurement: Measurement) -> Option<Self::SourceMessage> {
        T::handle_measurement(
            self,
            InternalMeasurement {
                delay: (),
                offset: measurement.sender_ts - measurement.receiver_ts,
                localtime: measurement.receiver_ts,
                stratum: measurement.stratum,
                root_delay: measurement.root_delay,
                root_dispersion: measurement.root_dispersion,
                leap: measurement.leap,
                precision: measurement.precision,
            },
        )
    }

    fn desired_poll_interval(&self) -> PollInterval {
        T::desired_poll_interval(self)
    }

    fn observe(&self) -> ObservableSourceTimedata {
        T::observe(self)
    }
}

pub struct TwoWaySourceControllerWrapper<
    T: InternalSourceController<MeasurementDelay = NtpDuration>,
> {
    inner: T,
    last_outgoing_measurement: Option<Measurement>,
}

impl<T: InternalSourceController<MeasurementDelay = NtpDuration>> SourceController
    for TwoWaySourceControllerWrapper<T>
{
    type ControllerMessage = T::ControllerMessage;
    type SourceMessage = T::SourceMessage;

    fn handle_message(&mut self, message: Self::ControllerMessage) {
        self.inner.handle_message(message);
    }

    fn handle_measurement(&mut self, measurement: Measurement) -> Option<Self::SourceMessage> {
        if measurement.sender_id == ClockId::SYSTEM {
            // This is an outgoing measurement, store it for later
            self.last_outgoing_measurement = Some(measurement);
            None
        } else {
            // This is an incoming measurement, we need to have an outgoing one to compute the delay
            let last_outgoing = self.last_outgoing_measurement.take()?;
            self.inner.handle_measurement(InternalMeasurement {
                delay: (measurement.receiver_ts - last_outgoing.sender_ts)
                    - (measurement.sender_ts - last_outgoing.receiver_ts),
                offset: ((last_outgoing.receiver_ts - last_outgoing.sender_ts)
                    + (measurement.sender_ts - measurement.receiver_ts))
                    / 2,
                localtime: measurement.receiver_ts,
                stratum: measurement.stratum,
                root_delay: measurement.root_delay,
                root_dispersion: measurement.root_dispersion,
                leap: measurement.leap,
                precision: measurement.precision,
            })
        }
    }

    fn desired_poll_interval(&self) -> PollInterval {
        self.inner.desired_poll_interval()
    }

    fn observe(&self) -> ObservableSourceTimedata {
        self.inner.observe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestInternalSourceController {
        last_measurement: Option<InternalMeasurement<NtpDuration>>,
    }

    impl InternalSourceController for TestInternalSourceController {
        type ControllerMessage = ();
        type SourceMessage = ();
        type MeasurementDelay = NtpDuration;

        fn handle_message(&mut self, _message: Self::ControllerMessage) {
            unimplemented!()
        }

        fn handle_measurement(
            &mut self,
            measurement: InternalMeasurement<Self::MeasurementDelay>,
        ) -> Option<Self::SourceMessage> {
            self.last_measurement = Some(measurement);
            None
        }

        fn desired_poll_interval(&self) -> PollInterval {
            unimplemented!()
        }

        fn observe(&self) -> ObservableSourceTimedata {
            unimplemented!()
        }
    }

    #[test]
    fn test_measurements_from_packet() {
        let mut measurement_outgoing = Measurement {
            sender_id: ClockId::SYSTEM,
            receiver_id: ClockId(1),
            sender_ts: NtpTimestamp::from_fixed_int(0),
            receiver_ts: NtpTimestamp::from_fixed_int(1),
            stratum: 0,
            root_delay: NtpDuration::from_fixed_int(0),
            root_dispersion: NtpDuration::from_fixed_int(0),
            leap: NtpLeapIndicator::NoWarning,
            precision: 0,
        };
        let mut measurement_incoming = Measurement {
            sender_id: ClockId(1),
            receiver_id: ClockId::SYSTEM,
            sender_ts: NtpTimestamp::from_fixed_int(2),
            receiver_ts: NtpTimestamp::from_fixed_int(3),
            stratum: 0,
            root_delay: NtpDuration::from_fixed_int(0),
            root_dispersion: NtpDuration::from_fixed_int(0),
            leap: NtpLeapIndicator::NoWarning,
            precision: 0,
        };

        let mut controller = TwoWaySourceControllerWrapper {
            inner: TestInternalSourceController {
                last_measurement: None,
            },
            last_outgoing_measurement: None,
        };
        measurement_outgoing.sender_ts = NtpTimestamp::from_fixed_int(0);
        measurement_outgoing.receiver_ts = NtpTimestamp::from_fixed_int(1);
        measurement_incoming.sender_ts = NtpTimestamp::from_fixed_int(2);
        measurement_incoming.receiver_ts = NtpTimestamp::from_fixed_int(3);
        controller.handle_measurement(measurement_outgoing);
        controller.handle_measurement(measurement_incoming);
        assert_eq!(
            controller.inner.last_measurement.unwrap().offset,
            NtpDuration::from_fixed_int(0)
        );
        assert_eq!(
            controller.inner.last_measurement.unwrap().delay,
            NtpDuration::from_fixed_int(2)
        );

        let mut controller = TwoWaySourceControllerWrapper {
            inner: TestInternalSourceController {
                last_measurement: None,
            },
            last_outgoing_measurement: None,
        };
        measurement_outgoing.sender_ts = NtpTimestamp::from_fixed_int(0);
        measurement_outgoing.receiver_ts = NtpTimestamp::from_fixed_int(2);
        measurement_incoming.sender_ts = NtpTimestamp::from_fixed_int(3);
        measurement_incoming.receiver_ts = NtpTimestamp::from_fixed_int(3);
        controller.handle_measurement(measurement_outgoing);
        controller.handle_measurement(measurement_incoming);
        assert_eq!(
            controller.inner.last_measurement.unwrap().offset,
            NtpDuration::from_fixed_int(1)
        );
        assert_eq!(
            controller.inner.last_measurement.unwrap().delay,
            NtpDuration::from_fixed_int(2)
        );

        let mut controller = TwoWaySourceControllerWrapper {
            inner: TestInternalSourceController {
                last_measurement: None,
            },
            last_outgoing_measurement: None,
        };
        measurement_outgoing.sender_ts = NtpTimestamp::from_fixed_int(0);
        measurement_outgoing.receiver_ts = NtpTimestamp::from_fixed_int(0);
        measurement_incoming.sender_ts = NtpTimestamp::from_fixed_int(5);
        measurement_incoming.receiver_ts = NtpTimestamp::from_fixed_int(3);
        controller.handle_measurement(measurement_outgoing);
        controller.handle_measurement(measurement_incoming);
        assert_eq!(
            controller.inner.last_measurement.unwrap().offset,
            NtpDuration::from_fixed_int(1)
        );
        assert_eq!(
            controller.inner.last_measurement.unwrap().delay,
            NtpDuration::from_fixed_int(-2)
        );
    }
}
