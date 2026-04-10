use std::{
    fmt::Debug,
    pin::Pin,
    sync::{Arc, Mutex, Weak},
    time::Duration,
};

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
pub struct InternalStateUpdate<ControllerMessage> {
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
impl<ControllerMessage> Default for InternalStateUpdate<ControllerMessage> {
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
        measurement_accuracy_estimate: f64,
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
    ) -> InternalStateUpdate<Self::ControllerMessage>;
    /// Non-message driven update (queued via next_update)
    fn time_update(&mut self) -> InternalStateUpdate<Self::ControllerMessage>;
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

    pub root_delay: NtpDuration,
    pub root_dispersion: NtpDuration,
    pub leap: NtpLeapIndicator,
    pub precision: i8,
}

pub trait TimeSyncController: Sized + Send + Sync + 'static {
    type Clock: NtpClock;
    type AlgorithmConfig: Debug + Copy + DeserializeOwned + Send;
    type NtpSourceController: SourceController;
    type OneWaySourceController: SourceController;

    /// Create a new clock controller controlling the given clock
    fn new(
        clock: Self::Clock,
        synchronization_config: SynchronizationConfig,
        algorithm_config: Self::AlgorithmConfig,
    ) -> Result<Self, <Self::Clock as NtpClock>::Error>;

    /// Take control of the clock (should not be done in new!)
    ///
    /// Should be callable multiple times, with subsequent calls not
    /// doing anything.
    fn take_control(&self) -> Result<(), <Self::Clock as NtpClock>::Error>;

    /// Create a new source with given identity
    fn add_source(&self, id: ClockId, source_config: SourceConfig) -> Self::NtpSourceController;
    /// Create a new one way source with given identity (used e.g. with GPS sock sources)
    fn add_one_way_source(
        &self,
        id: ClockId,
        source_config: SourceConfig,
        measurement_noise_estimate: f64,
        measurement_accuracy_estimate: f64,
        period: Option<f64>,
    ) -> Self::OneWaySourceController;
    /// Notify the controller that a previous source has gone
    fn remove_source(&self, id: ClockId);
    /// Current synchronization state
    fn synchronization_state(&self) -> (TimeSnapshot, Vec<ClockId>);
    /// Run the internal watchdog and messaging.
    fn run(&self) -> impl Future<Output = ()> + Send;
}

pub struct TimeSyncControllerWrapper<T: InternalTimeSyncController> {
    inner: Mutex<T>,
    #[expect(clippy::type_complexity)]
    messages_for_system: Mutex<
        Option<tokio::sync::mpsc::UnboundedReceiver<(ClockId, WrapperMessage<T::SourceMessage>)>>,
    >,
    messages_for_system_sender:
        tokio::sync::mpsc::UnboundedSender<(ClockId, WrapperMessage<T::SourceMessage>)>,
    oneway_sources: Mutex<Vec<Weak<Mutex<T::OneWaySourceController>>>>,
    twoway_sources: Mutex<Vec<Weak<Mutex<T::NtpSourceController>>>>,
    snapshot: Mutex<TimeSnapshot>,
    used_sources: Mutex<Vec<ClockId>>,
    has_taken_control: Mutex<bool>,
}

impl<T: InternalTimeSyncController> TimeSyncController for TimeSyncControllerWrapper<T> {
    type Clock = T::Clock;
    type AlgorithmConfig = T::AlgorithmConfig;
    type NtpSourceController = TwoWaySourceControllerWrapper<T::NtpSourceController>;
    type OneWaySourceController = OneWaySourceControllerWrapper<T::OneWaySourceController>;

    fn new(
        clock: Self::Clock,
        synchronization_config: SynchronizationConfig,
        algorithm_config: Self::AlgorithmConfig,
    ) -> Result<Self, <Self::Clock as NtpClock>::Error> {
        let inner = T::new(clock, synchronization_config, algorithm_config)?;
        let (messages_for_system_sender, messages_for_system) =
            tokio::sync::mpsc::unbounded_channel();
        Ok(Self {
            inner: Mutex::new(inner),
            messages_for_system: Mutex::new(Some(messages_for_system)),
            messages_for_system_sender,
            oneway_sources: Mutex::new(Vec::new()),
            twoway_sources: Mutex::new(Vec::new()),
            snapshot: Mutex::new(TimeSnapshot::default()),
            used_sources: Mutex::new(Vec::new()),
            has_taken_control: Mutex::new(false),
        })
    }

    fn take_control(&self) -> Result<(), <Self::Clock as NtpClock>::Error> {
        let mut has_taken_control = self.has_taken_control.lock().unwrap();
        if !*has_taken_control {
            self.inner.lock().unwrap().take_control()?;
            *has_taken_control = true;
        }
        Ok(())
    }

    fn add_source(&self, id: ClockId, source_config: SourceConfig) -> Self::NtpSourceController {
        let source_controller = self.inner.lock().unwrap().add_source(id, source_config);
        let wrapper = TwoWaySourceControllerWrapper {
            id,
            inner: Arc::new(Mutex::new(source_controller)),
            last_outgoing_measurement: None,
            messages_for_system: self.messages_for_system_sender.clone(),
        };
        self.twoway_sources
            .lock()
            .unwrap()
            .push(Arc::downgrade(&wrapper.inner));
        wrapper
    }

    fn add_one_way_source(
        &self,
        id: ClockId,
        source_config: SourceConfig,
        measurement_noise_estimate: f64,
        measurement_accuracy_estimate: f64,
        period: Option<f64>,
    ) -> Self::OneWaySourceController {
        let source_controller = self.inner.lock().unwrap().add_one_way_source(
            id,
            source_config,
            measurement_noise_estimate,
            measurement_accuracy_estimate,
            period,
        );
        let wrapper = OneWaySourceControllerWrapper {
            id,
            inner: Arc::new(Mutex::new(source_controller)),
            messages_for_system: self.messages_for_system_sender.clone(),
        };
        self.oneway_sources
            .lock()
            .unwrap()
            .push(Arc::downgrade(&wrapper.inner));
        wrapper
    }

    fn remove_source(&self, id: ClockId) {
        self.inner.lock().unwrap().remove_source(id);
    }

    fn synchronization_state(&self) -> (TimeSnapshot, Vec<ClockId>) {
        (
            *self.snapshot.lock().unwrap(),
            self.used_sources.lock().unwrap().clone(),
        )
    }

    async fn run(&self) {
        let mut messages_for_system = self.messages_for_system.lock().unwrap().take().unwrap();
        let mut sleeper = std::pin::pin!(SingleshotSleep::new_disabled());
        loop {
            tokio::select! {
                Some((clock_id, message)) = messages_for_system.recv() => {
                    match message {
                        WrapperMessage::SourceMessage(message) => {
                            let update = self.inner.lock().unwrap().source_message(clock_id, message);
                            if let Some(source_message) = update.source_message {
                                for source in self.oneway_sources.lock().unwrap().iter().filter_map(Weak::upgrade) {
                                    source.lock().unwrap().handle_message(source_message.clone());
                                }
                                for source in self.twoway_sources.lock().unwrap().iter().filter_map(Weak::upgrade) {
                                    source.lock().unwrap().handle_message(source_message.clone());
                                }
                            }
                            if let Some(time_snapshot) = update.time_snapshot {
                                *self.snapshot.lock().unwrap() = time_snapshot;
                            }
                            if let Some(used_sources) = update.used_sources {
                                *self.used_sources.lock().unwrap() = used_sources;
                            }
                            if let Some(next_update) = update.next_update {
                                sleeper.as_mut().reset(tokio::time::Instant::now() + next_update);
                            }
                        },
                        WrapperMessage::UsabilityChange(usable) => {
                            self.inner.lock().unwrap().source_update(clock_id, usable);
                        },
                    }
                },
                _ = sleeper.as_mut() => {
                    let update = self.inner.lock().unwrap().time_update();
                    if let Some(source_message) = update.source_message {
                        for source in self.oneway_sources.lock().unwrap().iter().filter_map(Weak::upgrade) {
                            source.lock().unwrap().handle_message(source_message.clone());
                        }
                        for source in self.twoway_sources.lock().unwrap().iter().filter_map(Weak::upgrade) {
                            source.lock().unwrap().handle_message(source_message.clone());
                        }
                    }
                    if let Some(time_snapshot) = update.time_snapshot {
                        *self.snapshot.lock().unwrap() = time_snapshot;
                    }
                    if let Some(used_sources) = update.used_sources {
                        *self.used_sources.lock().unwrap() = used_sources;
                    }
                    if let Some(next_update) = update.next_update {
                        sleeper.as_mut().reset(tokio::time::Instant::now() + next_update);
                    }
                },
            }
        }
    }
}

pub trait SourceController: Sized + Send + 'static {
    fn handle_measurement(&mut self, measurement: Measurement);

    fn set_usable(&mut self, usable: bool);

    fn desired_poll_interval(&self) -> PollInterval;

    fn observe(&self) -> ObservableSourceTimedata;
}

enum WrapperMessage<SourceMessage> {
    SourceMessage(SourceMessage),
    UsabilityChange(bool),
}

pub struct OneWaySourceControllerWrapper<T: InternalSourceController<MeasurementDelay = ()>> {
    id: ClockId,
    inner: Arc<Mutex<T>>,
    messages_for_system:
        tokio::sync::mpsc::UnboundedSender<(ClockId, WrapperMessage<T::SourceMessage>)>,
}

impl<T: InternalSourceController<MeasurementDelay = ()>> SourceController
    for OneWaySourceControllerWrapper<T>
{
    fn handle_measurement(&mut self, measurement: Measurement) {
        if let Some(message) = self
            .inner
            .lock()
            .unwrap()
            .handle_measurement(InternalMeasurement {
                delay: (),
                // Remote (which is the send timestamp) - local (which is the receive timestamp)
                offset: measurement.sender_ts - measurement.receiver_ts,
                localtime: measurement.receiver_ts,
                root_delay: measurement.root_delay,
                root_dispersion: measurement.root_dispersion,
                leap: measurement.leap,
                precision: measurement.precision,
            })
        {
            self.messages_for_system
                .send((self.id, WrapperMessage::SourceMessage(message)))
                .ok();
        }
    }

    fn set_usable(&mut self, usable: bool) {
        self.messages_for_system
            .send((self.id, WrapperMessage::UsabilityChange(usable)))
            .ok();
    }

    fn desired_poll_interval(&self) -> PollInterval {
        self.inner.lock().unwrap().desired_poll_interval()
    }

    fn observe(&self) -> ObservableSourceTimedata {
        self.inner.lock().unwrap().observe()
    }
}

pub struct TwoWaySourceControllerWrapper<
    T: InternalSourceController<MeasurementDelay = NtpDuration>,
> {
    id: ClockId,
    inner: Arc<Mutex<T>>,
    last_outgoing_measurement: Option<Measurement>,
    messages_for_system:
        tokio::sync::mpsc::UnboundedSender<(ClockId, WrapperMessage<T::SourceMessage>)>,
}

impl<T: InternalSourceController<MeasurementDelay = NtpDuration>> SourceController
    for TwoWaySourceControllerWrapper<T>
{
    fn handle_measurement(&mut self, measurement: Measurement) {
        if measurement.sender_id == ClockId::SYSTEM {
            // This is an outgoing measurement, store it for later
            self.last_outgoing_measurement = Some(measurement);
        } else {
            // This is an incoming measurement, we need to have an outgoing one to compute the delay
            let Some(last_outgoing) = self.last_outgoing_measurement.take() else {
                return;
            };
            if let Some(message) =
                self.inner
                    .lock()
                    .unwrap()
                    .handle_measurement(InternalMeasurement {
                        delay: (measurement.receiver_ts - last_outgoing.sender_ts)
                            - (measurement.sender_ts - last_outgoing.receiver_ts),
                        offset: ((last_outgoing.receiver_ts - last_outgoing.sender_ts)
                            + (measurement.sender_ts - measurement.receiver_ts))
                            / 2,
                        localtime: measurement.receiver_ts,
                        root_delay: measurement.root_delay,
                        root_dispersion: measurement.root_dispersion,
                        leap: measurement.leap,
                        precision: measurement.precision,
                    })
            {
                self.messages_for_system
                    .send((self.id, WrapperMessage::SourceMessage(message)))
                    .ok();
            }
        }
    }

    fn set_usable(&mut self, usable: bool) {
        self.messages_for_system
            .send((self.id, WrapperMessage::UsabilityChange(usable)))
            .ok();
    }

    fn desired_poll_interval(&self) -> PollInterval {
        self.inner.lock().unwrap().desired_poll_interval()
    }

    fn observe(&self) -> ObservableSourceTimedata {
        self.inner.lock().unwrap().observe()
    }
}

struct SingleshotSleep {
    enabled: bool,
    sleep: Pin<Box<tokio::time::Sleep>>,
}

impl SingleshotSleep {
    fn new_disabled() -> Self {
        SingleshotSleep {
            enabled: false,
            sleep: Box::pin(tokio::time::sleep_until(tokio::time::Instant::now())),
        }
    }
}

impl Future for SingleshotSleep {
    type Output = ();

    fn poll(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let this = self.get_mut();
        if !this.enabled {
            return std::task::Poll::Pending;
        }
        match this.sleep.as_mut().poll(cx) {
            std::task::Poll::Ready(v) => {
                this.enabled = false;
                std::task::Poll::Ready(v)
            }
            u @ std::task::Poll::Pending => u,
        }
    }
}

impl SingleshotSleep {
    fn reset(self: Pin<&mut Self>, deadline: tokio::time::Instant) {
        let this = self.get_mut();
        this.enabled = true;
        this.sleep.as_mut().reset(deadline);
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
    #[expect(clippy::too_many_lines)]
    fn test_measurements_from_packet() {
        let mut measurement_outgoing = Measurement {
            sender_id: ClockId::SYSTEM,
            receiver_id: ClockId(1),
            sender_ts: NtpTimestamp::from_fixed_int(0),
            receiver_ts: NtpTimestamp::from_fixed_int(1),
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
            root_delay: NtpDuration::from_fixed_int(0),
            root_dispersion: NtpDuration::from_fixed_int(0),
            leap: NtpLeapIndicator::NoWarning,
            precision: 0,
        };

        let mut controller = TwoWaySourceControllerWrapper {
            id: ClockId(1),
            inner: Arc::new(Mutex::new(TestInternalSourceController {
                last_measurement: None,
            })),
            last_outgoing_measurement: None,
            messages_for_system: tokio::sync::mpsc::unbounded_channel().0,
        };
        measurement_outgoing.sender_ts = NtpTimestamp::from_fixed_int(0);
        measurement_outgoing.receiver_ts = NtpTimestamp::from_fixed_int(1);
        measurement_incoming.sender_ts = NtpTimestamp::from_fixed_int(2);
        measurement_incoming.receiver_ts = NtpTimestamp::from_fixed_int(3);
        controller.handle_measurement(measurement_outgoing);
        controller.handle_measurement(measurement_incoming);
        assert_eq!(
            controller
                .inner
                .lock()
                .unwrap()
                .last_measurement
                .unwrap()
                .offset,
            NtpDuration::from_fixed_int(0)
        );
        assert_eq!(
            controller
                .inner
                .lock()
                .unwrap()
                .last_measurement
                .unwrap()
                .delay,
            NtpDuration::from_fixed_int(2)
        );

        let mut controller = TwoWaySourceControllerWrapper {
            id: ClockId(1),
            inner: Arc::new(Mutex::new(TestInternalSourceController {
                last_measurement: None,
            })),
            messages_for_system: tokio::sync::mpsc::unbounded_channel().0,
            last_outgoing_measurement: None,
        };
        measurement_outgoing.sender_ts = NtpTimestamp::from_fixed_int(0);
        measurement_outgoing.receiver_ts = NtpTimestamp::from_fixed_int(2);
        measurement_incoming.sender_ts = NtpTimestamp::from_fixed_int(3);
        measurement_incoming.receiver_ts = NtpTimestamp::from_fixed_int(3);
        controller.handle_measurement(measurement_outgoing);
        controller.handle_measurement(measurement_incoming);
        assert_eq!(
            controller
                .inner
                .lock()
                .unwrap()
                .last_measurement
                .unwrap()
                .offset,
            NtpDuration::from_fixed_int(1)
        );
        assert_eq!(
            controller
                .inner
                .lock()
                .unwrap()
                .last_measurement
                .unwrap()
                .delay,
            NtpDuration::from_fixed_int(2)
        );

        let mut controller = TwoWaySourceControllerWrapper {
            id: ClockId(1),
            inner: Arc::new(Mutex::new(TestInternalSourceController {
                last_measurement: None,
            })),
            messages_for_system: tokio::sync::mpsc::unbounded_channel().0,
            last_outgoing_measurement: None,
        };
        measurement_outgoing.sender_ts = NtpTimestamp::from_fixed_int(0);
        measurement_outgoing.receiver_ts = NtpTimestamp::from_fixed_int(0);
        measurement_incoming.sender_ts = NtpTimestamp::from_fixed_int(5);
        measurement_incoming.receiver_ts = NtpTimestamp::from_fixed_int(3);
        controller.handle_measurement(measurement_outgoing);
        controller.handle_measurement(measurement_incoming);
        assert_eq!(
            controller
                .inner
                .lock()
                .unwrap()
                .last_measurement
                .unwrap()
                .offset,
            NtpDuration::from_fixed_int(1)
        );
        assert_eq!(
            controller
                .inner
                .lock()
                .unwrap()
                .last_measurement
                .unwrap()
                .delay,
            NtpDuration::from_fixed_int(-2)
        );
    }
}
