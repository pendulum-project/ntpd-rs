use std::fmt::Debug;
use std::{collections::HashMap, marker::PhantomData};

use ntp_proto::{
    Measurement, NtpClock, NtpDuration, PollInterval, SourceController, TimeSyncController,
};
use serde::Deserialize;

use crate::daemon::spawn::SourceId;

#[derive(Debug, Clone)]
pub enum Measurements {
    Ntp(Measurement<NtpDuration>),
    Sock(Measurement<()>),
}

impl Measurements {
    fn get_offset(&self) -> NtpDuration {
        match self {
            Measurements::Ntp(measurement) => measurement.offset,
            Measurements::Sock(measurement) => measurement.offset,
        }
    }
}

pub trait WrapMeasurements<D: Debug + Copy + Clone> {
    fn wrap(&self) -> Measurements;
}

impl WrapMeasurements<NtpDuration> for Measurement<NtpDuration> {
    fn wrap(&self) -> Measurements {
        Measurements::Ntp(*self)
    }
}

impl WrapMeasurements<()> for Measurement<()> {
    fn wrap(&self) -> Measurements {
        Measurements::Sock(*self)
    }
}

pub(crate) struct SingleShotController<C> {
    pub(super) clock: C,
    sources: HashMap<SourceId, Measurements>,
    min_poll_interval: PollInterval,
    min_agreeing: usize,
}

#[derive(Debug, Copy, Clone, Deserialize)]
pub(crate) struct SingleShotControllerConfig {
    pub expected_sources: usize,
}

pub(crate) struct SingleShotSourceController<D: Debug + Copy + Clone> {
    delay_type: PhantomData<D>,
    min_poll_interval: PollInterval,
    done: bool,
}

#[derive(Debug, Copy, Clone)]
pub(crate) enum SingleShotControllerMessage {}

impl<C: NtpClock> SingleShotController<C> {
    const ASSUMED_UNCERTAINTY: NtpDuration = NtpDuration::from_exponent(-1);

    fn try_steer(&self) {
        if self.sources.len() < self.min_agreeing {
            return;
        }

        struct Event {
            offset: NtpDuration,
            count: isize,
        }
        let mut events: Vec<_> = self
            .sources
            .values()
            .flat_map(|m| {
                [
                    Event {
                        offset: m.get_offset() - Self::ASSUMED_UNCERTAINTY,
                        count: 1,
                    },
                    Event {
                        offset: m.get_offset() + Self::ASSUMED_UNCERTAINTY,
                        count: -1,
                    },
                ]
                .into_iter()
            })
            .collect();
        events.sort_by(|a, b| a.offset.cmp(&b.offset));

        let mut peak = 0;
        let mut peak_offset = events[0].offset;
        let mut cur = 0;
        for ev in events {
            cur += ev.count;
            if cur > peak {
                peak = cur;
                peak_offset = ev.offset;
            }
        }

        if peak as usize >= self.min_agreeing {
            let mut sum = 0.0;
            let mut count = 0;
            for source in self.sources.values() {
                if source.get_offset().abs_diff(peak_offset) < Self::ASSUMED_UNCERTAINTY {
                    count += 1;
                    sum += source.get_offset().to_seconds()
                }
            }

            let avg_offset = NtpDuration::from_seconds(sum / (count as f64));
            self.offer_clock_change(avg_offset);

            std::process::exit(0);
        }
    }
}

impl<C: NtpClock> TimeSyncController for SingleShotController<C> {
    type Clock = C;
    type SourceId = SourceId;
    type AlgorithmConfig = SingleShotControllerConfig;
    type ControllerMessage = SingleShotControllerMessage;
    type SourceMessage = Measurements;
    type NtpSourceController = SingleShotSourceController<NtpDuration>;
    type SockSourceController = SingleShotSourceController<()>;

    fn new(
        clock: Self::Clock,
        synchronization_config: ntp_proto::SynchronizationConfig,
        source_defaults_config: ntp_proto::SourceDefaultsConfig,
        algorithm_config: Self::AlgorithmConfig,
    ) -> Result<Self, <Self::Clock as ntp_proto::NtpClock>::Error> {
        Ok(SingleShotController {
            clock,
            sources: HashMap::new(),
            min_poll_interval: source_defaults_config.poll_interval_limits.min,
            min_agreeing: synchronization_config
                .minimum_agreeing_sources
                .max(algorithm_config.expected_sources / 2),
        })
    }

    fn take_control(&mut self) -> Result<(), <Self::Clock as ntp_proto::NtpClock>::Error> {
        //no need for actions
        Ok(())
    }

    fn add_source(&mut self, _id: Self::SourceId) -> Self::NtpSourceController {
        SingleShotSourceController::<NtpDuration> {
            delay_type: PhantomData,
            min_poll_interval: self.min_poll_interval,
            done: false,
        }
    }

    fn add_sock_source(
        &mut self,
        _id: Self::SourceId,
        _measurement_noise_estimate: f64,
    ) -> Self::SockSourceController {
        SingleShotSourceController::<()> {
            delay_type: PhantomData,
            min_poll_interval: self.min_poll_interval,
            done: false,
        }
    }

    fn remove_source(&mut self, id: Self::SourceId) {
        self.sources.remove(&id);
    }

    fn source_update(&mut self, id: Self::SourceId, usable: bool) {
        if !usable {
            self.sources.remove(&id);
        }
    }

    fn source_message(
        &mut self,
        id: Self::SourceId,
        message: Self::SourceMessage,
    ) -> ntp_proto::StateUpdate<Self::SourceId, Self::ControllerMessage> {
        self.sources.insert(id, message);
        // TODO, check and update time once we have sufficient sources
        self.try_steer();
        Default::default()
    }

    fn time_update(&mut self) -> ntp_proto::StateUpdate<Self::SourceId, Self::ControllerMessage> {
        // no need for action
        Default::default()
    }
}

impl<D: Debug + Copy + Clone + Send + 'static> SourceController for SingleShotSourceController<D>
where
    Measurement<D>: WrapMeasurements<D>,
{
    type ControllerMessage = SingleShotControllerMessage;
    type MeasurementDelay = D;
    type SourceMessage = Measurements;

    fn handle_message(&mut self, _message: Self::ControllerMessage) {
        //ignore
    }

    fn handle_measurement(
        &mut self,
        measurement: Measurement<Self::MeasurementDelay>,
    ) -> Option<Self::SourceMessage> {
        self.done = true;
        Some(measurement.wrap())
    }

    fn desired_poll_interval(&self) -> ntp_proto::PollInterval {
        if self.done {
            PollInterval::NEVER
        } else {
            self.min_poll_interval
        }
    }

    fn observe(&self) -> ntp_proto::ObservableSourceTimedata {
        ntp_proto::ObservableSourceTimedata::default()
    }
}
