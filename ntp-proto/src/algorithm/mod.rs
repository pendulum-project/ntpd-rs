use std::fmt::Debug;

use serde::{Deserialize, Serialize};

use crate::{
    ClockId, NtpLeapIndicator, PollInterval, PollIntervalLimits,
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

pub trait SourceController: Sized + Send + 'static {
    fn handle_measurement(&mut self, measurement: Measurement);

    fn set_usable(&mut self, usable: bool);

    fn desired_poll_interval(&self) -> PollInterval;

    fn observe(&self) -> ObservableSourceTimedata;
}

pub struct StatimeBaseWrapper<T> {
    inner: T,
    root_delay: statime_base::Duration,
    leap_status: Option<statime_base::LeapStatus>,
    usable: bool,
    poll_interval_limits: PollIntervalLimits,
}

impl<T> StatimeBaseWrapper<T> {
    pub fn new(inner: T, poll_interval_limits: PollIntervalLimits) -> Self {
        Self {
            inner,
            root_delay: statime_base::Duration::ZERO,
            leap_status: None,
            usable: false,
            poll_interval_limits,
        }
    }
}

impl<T: statime_base::Link + Send + 'static> SourceController for StatimeBaseWrapper<T> {
    fn handle_measurement(&mut self, measurement: Measurement) {
        let direction = if measurement.sender_id == ClockId::SYSTEM {
            statime_base::Direction::Forward
        } else {
            statime_base::Direction::Reverse
        };

        self.inner
            .measurement(
                statime_base::Measurement {
                    send_timestamp: measurement.sender_ts.into(),
                    recv_timestamp: measurement.receiver_ts.into(),
                    uncertainty: measurement.root_dispersion.into(),
                },
                direction,
            )
            .expect("Unable to handle measurement.");

        self.leap_status = match measurement.leap {
            NtpLeapIndicator::NoWarning => Some(statime_base::LeapStatus::None),
            NtpLeapIndicator::Leap61 => Some(statime_base::LeapStatus::Leap61),
            NtpLeapIndicator::Leap59 => Some(statime_base::LeapStatus::Leap59),
            NtpLeapIndicator::Unknown | NtpLeapIndicator::Unsynchronized => None,
        };

        self.root_delay = measurement.root_delay.into();

        self.inner
            .external_data_update(self.root_delay, self.leap_status, self.usable)
            .expect("Unable to update external link data.");
    }

    fn set_usable(&mut self, usable: bool) {
        self.usable = usable;

        self.inner
            .external_data_update(self.root_delay, self.leap_status, self.usable)
            .expect("Unable to update external link data.");
    }

    fn desired_poll_interval(&self) -> PollInterval {
        let target = self
            .inner
            .desired_poll_interval()
            .expect("Unable to get desired poll interval");
        // The cast here is intentionally saturating.
        let interval =
            PollInterval::from_byte((target.as_seconds().log2().floor() as i8).cast_unsigned());
        interval.clamp(self.poll_interval_limits.min, self.poll_interval_limits.max)
    }

    fn observe(&self) -> ObservableSourceTimedata {
        ObservableSourceTimedata {
            offset: NtpDuration::ZERO,
            uncertainty: NtpDuration::ZERO,
            delay: NtpDuration::ZERO,
            remote_delay: NtpDuration::ZERO,
            remote_uncertainty: NtpDuration::ZERO,
            last_update: NtpTimestamp::from_seconds_nanos_since_ntp_era(0, 0),
        }
    }
}
