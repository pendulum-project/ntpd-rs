use clock_steering::unix::UnixClock;
use statime_base::{Clock, ClockError, Duration, LeapStatus, TAI, UTC};

#[derive(Debug, Clone, Copy)]
pub struct NtpClockWrapper(NtpClockWrapperInner);

pub(crate) fn utc_to_tai(ts: statime_base::Timestamp<UTC>) -> statime_base::Timestamp<TAI> {
    statime_base::Timestamp::UNIX_EPOCH
        + (ts - statime_base::Timestamp::UNIX_EPOCH)
        + Duration::from_seconds_nanos(37, 0)
}

#[derive(Debug, Clone, Copy)]
enum NtpClockWrapperInner {
    Utc(UnixClock<UTC>),
    Tai(UnixClock<TAI>),
}

impl From<UnixClock<TAI>> for NtpClockWrapper {
    fn from(value: UnixClock<TAI>) -> Self {
        Self(NtpClockWrapperInner::Tai(value))
    }
}

impl From<UnixClock<UTC>> for NtpClockWrapper {
    fn from(value: UnixClock<UTC>) -> Self {
        Self(NtpClockWrapperInner::Utc(value))
    }
}

impl Default for NtpClockWrapper {
    fn default() -> Self {
        NtpClockWrapper(NtpClockWrapperInner::Utc(UnixClock::CLOCK_REALTIME))
    }
}

impl Clock<TAI> for NtpClockWrapper {
    fn now(&self) -> Result<statime_base::Timestamp<TAI>, ClockError> {
        match self.0 {
            NtpClockWrapperInner::Utc(unix_clock) => unix_clock.now().map(utc_to_tai),
            NtpClockWrapperInner::Tai(unix_clock) => unix_clock.now(),
        }
    }

    fn set_frequency(&self, freq: f64) -> Result<statime_base::Timestamp<TAI>, ClockError> {
        match self.0 {
            NtpClockWrapperInner::Utc(unix_clock) => unix_clock.set_frequency(freq).map(utc_to_tai),
            NtpClockWrapperInner::Tai(unix_clock) => unix_clock.set_frequency(freq),
        }
    }

    fn get_frequency(&self) -> Result<f64, ClockError> {
        match self.0 {
            NtpClockWrapperInner::Utc(unix_clock) => unix_clock.get_frequency(),
            NtpClockWrapperInner::Tai(unix_clock) => unix_clock.get_frequency(),
        }
    }

    fn max_frequency(&self) -> Result<f64, ClockError> {
        match self.0 {
            NtpClockWrapperInner::Utc(unix_clock) => unix_clock.max_frequency(),
            NtpClockWrapperInner::Tai(unix_clock) => unix_clock.max_frequency(),
        }
    }

    fn step_clock(&self, offset: Duration) -> Result<statime_base::Timestamp<TAI>, ClockError> {
        match self.0 {
            NtpClockWrapperInner::Utc(unix_clock) => unix_clock.step_clock(offset).map(utc_to_tai),
            NtpClockWrapperInner::Tai(unix_clock) => unix_clock.step_clock(offset),
        }
    }

    fn error_estimate_update(
        &self,
        est_error: Duration,
        max_error: Duration,
    ) -> Result<(), ClockError> {
        match self.0 {
            NtpClockWrapperInner::Utc(unix_clock) => {
                unix_clock.error_estimate_update(est_error, max_error)
            }
            NtpClockWrapperInner::Tai(unix_clock) => {
                unix_clock.error_estimate_update(est_error, max_error)
            }
        }
    }

    fn leap_update(&self, leap_status: LeapStatus) -> Result<(), ClockError> {
        match self.0 {
            NtpClockWrapperInner::Utc(unix_clock) => unix_clock.leap_update(leap_status),
            NtpClockWrapperInner::Tai(unix_clock) => unix_clock.leap_update(leap_status),
        }
    }

    fn synchronization_update(&self, synchronized: bool) -> Result<(), ClockError> {
        match self.0 {
            NtpClockWrapperInner::Utc(unix_clock) => {
                unix_clock.synchronization_update(synchronized)
            }
            NtpClockWrapperInner::Tai(unix_clock) => {
                unix_clock.synchronization_update(synchronized)
            }
        }
    }
}

impl NtpClockWrapper {
    pub(crate) fn disable_ntp_algorithm(self) -> Result<(), ClockError> {
        match self.0 {
            NtpClockWrapperInner::Utc(unix_clock) => unix_clock.disable_kernel(),
            NtpClockWrapperInner::Tai(unix_clock) => unix_clock.disable_kernel(),
        }
    }
}
