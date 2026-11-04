use std::sync::{Arc, RwLock};

use clock_steering::unix::UnixClock;
use statime_base::{Clock, ClockError, Duration, LeapStatus, TAI, UTC};

#[derive(Debug, Clone)]
pub struct NtpClockWrapper {
    inner: NtpClockWrapperInner,
    soft_state: Option<Arc<RwLock<SoftClockState>>>,
}

impl NtpClockWrapper {
    pub fn new_utc(inner: UnixClock<UTC>) -> Self {
        Self {
            inner: NtpClockWrapperInner::Utc(inner),
            soft_state: None,
        }
    }

    pub fn new_unsteered_utc(inner: UnixClock<UTC>) -> Result<Self, ClockError> {
        let inner = NtpClockWrapperInner::Utc(inner);
        let now = inner.now()?;
        Ok(Self {
            inner,
            soft_state: Some(Arc::new(RwLock::new(SoftClockState {
                offset: Duration::ZERO,
                frequency_offset: 0.0,
                base: now,
            }))),
        })
    }

    pub fn new_tai(inner: UnixClock<TAI>) -> Self {
        Self {
            inner: NtpClockWrapperInner::Tai(inner),
            soft_state: None,
        }
    }

    pub fn new_unsteered_tai(inner: UnixClock<TAI>) -> Result<Self, ClockError> {
        let inner = NtpClockWrapperInner::Tai(inner);
        let now = inner.now()?;
        Ok(Self {
            inner,
            soft_state: Some(Arc::new(RwLock::new(SoftClockState {
                offset: Duration::ZERO,
                frequency_offset: 0.0,
                base: now,
            }))),
        })
    }

    fn disable_ntp_algorithm(&self) -> Result<(), ClockError> {
        if self.soft_state.is_some() {
            // not used
            Ok(())
        } else {
            match self.inner {
                NtpClockWrapperInner::Utc(unix_clock) => unix_clock.disable_kernel(),
                NtpClockWrapperInner::Tai(unix_clock) => unix_clock.disable_kernel(),
            }
        }
    }
}

#[derive(Debug)]
struct SoftClockState {
    offset: Duration,
    frequency_offset: f64,
    base: statime_base::Timestamp<TAI>,
}

impl SoftClockState {
    fn convert_ts(&self, timestamp: statime_base::Timestamp<TAI>) -> statime_base::Timestamp<TAI> {
        let elapsed = timestamp - self.base;
        let drift = elapsed.as_seconds() * self.frequency_offset;
        timestamp + self.offset + Duration::from_f64_seconds(drift)
    }
}

pub(crate) fn utc_to_tai(ts: statime_base::Timestamp<UTC>) -> statime_base::Timestamp<TAI> {
    statime_base::Timestamp::UNIX_EPOCH
        + (ts - statime_base::Timestamp::UNIX_EPOCH)
        + Duration::from_seconds_nanos(37, 0)
}

#[derive(Debug, Clone)]
enum NtpClockWrapperInner {
    Utc(UnixClock<UTC>),
    Tai(UnixClock<TAI>),
}

impl Clock<TAI> for NtpClockWrapper {
    fn now(&self) -> Result<statime_base::Timestamp<TAI>, ClockError> {
        let ts = self.inner.now()?;
        if let Some(soft_state) = self.soft_state.as_ref() {
            let soft_state = soft_state.read().unwrap();
            Ok(soft_state.convert_ts(ts))
        } else {
            Ok(ts)
        }
    }

    fn set_frequency(&self, freq: f64) -> Result<statime_base::Timestamp<TAI>, ClockError> {
        if let Some(soft_state) = self.soft_state.as_ref() {
            let mut soft_state = soft_state.write().unwrap();
            let now = self.inner.now()?;
            let now_out = soft_state.convert_ts(now);
            soft_state.base = now;
            soft_state.offset = now_out - now;
            soft_state.frequency_offset = freq;
            Ok(now_out)
        } else {
            self.disable_ntp_algorithm()?;
            self.inner.set_frequency(freq)
        }
    }

    fn get_frequency(&self) -> Result<f64, ClockError> {
        if let Some(soft_state) = self.soft_state.as_ref() {
            let soft_state = soft_state.read().unwrap();
            Ok(soft_state.frequency_offset)
        } else {
            self.inner.get_frequency()
        }
    }

    fn max_frequency(&self) -> Result<f64, ClockError> {
        if self.soft_state.is_some() {
            Ok(10_000e-6)
        } else {
            self.inner.max_frequency()
        }
    }

    fn step_clock(&self, offset: Duration) -> Result<statime_base::Timestamp<TAI>, ClockError> {
        if let Some(soft_state) = self.soft_state.as_ref() {
            let mut soft_state = soft_state.write().unwrap();
            let now = self.inner.now()?;
            let now_out = soft_state.convert_ts(now);
            soft_state.base = now;
            soft_state.offset = (now_out - now) + offset;
            Ok(now_out)
        } else {
            self.disable_ntp_algorithm()?;
            self.inner.step_clock(offset)
        }
    }

    fn error_estimate_update(
        &self,
        est_error: Duration,
        max_error: Duration,
    ) -> Result<(), ClockError> {
        if self.soft_state.is_some() {
            // not used
            Ok(())
        } else {
            self.disable_ntp_algorithm()?;
            self.inner.error_estimate_update(est_error, max_error)
        }
    }

    fn leap_update(&self, leap_status: LeapStatus) -> Result<(), ClockError> {
        if self.soft_state.is_some() {
            // not used
            Ok(())
        } else {
            self.disable_ntp_algorithm()?;
            self.inner.leap_update(leap_status)
        }
    }

    fn synchronization_update(&self, synchronized: bool) -> Result<(), ClockError> {
        if self.soft_state.is_some() {
            // not used
            Ok(())
        } else {
            self.disable_ntp_algorithm()?;
            self.inner.synchronization_update(synchronized)
        }
    }
}

impl Clock<TAI> for NtpClockWrapperInner {
    fn now(&self) -> Result<statime_base::Timestamp<TAI>, ClockError> {
        match self {
            NtpClockWrapperInner::Utc(unix_clock) => unix_clock.now().map(utc_to_tai),
            NtpClockWrapperInner::Tai(unix_clock) => unix_clock.now(),
        }
    }

    fn set_frequency(&self, freq: f64) -> Result<statime_base::Timestamp<TAI>, ClockError> {
        match self {
            NtpClockWrapperInner::Utc(unix_clock) => unix_clock.set_frequency(freq).map(utc_to_tai),
            NtpClockWrapperInner::Tai(unix_clock) => unix_clock.set_frequency(freq),
        }
    }

    fn get_frequency(&self) -> Result<f64, ClockError> {
        match self {
            NtpClockWrapperInner::Utc(unix_clock) => unix_clock.get_frequency(),
            NtpClockWrapperInner::Tai(unix_clock) => unix_clock.get_frequency(),
        }
    }

    fn max_frequency(&self) -> Result<f64, ClockError> {
        match self {
            NtpClockWrapperInner::Utc(unix_clock) => unix_clock.max_frequency(),
            NtpClockWrapperInner::Tai(unix_clock) => unix_clock.max_frequency(),
        }
    }

    fn step_clock(&self, offset: Duration) -> Result<statime_base::Timestamp<TAI>, ClockError> {
        match self {
            NtpClockWrapperInner::Utc(unix_clock) => unix_clock.step_clock(offset).map(utc_to_tai),
            NtpClockWrapperInner::Tai(unix_clock) => unix_clock.step_clock(offset),
        }
    }

    fn error_estimate_update(
        &self,
        est_error: Duration,
        max_error: Duration,
    ) -> Result<(), ClockError> {
        match self {
            NtpClockWrapperInner::Utc(unix_clock) => {
                unix_clock.error_estimate_update(est_error, max_error)
            }
            NtpClockWrapperInner::Tai(unix_clock) => {
                unix_clock.error_estimate_update(est_error, max_error)
            }
        }
    }

    fn leap_update(&self, leap_status: LeapStatus) -> Result<(), ClockError> {
        match self {
            NtpClockWrapperInner::Utc(unix_clock) => unix_clock.leap_update(leap_status),
            NtpClockWrapperInner::Tai(unix_clock) => unix_clock.leap_update(leap_status),
        }
    }

    fn synchronization_update(&self, synchronized: bool) -> Result<(), ClockError> {
        match self {
            NtpClockWrapperInner::Utc(unix_clock) => {
                unix_clock.synchronization_update(synchronized)
            }
            NtpClockWrapperInner::Tai(unix_clock) => {
                unix_clock.synchronization_update(synchronized)
            }
        }
    }
}
