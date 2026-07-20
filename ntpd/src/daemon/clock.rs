use clock_steering::{Clock, TimeOffset, unix::UnixClock};
use ntp_proto::NtpClock;
use ntp_proto::{NtpDuration, NtpTimestamp};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use super::util::convert_clock_timestamp;

#[derive(Debug, Clone, Copy)]
pub struct NtpClockWrapper(UnixClock);

impl NtpClockWrapper {
    pub fn new(clock: UnixClock) -> Self {
        NtpClockWrapper(clock)
    }
}

impl Default for NtpClockWrapper {
    fn default() -> Self {
        NtpClockWrapper(UnixClock::CLOCK_REALTIME)
    }
}

impl NtpClock for NtpClockWrapper {
    type Error = <UnixClock as Clock>::Error;

    fn now(&self) -> Result<ntp_proto::NtpTimestamp, Self::Error> {
        self.0.now().map(convert_clock_timestamp)
    }

    fn set_frequency(&self, freq: f64) -> Result<ntp_proto::NtpTimestamp, Self::Error> {
        self.0
            .set_frequency(freq * 1e6)
            .map(convert_clock_timestamp)
    }

    fn get_frequency(&self) -> Result<f64, Self::Error> {
        self.0.get_frequency().map(|v| v * 1e-6)
    }

    fn step_clock(
        &self,
        offset: ntp_proto::NtpDuration,
    ) -> Result<ntp_proto::NtpTimestamp, Self::Error> {
        let (seconds, nanos) = offset.as_seconds_nanos();
        #[allow(clippy::useless_conversion)]
        let seconds = seconds.into();
        self.0
            .step_clock(TimeOffset { seconds, nanos })
            .map(convert_clock_timestamp)
    }

    fn disable_ntp_algorithm(&self) -> Result<(), Self::Error> {
        self.0.disable_kernel_ntp_algorithm()
    }

    fn error_estimate_update(
        &self,
        est_error: ntp_proto::NtpDuration,
        max_error: ntp_proto::NtpDuration,
    ) -> Result<(), Self::Error> {
        self.0.error_estimate_update(
            core::time::Duration::from_secs_f64(est_error.to_seconds()),
            core::time::Duration::from_secs_f64(max_error.to_seconds()),
        )
    }

    fn status_update(&self, leap_status: ntp_proto::NtpLeapIndicator) -> Result<(), Self::Error> {
        self.0.set_leap_seconds(match leap_status {
            ntp_proto::NtpLeapIndicator::NoWarning => clock_steering::LeapIndicator::NoWarning,
            ntp_proto::NtpLeapIndicator::Leap61 => clock_steering::LeapIndicator::Leap61,
            ntp_proto::NtpLeapIndicator::Leap59 => clock_steering::LeapIndicator::Leap59,
            ntp_proto::NtpLeapIndicator::Unknown | ntp_proto::NtpLeapIndicator::Unsynchronized => {
                clock_steering::LeapIndicator::Unknown
            }
        })
    }
}

/// Trait for clocks that can convert a system timestamp to "true" time.
/// For regular clocks this is a no-op; for soft-clock mode it adds the
/// tracked offset.
pub trait TrueTimeClock: NtpClock {
    fn to_true_time(&self, system_time: NtpTimestamp) -> NtpTimestamp;
}

impl TrueTimeClock for NtpClockWrapper {
    fn to_true_time(&self, system_time: NtpTimestamp) -> NtpTimestamp {
        system_time
    }
}

/// Clock wrapper that optionally tracks offset without steering the OS.
/// When `update_system_clock` is false, all steering calls become no-ops
/// and the offset is tracked internally. `now()` always returns system
/// time (needed by the Kalman filter and sources); use `to_true_time()`
/// to convert a system timestamp to the estimated true time.
#[derive(Clone)]
pub struct SoftClock<C: NtpClock + Clone> {
    inner: C,
    enabled: Arc<AtomicBool>,
    state: Arc<Mutex<SoftClockState>>,
}

#[derive(Clone, Copy, Debug)]
struct SoftClockState {
    offset: NtpDuration,
    frequency_ppm: f64,
    last_update: NtpTimestamp,
}

impl<C: NtpClock + Clone> SoftClock<C> {
    pub fn new(inner: C, update_system_clock: bool) -> Self {
        Self {
            inner,
            enabled: Arc::new(AtomicBool::new(update_system_clock)),
            state: Arc::new(Mutex::new(SoftClockState {
                offset: NtpDuration::ZERO,
                frequency_ppm: 0.0,
                last_update: NtpTimestamp::default(),
            })),
        }
    }

    fn now_true_from_system(&self, sys_ts: NtpTimestamp) -> NtpTimestamp {
        let state = self.state.lock().unwrap();
        let elapsed = sys_ts - state.last_update;
        let elapsed_secs = duration_to_seconds(elapsed);
        let drift = NtpDuration::from_seconds(elapsed_secs * state.frequency_ppm * 1e-6);
        sys_ts + state.offset + drift
    }
}

impl<C: NtpClock + Clone> NtpClock for SoftClock<C> {
    type Error = C::Error;

    /// Always returns system time. The Kalman filter and source tasks
    /// need system time for consistent offset calculations.
    fn now(&self) -> Result<NtpTimestamp, Self::Error> {
        self.inner.now()
    }

    fn set_frequency(&self, freq: f64) -> Result<NtpTimestamp, Self::Error> {
        if self.enabled.load(Ordering::Relaxed) {
            self.inner.set_frequency(freq)
        } else {
            let mut state = self.state.lock().unwrap();
            state.frequency_ppm = freq;
            state.last_update = self.inner.now()?;
            Ok(state.last_update)
        }
    }

    fn get_frequency(&self) -> Result<f64, Self::Error> {
        if self.enabled.load(Ordering::Relaxed) {
            self.inner.get_frequency()
        } else {
            Ok(self.state.lock().unwrap().frequency_ppm)
        }
    }

    fn step_clock(&self, offset: NtpDuration) -> Result<NtpTimestamp, Self::Error> {
        if self.enabled.load(Ordering::Relaxed) {
            self.inner.step_clock(offset)
        } else {
            let mut state = self.state.lock().unwrap();
            state.offset = offset;
            state.last_update = self.inner.now()?;
            Ok(state.last_update)
        }
    }

    fn disable_ntp_algorithm(&self) -> Result<(), Self::Error> {
        if self.enabled.load(Ordering::Relaxed) {
            self.inner.disable_ntp_algorithm()
        } else {
            Ok(())
        }
    }

    fn error_estimate_update(
        &self,
        _est_error: NtpDuration,
        _max_error: NtpDuration,
    ) -> Result<(), Self::Error> {
        if self.enabled.load(Ordering::Relaxed) {
            self.inner.error_estimate_update(_est_error, _max_error)
        } else {
            Ok(())
        }
    }

    fn status_update(&self, leap_status: ntp_proto::NtpLeapIndicator) -> Result<(), Self::Error> {
        if self.enabled.load(Ordering::Relaxed) {
            self.inner.status_update(leap_status)
        } else {
            Ok(())
        }
    }
}

impl<C: NtpClock + Clone> TrueTimeClock for SoftClock<C> {
    fn to_true_time(&self, system_time: NtpTimestamp) -> NtpTimestamp {
        if self.enabled.load(Ordering::Relaxed) {
            system_time
        } else {
            self.now_true_from_system(system_time)
        }
    }
}

fn duration_to_seconds(d: NtpDuration) -> f64 {
    let (secs, nanos) = d.as_seconds_nanos();
    secs as f64 + nanos as f64 / 1_000_000_000.0
}
