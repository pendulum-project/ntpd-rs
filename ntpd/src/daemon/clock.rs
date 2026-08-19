use clock_steering::unix::UnixClock;
use ntp_proto::{NtpClock, NtpTimestamp};
use statime_base::{Clock, ClockError, Duration, LeapStatus};

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
    type Error = ClockError;

    fn now(&self) -> Result<ntp_proto::NtpTimestamp, Self::Error> {
        self.0.now().map(NtpTimestamp::from)
    }

    fn set_frequency(&self, freq: f64) -> Result<ntp_proto::NtpTimestamp, Self::Error> {
        self.0.set_frequency(freq).map(NtpTimestamp::from)
    }

    fn get_frequency(&self) -> Result<f64, Self::Error> {
        self.0.get_frequency()
    }

    fn step_clock(
        &self,
        offset: ntp_proto::NtpDuration,
    ) -> Result<ntp_proto::NtpTimestamp, Self::Error> {
        self.0
            .step_clock(Duration::from(offset))
            .map(NtpTimestamp::from)
    }

    fn disable_ntp_algorithm(&self) -> Result<(), Self::Error> {
        self.0.disable_kernel()
    }

    fn error_estimate_update(
        &self,
        est_error: ntp_proto::NtpDuration,
        max_error: ntp_proto::NtpDuration,
    ) -> Result<(), Self::Error> {
        self.0
            .error_estimate_update(est_error.into(), max_error.into())
    }

    fn status_update(&self, leap_status: ntp_proto::NtpLeapIndicator) -> Result<(), Self::Error> {
        match leap_status {
            ntp_proto::NtpLeapIndicator::NoWarning => {
                self.0.synchronization_update(true)?;
                self.0.leap_update(LeapStatus::None)
            }
            ntp_proto::NtpLeapIndicator::Leap61 => {
                self.0.synchronization_update(true)?;
                self.0.leap_update(LeapStatus::Leap61)
            }
            ntp_proto::NtpLeapIndicator::Leap59 => {
                self.0.synchronization_update(true)?;
                self.0.leap_update(LeapStatus::Leap59)
            }
            ntp_proto::NtpLeapIndicator::Unknown => self.0.synchronization_update(true),
            ntp_proto::NtpLeapIndicator::Unsynchronized => self.0.synchronization_update(false),
        }
    }
}
