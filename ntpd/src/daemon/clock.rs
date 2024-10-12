use clock_steering::{unix::UnixClock, Clock, TimeOffset};
use ntp_proto::NtpClock;

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

        #[allow(clippy::cast_lossless)]
        self.0
            .step_clock(TimeOffset {
                seconds: seconds as _,
                nanos,
            })
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
            ntp_proto::NtpLeapIndicator::Unknown => clock_steering::LeapIndicator::Unknown,
        })
    }
}
