use crate::{packet::NtpLeapIndicator, time_types::PollInterval, NtpDuration, NtpTimestamp};

/// Interface for a clock settable by the ntp implementation.
/// This needs to be a trait as a single system can have multiple clocks
/// which need different implementation for steering and/or now.
pub trait NtpClock: Clone + Send + 'static {
    type Error: std::error::Error;

    fn now(&self) -> Result<NtpTimestamp, Self::Error>;

    fn set_frequency(&self, freq: f64) -> Result<NtpTimestamp, Self::Error>;
    fn step_clock(&self, offset: NtpDuration) -> Result<NtpTimestamp, Self::Error>;

    fn disable_ntp_algorithm(&self) -> Result<(), Self::Error>;
    fn enable_ntp_algorithm(&self) -> Result<(), Self::Error>;
    fn ntp_algorithm_update(
        &self,
        offset: NtpDuration,
        poll_interval: PollInterval,
    ) -> Result<(), Self::Error>;

    fn error_estimate_update(
        &self,
        est_error: NtpDuration,
        max_error: NtpDuration,
    ) -> Result<(), Self::Error>;
    fn status_update(&self, leap_status: NtpLeapIndicator) -> Result<(), Self::Error>;
}
