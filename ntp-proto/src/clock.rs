use crate::{packet::NtpLeapIndicator, time_types::PollInterval, NtpDuration, NtpTimestamp};

/// Interface for a clock settable by the ntp implementation.
/// This needs to be a trait as a single system can have multiple clocks
/// which need different implementation for steering and/or now.
pub trait NtpClock: Clone + Send + 'static {
    type Error: std::error::Error;

    fn now(&self) -> Result<NtpTimestamp, Self::Error>;

    fn set_freq(&self, freq: f64) -> Result<(), Self::Error>;
    fn step_clock(&self, offset: NtpDuration) -> Result<(), Self::Error>;
    fn update_clock(
        &self,
        offset: NtpDuration,
        est_error: NtpDuration,
        max_error: NtpDuration,
        poll_interval: PollInterval,
        leap_status: NtpLeapIndicator,
    ) -> Result<(), Self::Error>;
}
