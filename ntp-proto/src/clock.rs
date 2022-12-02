use crate::{packet::NtpLeapIndicator, time_types::PollInterval, NtpDuration, NtpTimestamp};

/// Interface for a clock settable by the ntp implementation.
/// This needs to be a trait as a single system can have multiple clocks
/// which need different implementation for steering and/or now.
///
/// Note: There are two main update functions. These are both needed since
/// depending on which timekeeping algorithm is used, one may want to use
/// or ignore the fact that the kernel can do some parts of the clock
/// disciplining.
pub trait NtpClock: Clone + Send + 'static {
    type Error: std::error::Error;

    fn now(&self) -> Result<NtpTimestamp, Self::Error>;

    fn set_freq(&self, freq: f64) -> Result<(), Self::Error>;
    fn step_clock(&self, offset: NtpDuration) -> Result<(), Self::Error>;
    // Update using the NTP discipline
    fn update_clock(
        &self,
        offset: NtpDuration,
        est_error: NtpDuration,
        max_error: NtpDuration,
        poll_interval: PollInterval,
        leap_status: NtpLeapIndicator,
    ) -> Result<(), Self::Error>;
    // Update with NTP discipline disabled
    fn bare_update(
        &self,
        offset: NtpDuration,
        est_error: NtpDuration,
        max_error: NtpDuration,
        leap_status: NtpLeapIndicator,
    ) -> Result<(), Self::Error>;
}
