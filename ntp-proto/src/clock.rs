use crate::{
    packet::NtpLeapIndicator,
    time_types::{NtpDuration, NtpTimestamp},
};

/// Interface for a clock settable by the ntp implementation.
/// This needs to be a trait as a single system can have multiple clocks
/// which need different implementation for steering and/or now.
pub trait NtpClock: Clone + Send + 'static {
    type Error: std::error::Error + Send + Sync;

    // Get current time
    fn now(&self) -> Result<NtpTimestamp, Self::Error>;

    // Change the frequency of the clock, returning the time
    // at which the change was applied.
    fn set_frequency(&self, freq: f64) -> Result<NtpTimestamp, Self::Error>;

    // Get the frequency of the clock
    fn get_frequency(&self) -> Result<f64, Self::Error>;

    // Change the current time of the clock by offset. Returns
    // the time at which the change was applied.
    fn step_clock(&self, offset: NtpDuration) -> Result<NtpTimestamp, Self::Error>;

    // A clock can have a built in NTP clock discipline algorithm
    // that does more processing on the offsets it receives. This
    // functions disables that discipline.
    fn disable_ntp_algorithm(&self) -> Result<(), Self::Error>;

    // Provide the system with our current best estimates for
    // the statistical error of the clock (est_error), and
    // the maximum deviation due to frequency error and
    // distance to the root clock.
    fn error_estimate_update(
        &self,
        est_error: NtpDuration,
        max_error: NtpDuration,
    ) -> Result<(), Self::Error>;
    // Change the indicators for upcoming leap seconds and
    // the clocks synchronization status.
    fn status_update(&self, leap_status: NtpLeapIndicator) -> Result<(), Self::Error>;
}
