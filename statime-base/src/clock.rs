use crate::{Duration, TAI, Timestamp};

/// Interface for a controllable clock
/// This needs to be a trait as a single system can have multiple clocks
/// which need different implementation for steering and/or now.
pub trait Clock: Clone + Send + 'static {
    /// Error that can occur in operations on the clock.
    type Error: core::error::Error + Send + Sync;

    /// Get current time
    ///
    /// # Errors
    /// Should return an error if the clock is unable to provide a timestamp.
    fn now(&self) -> Result<Timestamp<TAI>, Self::Error>;

    /// Change the frequency of the clock, returning the time
    /// at which the change was applied.
    ///
    /// # Errors
    /// Should return an error if the clock is unable to be steered by the requested amount.
    fn set_frequency(&self, freq: f64) -> Result<Timestamp<TAI>, Self::Error>;

    /// Get the frequency of the clock
    ///
    /// # Errors
    /// Should return an error if the clock is unable to provide its current steering frequency.
    fn get_frequency(&self) -> Result<f64, Self::Error>;

    /// Maximum frequency offset the clock is capable of.
    ///
    /// # Errors
    /// Should return an error if the maximum frequency offset could not be determined.
    fn max_frequency(&self) -> Result<f64, Self::Error>;

    /// Change the current time of the clock by offset. Returns
    /// the time at which the change was applied.
    ///
    /// # Errors
    /// Should return an error if the clock cannot be stepped by the amount requested.
    fn step_clock(&self, offset: Duration) -> Result<Timestamp<TAI>, Self::Error>;

    /// Provide the system with our current best estimates for
    /// the statistical error of the clock (`est_error`), and
    /// the maximum deviation due to frequency error and
    /// distance to the root clock.
    ///
    /// # Errors
    /// Should return an error if the error estimate update cannot be applied to the clock.
    fn error_estimate_update(
        &self,
        est_error: Duration,
        max_error: Duration,
    ) -> Result<(), Self::Error>;

    /// Change the indicators for upcoming leap seconds and
    /// the clocks synchronization status. Application should happen at the end of the UTC month.
    ///
    /// # Errors
    /// Should return an error if the status update cannot be applied to the clock.
    fn status_update(&self, leap_status: LeapStatus) -> Result<(), Self::Error>;
}

/// Information on what the next leap second is going to be.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LeapStatus {
    /// There is no leap second at the end of the month.
    #[default]
    None,
    /// A second needs to be removed from the last minute of the month.
    Leap59,
    /// A second needs to be inserted into the last minute of the month.
    Leap61,
}
