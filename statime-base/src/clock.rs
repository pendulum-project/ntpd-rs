use crate::{Duration, TAI, Timestamp};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Errors than can occur when interacting with a clock
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClockError {
    /// Insufficient permissions to perform the requested operation
    PermissionDenied,
    /// The underlying clock device is no longer available
    NoDevice,
    /// The requested operation is not supported by the clock or OS
    NotSupported,
    /// One of the provided values is invalid
    InvalidValue,
    /// An unknown error occured when interacting with the clock
    Unknown,
}

/// Interface for a controllable clock
/// This needs to be a trait as a single system can have multiple clocks
/// which need different implementation for steering and/or now.
pub trait Clock: Clone + Send + 'static {
    /// Get current time
    ///
    /// # Errors
    /// Should return an error if the clock is unable to provide a timestamp.
    fn now(&self) -> Result<Timestamp<TAI>, ClockError>;

    /// Change the frequency of the clock, returning the time
    /// at which the change was applied.
    ///
    /// # Errors
    /// Should return an error if the clock is unable to be steered by the requested amount.
    fn set_frequency(&self, freq: f64) -> Result<Timestamp<TAI>, ClockError>;

    /// Get the frequency of the clock
    ///
    /// # Errors
    /// Should return an error if the clock is unable to provide its current steering frequency.
    fn get_frequency(&self) -> Result<f64, ClockError>;

    /// Maximum frequency offset the clock is capable of.
    ///
    /// # Errors
    /// Should return an error if the maximum frequency offset could not be determined.
    fn max_frequency(&self) -> Result<f64, ClockError>;

    /// Change the current time of the clock by offset. Returns
    /// the time at which the change was applied.
    ///
    /// # Errors
    /// Should return an error if the clock cannot be stepped by the amount requested.
    fn step_clock(&self, offset: Duration) -> Result<Timestamp<TAI>, ClockError>;

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
    ) -> Result<(), ClockError>;

    /// Change the indicators for upcoming leap seconds. Application should happen at the end of the UTC month.
    ///
    /// # Errors
    /// Should return an error if the status update cannot be applied to the clock.
    fn leap_update(&self, leap_status: LeapStatus) -> Result<(), ClockError>;

    /// Change the synchronization indicator.
    ///
    /// # Errors
    /// should return an error if the synchronization indicator cannot be updated
    fn synchronization_update(&self, synchronized: bool) -> Result<(), ClockError>;
}

/// Information on what the next leap second is going to be.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum LeapStatus {
    /// There is no leap second at the end of the month.
    #[default]
    None,
    /// A second needs to be removed from the last minute of the month.
    Leap59,
    /// A second needs to be inserted into the last minute of the month.
    Leap61,
}
