//! Definitions and implementations of the abstract clock types

use crate::{
    datastructures::{common::ClockQuality, datasets::TimePropertiesDS},
    time::{Duration, Instant},
};

/// Clock type for use in the PTP stack
pub trait Clock {
    type Error: core::fmt::Debug;

    /// Get the current time of the clock
    fn now(&self) -> Instant;

    /// Get the quality of the clock
    fn quality(&self) -> ClockQuality;

    /// Adjust the clock with the given time offset and frequency multiplier.
    /// The adjustment is based on the given time properties.
    ///
    /// The adjustment that is actually being done to the clock doesn't have to
    /// be exactly what is being given. The clock can (and should) do some
    /// filtering.
    // TODO: Discuss whether both the PTP instance and the clock itself should do
    // filtering?
    fn adjust(
        &mut self,
        time_offset: Duration,
        frequency_multiplier: f64,
        time_properties_ds: &TimePropertiesDS,
    ) -> Result<(), Self::Error>;
}

/// A timer let's you get the current time and wait for durations
pub trait Timer {
    /// Wait for the given amount of time
    async fn after(&self, duration: Duration);
}
