//! Definitions and implementations of the abstract clock types

use crate::{
    datastructures::{common::ClockQuality, datasets::TimePropertiesDS},
    time::{Duration, Time},
};

/// Clock manipulation and querying interface
///
/// The clock trait is the primary way the PTP stack interfaces with the
/// system's clock. It's implementation should be provided by the user of the
/// Statime crate, and should provide information on and ways to manipulate the
/// system's clock. An implementation of this trait for linux is provided in the
/// statime-linux crate.
///
/// Note that the clock implementation is responsible for handling leap seconds.
/// On most operating systems, this will be provided for by the OS, but on some
/// platforms this may require extra logic.
pub trait Clock {
    type Error: core::fmt::Debug;

    /// Get the current time of the clock
    fn now(&self) -> Time;

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

/// Async timer trait for waiting an interval
///
/// The Timer trait is the primary way the ptp futures wait for time to pass.
/// The after future should provide waiting for multpile timers.
///
/// Note: the timer need not use a high precision time source. The only
/// requirement is that the underlying definition of a second is the same
/// between the [Clock] and timers.
pub trait Timer {
    /// Wait for a given amount of time
    async fn after(&self, duration: Duration);
}
