//! Definitions and implementations of the abstract clock types

use crate::datastructures::datasets::TimePropertiesDS;
use crate::{
    datastructures::common::ClockQuality,
    time::{Duration, Instant},
};

/// Clock type for use in the PTP stack
pub trait Clock {
    type E: core::fmt::Debug;
    type W: Watch;

    /// Get the current time of the clock
    fn now(&self) -> Instant;

    /// Get the quality of the clock
    fn quality(&self) -> ClockQuality;

    /// Create a watch with which the time can be read and an alarm can be set
    fn get_watch(&mut self) -> Self::W;

    /// Adjust the clock with the given time offset and frequency multiplier.
    /// The adjustment is based on the given time properties.
    ///
    /// The adjustment that is actually being done to the clock doesn't have to be exactly what is being given.
    /// The clock can (and should) do some filtering.
    fn adjust(
        &mut self,
        time_offset: Duration,
        frequency_multiplier: f64,
        time_properties: TimePropertiesDS,
    ) -> Result<bool, Self::E>;
}

/// A watch can tell you the time and set an alarm.
///
/// How the alarm event is fed back into the PTP runtime is implementation defined.
pub trait Watch {
    type WatchId: core::fmt::Debug + Eq;

    /// Get the current time
    fn now(&self) -> Instant;
    /// Set an alarm. A previously set alarm will be overwritten
    fn set_alarm(&mut self, from_now: Duration);
    /// Clear existing alarm, if any exists
    fn clear(&mut self);
    /// The id of the watch.
    ///
    /// Used by the alarm API to know which watch went off
    fn id(&self) -> Self::WatchId;
}
