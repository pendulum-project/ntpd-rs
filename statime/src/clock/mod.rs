//! Definitions and implementations of the abstract clock types

use crate::{
    datastructures::common::ClockQuality,
    time::{Duration, Instant},
};

/// Clock type for use in the PTP stack
pub trait Clock {
    type E: std::fmt::Debug;
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
        time_properties: TimeProperties,
    ) -> Result<bool, Self::E>;
}

/// A watch can tell you the time and set an alarm.
///
/// How the alarm event is fed back into the PTP runtime is implementation defined.
pub trait Watch {
    type WatchId: std::fmt::Debug + Eq;

    /// Get the current time
    fn now(&self) -> Instant;
    /// Set an alarm. A previously set alarm will be overwritten
    fn set_alarm(&mut self, from_now: Duration);
    /// The id of the watch.
    ///
    /// Used by the alarm API to know which watch went off
    fn id(&self) -> Self::WatchId;
}

#[derive(Debug, Clone, Copy)]
pub enum TimeProperties {
    /// The time is synchronized as a UTC time
    PtpTime {
        /// The amount of seconds the time is away from UTC
        current_utc_offset: Option<u16>,
        /// Indicates that the last minute of this day will have 61 seconds
        leap_61: bool,
        /// Indicates that the last minute of this day will have 59 seconds
        leap_59: bool,
        /// Indicates that the time is traceable to the primary source.
        /// This may have an effect on how the time is filtered.
        time_traceable: bool,
        /// Indicates that the frequency is traceable to the primary source.
        /// This may have an effect on how the frequency is filtered.
        frequency_traceable: bool,
    },
    /// The time is synchronized with an arbitrary start point
    ArbitraryTime {
        /// Indicates that the time is traceable to the primary source.
        /// This may have an effect on how the time is filtered.
        time_traceable: bool,
        /// Indicates that the frequency is traceable to the primary source.
        /// This may have an effect on how the frequency is filtered.
        frequency_traceable: bool,
    },
}

impl TimeProperties {
    /// Returns `true` if the time properties is [`PtpTime`].
    ///
    /// [`PtpTime`]: TimeProperties::PtpTime
    pub fn is_ptp_time(&self) -> bool {
        matches!(self, Self::PtpTime { .. })
    }

    /// Returns `true` if the time properties is [`ArbitraryTime`].
    ///
    /// [`ArbitraryTime`]: TimeProperties::ArbitraryTime
    pub fn is_arbitrary_time(&self) -> bool {
        matches!(self, Self::ArbitraryTime { .. })
    }

    pub fn time_traceable(&self) -> bool {
        match self {
            TimeProperties::PtpTime { time_traceable, .. } => *time_traceable,
            TimeProperties::ArbitraryTime { time_traceable, .. } => *time_traceable,
        }
    }

    pub fn frequency_traceable(&self) -> bool {
        match self {
            TimeProperties::PtpTime {
                frequency_traceable,
                ..
            } => *frequency_traceable,
            TimeProperties::ArbitraryTime {
                frequency_traceable,
                ..
            } => *frequency_traceable,
        }
    }
}
