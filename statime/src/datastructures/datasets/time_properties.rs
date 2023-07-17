use crate::datastructures::common::{LeapIndicator, TimeSource};

/// A concrete implementation of the PTP Time Properties dataset (IEEE1588-2019
/// section 8.2.4
///
/// This dataset describes the timescale currently in use, as well as any
/// upcoming leap seconds on that timescale.
#[derive(Default, Copy, Clone, Debug, Eq, PartialEq)]
pub struct TimePropertiesDS {
    pub(crate) current_utc_offset: i16,
    pub(crate) current_utc_offset_valid: bool,
    pub(crate) leap_indicator: LeapIndicator,
    pub(crate) time_traceable: bool,
    pub(crate) frequency_traceable: bool,
    pub(crate) ptp_timescale: bool,
    pub(crate) time_source: TimeSource,
}

impl TimePropertiesDS {
    /// Create a Time Properties data set for the PTP timescale.
    ///
    /// This creates a dataset for the default PTP timescale, which is UTC
    /// seconds since the PTP epoch excluding leap seconds. The traceability
    /// properties indicate whether the current clock time and frequency can be
    /// traced back to an internationally recognized standard in the metrology
    /// sense of the word. When in doubt, just set these to false.
    pub fn new_ptp_time(
        current_utc_offset: i16,
        current_utc_offset_valid: bool,
        leap_indicator: LeapIndicator,
        time_traceable: bool,
        frequency_traceable: bool,
        time_source: TimeSource,
    ) -> Self {
        TimePropertiesDS {
            current_utc_offset,
            current_utc_offset_valid,
            leap_indicator,
            time_traceable,
            frequency_traceable,
            ptp_timescale: true,
            time_source,
        }
    }

    /// Create a Time Properties data set for an Arbitrary timescale
    ///
    /// The arbitrary timescale can be used when wanting to synchronize multiple
    /// computers using PTP to a timescale that is unrelated to UTC. The
    /// traceability properties indicate whether the current clock time and
    /// frequency can be traced back to an internationally recognized standard
    /// in the metrology sense of the word. When in doubt, just set these to
    /// false.
    pub fn new_arbitrary_time(
        time_traceable: bool,
        frequency_traceable: bool,
        time_source: TimeSource,
    ) -> Self {
        TimePropertiesDS {
            current_utc_offset: 0,
            current_utc_offset_valid: false,
            leap_indicator: LeapIndicator::NoLeap,
            time_traceable,
            frequency_traceable,
            ptp_timescale: false,
            time_source,
        }
    }

    /// Is the current timescale the ptp (utc-derived) timescale?
    pub fn is_ptp(&self) -> bool {
        self.ptp_timescale
    }

    pub fn leap_indicator(&self) -> LeapIndicator {
        self.leap_indicator
    }
}
