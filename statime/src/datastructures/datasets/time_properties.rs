use crate::datastructures::common::TimeSource;

#[derive(Default, Copy, Clone, Debug, Eq, PartialEq)]
pub struct TimePropertiesDS {
    pub(crate) current_utc_offset: i16,
    pub(crate) current_utc_offset_valid: bool,
    pub(crate) leap59: bool,
    pub(crate) leap61: bool,
    pub(crate) time_traceable: bool,
    pub(crate) frequency_traceable: bool,
    pub(crate) ptp_timescale: bool,
    pub(crate) time_source: TimeSource,
}

impl TimePropertiesDS {
    pub fn new_ptp_time(
        current_utc_offset: i16,
        current_utc_offset_valid: bool,
        leap59: bool,
        leap61: bool,
        time_traceable: bool,
        frequency_traceable: bool,
        time_source: TimeSource,
    ) -> Self {
        TimePropertiesDS {
            current_utc_offset,
            current_utc_offset_valid,
            leap59,
            leap61,
            time_traceable,
            frequency_traceable,
            ptp_timescale: true,
            time_source,
        }
    }

    pub fn new_arbitrary_time(
        time_traceable: bool,
        frequency_traceable: bool,
        time_source: TimeSource,
    ) -> Self {
        TimePropertiesDS {
            current_utc_offset: 0,
            current_utc_offset_valid: false,
            leap59: false,
            leap61: false,
            time_traceable,
            frequency_traceable,
            ptp_timescale: false,
            time_source,
        }
    }

    pub fn is_ptp(&self) -> bool {
        self.ptp_timescale
    }

    pub fn leap59(&self) -> bool {
        self.leap59
    }

    pub fn leap61(&self) -> bool {
        self.leap61
    }
}
