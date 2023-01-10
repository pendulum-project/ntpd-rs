use crate::datastructures::common::TimeSource;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct TimePropertiesDS {
    pub current_utc_offset: i16,
    pub current_utc_offset_valid: bool,
    pub leap59: bool,
    pub leap61: bool,
    pub time_traceable: bool,
    pub frequency_traceable: bool,
    pub ptp_timescale: bool,
    pub time_source: TimeSource,
}

impl TimePropertiesDS {
    pub fn new(ptp_timescale: bool) -> Self {
        TimePropertiesDS {
            current_utc_offset: 0,
            current_utc_offset_valid: false,
            leap59: false,
            leap61: false,
            time_traceable: false,
            frequency_traceable: false,
            ptp_timescale,
            time_source: TimeSource::InternalOscillator,
        }
    }
}
