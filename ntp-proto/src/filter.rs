// An implementation of the NTP clock filter algorithm, as described by
//
//      https://datatracker.ietf.org/doc/html/rfc5905#page-37
//
// Specifically this is a rust implementation of the `clock_filter()` routine,
// described in the appendix
//
//      https://datatracker.ietf.org/doc/html/rfc5905#appendix-A.5.2

use crate::{NtpDuration, NtpTimestamp};

#[derive(Debug, Clone, Copy, PartialEq)]
struct FilterTuple {
    offset: NtpDuration,
    delay: NtpDuration,
    dispersion: NtpDuration,
    time: NtpTimestamp,
}

impl FilterTuple {
    fn dummy() -> Self {
        Self {
            offset: NtpDuration::default(),
            delay: NtpDuration::MAXDISP,
            dispersion: NtpDuration::MAXDISP,
            time: NtpTimestamp::default(),
        }
    }

    fn is_dummy(self) -> bool {
        self == Self::dummy()
    }
}
