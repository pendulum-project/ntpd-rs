#![forbid(unsafe_code)]

use crate::unix::{current_time_timeval, Precision, UnixNtpClock, EMPTY_TIMEX};
use crate::Error;
use ntp_proto::{NtpClock, NtpDuration, NtpLeapIndicator, NtpTimestamp, PollInterval};

/// NTP Clock that uses the unix NTP KAPI clock functions to get/modify the
/// current time. Uses linux-specific functionality to reduce the number of syscalls
// Implementation note: this is intentionally a bare struct, the NTP Clock defined
// in the NTP KAPI is unique and no state is needed to interact with it.
#[derive(Debug, Default, Clone)]
pub struct LinuxNtpClock(());

impl LinuxNtpClock {
    pub fn new() -> Self {
        Self(())
    }
}

fn extract_current_time(timex: &libc::timex) -> NtpTimestamp {
    let precision = match timex.status & libc::STA_NANO {
        0 => Precision::Micro,
        _ => Precision::Nano,
    };

    // on linux, the `timex` struct has a `time` field. Other unix flavors don't have this field
    // and getting the time requires an additional `ntp_gettime` call.
    current_time_timeval(timex.time, precision)
}

impl NtpClock for LinuxNtpClock {
    type Error = Error;

    fn now(&self) -> Result<ntp_proto::NtpTimestamp, Error> {
        let mut ntp_kapi_timex = EMPTY_TIMEX;

        UnixNtpClock::realtime().adjtime(&mut ntp_kapi_timex)?;

        Ok(extract_current_time(&ntp_kapi_timex))
    }

    fn set_frequency(&self, freq: f64) -> Result<NtpTimestamp, Self::Error> {
        let mut ntp_kapi_timex = EMPTY_TIMEX;
        ntp_kapi_timex.modes = libc::MOD_FREQUENCY;
        // NTP Kapi expects frequency adjustment in units of 2^-16 ppm
        // but our input is in units of seconds drift per second, so convert.
        ntp_kapi_timex.freq = (freq * 65536e6) as libc::c_long;
        UnixNtpClock::realtime().adjtime(&mut ntp_kapi_timex)?;
        Ok(extract_current_time(&ntp_kapi_timex))
    }

    fn step_clock(&self, offset: ntp_proto::NtpDuration) -> Result<NtpTimestamp, Self::Error> {
        UnixNtpClock::realtime().step_clock(offset)
    }

    fn enable_ntp_algorithm(&self) -> Result<(), Self::Error> {
        UnixNtpClock::realtime().enable_ntp_algorithm()
    }

    fn disable_ntp_algorithm(&self) -> Result<(), Self::Error> {
        UnixNtpClock::realtime().disable_ntp_algorithm()
    }

    fn ntp_algorithm_update(
        &self,
        offset: NtpDuration,
        poll_interval: PollInterval,
    ) -> Result<(), Self::Error> {
        UnixNtpClock::realtime().ntp_algorithm_update(offset, poll_interval)
    }

    fn error_estimate_update(
        &self,
        est_error: NtpDuration,
        max_error: NtpDuration,
    ) -> Result<(), Self::Error> {
        UnixNtpClock::realtime().error_estimate_update(est_error, max_error)
    }

    fn status_update(&self, leap_status: NtpLeapIndicator) -> Result<(), Self::Error> {
        UnixNtpClock::realtime().status_update(leap_status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_time_now_does_not_crash() {
        let clock = LinuxNtpClock::new();
        assert_ne!(
            clock.now().unwrap(),
            NtpTimestamp::from_seconds_nanos_since_ntp_era(0, 0)
        );
    }
}
