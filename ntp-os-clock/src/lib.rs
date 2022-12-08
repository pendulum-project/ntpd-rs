// Note on unsafe usage.
//
// This module uses unsafe code to interact with the system calls that
// are used to set/get the current behaviour and time of the clock. It
// is constructed in such a way that use of the public functions is
// safe regardless of given arguments.

use ntp_proto::{NtpClock, NtpDuration, NtpLeapIndicator, NtpTimestamp, PollInterval};
use thiserror::Error as ThisError;

#[derive(Debug, Copy, Clone, ThisError)]
pub enum Error {
    #[error("Insufficient permissions to interact with the clock.")]
    NoPermission,
    #[error("Invalid operation requested")]
    Invalid,
    #[error("Clock device has gone away")]
    NoDev,
    #[error("Clock operation requested is not supported by operating system.")]
    NotSupported,
}

// Unix uses an epoch located at 1/1/1970-00:00h (UTC) and NTP uses 1/1/1900-00:00h.
// This leads to an offset equivalent to 70 years in seconds
// there are 17 leap years between the two dates so the offset is
const EPOCH_OFFSET: u32 = (70 * 365 + 17) * 86400;

// Libc has no good other way of obtaining this, so let's at least make our functions
// more readable.
const EMPTY_TIMEX: libc::timex = libc::timex {
    modes: 0,
    offset: 0,
    freq: 0,
    maxerror: 0,
    esterror: 0,
    status: 0,
    constant: 0,
    precision: 0,
    tolerance: 0,
    time: libc::timeval {
        tv_sec: 0,
        tv_usec: 0,
    },
    tick: 0,
    ppsfreq: 0,
    jitter: 0,
    shift: 0,
    stabil: 0,
    jitcnt: 0,
    calcnt: 0,
    errcnt: 0,
    stbcnt: 0,
    tai: 0,
    __unused1: 0,
    __unused2: 0,
    __unused3: 0,
    __unused4: 0,
    __unused5: 0,
    __unused6: 0,
    __unused7: 0,
    __unused8: 0,
    __unused9: 0,
    __unused10: 0,
    __unused11: 0,
};

fn adjtime(timex: &mut libc::timex) -> Result<(), Error> {
    // We don't care about the time status, so the non-error
    // information in the return value of ntp_adjtime can be ignored.
    // The ntp_adjtime call is safe because the reference always
    // points to a valid libc::timex.
    if unsafe { libc::ntp_adjtime(timex as *mut _) } == -1 {
        Err(convert_errno())
    } else {
        Ok(())
    }
}

/// NTP Clock that uses the unix NTP KAPI clock functions to get/modify the
/// current time.
// Implementation note: this is intentionally a bare struct, the NTP Clock defined
// in the NTP KAPI is unique and no state is needed to interact with it.
#[derive(Debug, Default, Clone)]
pub struct UnixNtpClock(());

impl UnixNtpClock {
    pub fn new() -> Self {
        Self(())
    }
}

// Convert those error numbers that can occur for the ntp_gettime and ntp_adjtimex calls
fn convert_errno() -> Error {
    match unsafe { *libc::__errno_location() } {
        libc::EINVAL => Error::Invalid,
        // The documentation is a bit unclear if this can happen with
        // non-dynamic clocks like the ntp kapi clock, however lets
        // deal with it just in case.
        libc::ENODEV => Error::NoDev,
        libc::EOPNOTSUPP => Error::NotSupported,
        libc::EPERM => Error::NoPermission,
        // No other errors should occur (EFAULT is not possible as we always
        // pass in a proper buffer)
        _ => unreachable!(),
    }
}

fn duration_in_nanos(duration: NtpDuration) -> libc::c_long {
    let (secs, nanos) = duration.as_seconds_nanos();
    (secs as libc::c_long) * 1_000_000_000 + (nanos as libc::c_long)
}

fn extract_current_time(timex: &libc::timex) -> NtpTimestamp {
    // Negative eras are completely valid, so any wrapping is
    // perfectly reasonable here.
    NtpTimestamp::from_seconds_nanos_since_ntp_era(
        (timex.time.tv_sec as u32).wrapping_add(EPOCH_OFFSET),
        if timex.status & libc::STA_NANO != 0 {
            // We have nanosecond precision. use it
            timex.time.tv_usec as u32
        } else {
            (timex.time.tv_usec as u32) * 1000
        },
    )
}

impl NtpClock for UnixNtpClock {
    type Error = Error;
    fn now(&self) -> Result<ntp_proto::NtpTimestamp, Error> {
        let mut ntp_kapi_timex = EMPTY_TIMEX;

        adjtime(&mut ntp_kapi_timex)?;

        Ok(extract_current_time(&ntp_kapi_timex))
    }

    fn set_frequency(&self, freq: f64) -> Result<NtpTimestamp, Self::Error> {
        let mut ntp_kapi_timex = EMPTY_TIMEX;
        ntp_kapi_timex.modes = libc::MOD_FREQUENCY;
        // NTP Kapi expects frequency adjustment in units of 2^-16 ppm
        // but our input is in units of seconds drift per second, so convert.
        ntp_kapi_timex.freq = (freq * 65536e6) as libc::c_long;
        adjtime(&mut ntp_kapi_timex)?;
        Ok(extract_current_time(&ntp_kapi_timex))
    }

    fn step_clock(&self, offset: ntp_proto::NtpDuration) -> Result<NtpTimestamp, Self::Error> {
        let mut timex = EMPTY_TIMEX;
        timex.modes = libc::ADJ_SETOFFSET | libc::MOD_NANO;
        let (secs, nanos) = offset.as_seconds_nanos();
        timex.time.tv_sec = secs as libc::time_t;
        timex.time.tv_usec = nanos as libc::suseconds_t;
        adjtime(&mut timex)?;
        Ok(extract_current_time(&timex))
    }

    fn enable_ntp_algorithm(&self) -> Result<(), Self::Error> {
        let mut timex = EMPTY_TIMEX;
        adjtime(&mut timex)?;
        timex.modes = libc::MOD_STATUS;
        timex.status |= libc::STA_PLL;
        timex.status &= !libc::STA_FLL & !libc::STA_PPSTIME & !libc::STA_PPSFREQ;
        adjtime(&mut timex)
    }

    fn disable_ntp_algorithm(&self) -> Result<(), Self::Error> {
        let mut timex = EMPTY_TIMEX;
        adjtime(&mut timex)?;
        timex.modes = libc::MOD_STATUS;
        timex.status &= !libc::STA_PLL & !libc::STA_FLL & !libc::STA_PPSTIME & !libc::STA_PPSFREQ;
        adjtime(&mut timex)
    }

    fn ntp_algorithm_update(
        &self,
        offset: NtpDuration,
        poll_interval: PollInterval,
    ) -> Result<(), Self::Error> {
        let mut timex = EMPTY_TIMEX;
        timex.modes = libc::MOD_OFFSET | libc::MOD_TIMECONST;
        timex.offset = duration_in_nanos(offset);
        timex.constant = poll_interval.as_log() as libc::c_long;
        adjtime(&mut timex)
    }

    fn error_estimate_update(
        &self,
        est_error: NtpDuration,
        max_error: NtpDuration,
    ) -> Result<(), Self::Error> {
        let mut timex = EMPTY_TIMEX;
        timex.modes = libc::MOD_ESTERROR | libc::MOD_MAXERROR;
        timex.esterror = duration_in_nanos(est_error) / 1000;
        timex.maxerror = duration_in_nanos(max_error) / 1000;
        adjtime(&mut timex)
    }

    fn status_update(&self, leap_status: NtpLeapIndicator) -> Result<(), Self::Error> {
        let mut timex = EMPTY_TIMEX;
        adjtime(&mut timex)?;
        timex.modes = libc::MOD_STATUS;
        timex.status &= !libc::STA_INS & !libc::STA_DEL & !libc::STA_UNSYNC;
        match leap_status {
            NtpLeapIndicator::NoWarning => {}
            NtpLeapIndicator::Leap61 => timex.status |= libc::STA_INS,
            NtpLeapIndicator::Leap59 => timex.status |= libc::STA_DEL,
            NtpLeapIndicator::Unknown => timex.status |= libc::STA_UNSYNC,
        }
        adjtime(&mut timex)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_time_now_does_not_crash() {
        let clock = UnixNtpClock::new();
        assert_ne!(
            clock.now().unwrap(),
            NtpTimestamp::from_seconds_nanos_since_ntp_era(0, 0)
        );
    }
}
