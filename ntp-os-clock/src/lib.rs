// Note on unsafe usage.
//
// This module uses unsafe code to interact with the system calls that
// are used to set/get the current behaviour and time of the clock. It
// is constructed in such a way that use of the public functions is
// safe regardless of given arguments.

use ntp_proto::{NtpClock, NtpTimestamp};
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

/// NTP Clock that uses the unix NTP KAPI clock functions to get/modify the
/// current time.
// Implementation note: this is intentionally a bare struct, the NTP Clock defined
// in the NTP KAPI is unique and no state is needed to interact with it.
#[derive(Debug, Default)]
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

impl NtpClock for UnixNtpClock {
    type Error = Error;
    fn now(&self) -> Result<ntp_proto::NtpTimestamp, Error> {
        let mut ntp_kapi_timex = EMPTY_TIMEX;

        // We don't care here about the time status, so the non-error
        // information in the return value of ntp_adjtime can be ignored
        if unsafe { libc::ntp_adjtime(&mut ntp_kapi_timex as *mut _) } == -1 {
            return Err(convert_errno());
        }

        // Negative eras are completely valid, so any wrapping is
        // perfectly reasonable here.
        Ok(NtpTimestamp::from_seconds_nanos_since_ntp_era(
            (ntp_kapi_timex.time.tv_sec as u32).wrapping_add(EPOCH_OFFSET),
            if ntp_kapi_timex.status & libc::STA_NANO != 0 {
                // We have nanosecond precision. use it
                ntp_kapi_timex.time.tv_usec as u32
            } else {
                (ntp_kapi_timex.time.tv_usec as u32) * 1000
            },
        ))
    }

    fn adjust_clock(offset: ntp_proto::NtpDuration, freq_offset_ppm: f64) -> Result<(), Error> {
        if freq_offset_ppm.abs() > 500.0 {
            return Err(Error::Invalid);
        }

        let mut ntp_kapi_timex = EMPTY_TIMEX;
        ntp_kapi_timex.modes = libc::ADJ_FREQUENCY | libc::ADJ_NANO;
        ntp_kapi_timex.freq = (freq_offset_ppm * ((1 << 16) as f64)) as libc::c_long;

        let (offset_seconds, offset_nanos) = offset.as_seconds_nanos();

        // gradual adjustment if less than half a second off, otherwise jump
        if (offset_seconds == -1 && offset_nanos >= 500_000_000)
            || (offset_seconds == 0 && offset_nanos <= 500_000_000)
        {
            ntp_kapi_timex.modes |= libc::ADJ_OFFSET;
            ntp_kapi_timex.offset =
                (offset_nanos as i32 + offset_seconds * 1_000_000_000) as libc::c_long;
        } else {
            ntp_kapi_timex.modes |= libc::ADJ_SETOFFSET;
            ntp_kapi_timex.time.tv_sec = offset_seconds as libc::time_t;
            ntp_kapi_timex.time.tv_usec = offset_nanos as libc::suseconds_t;
        }

        if unsafe { libc::ntp_adjtime(&mut ntp_kapi_timex as *mut _) } != -1 {
            // We don't care here about the time status, so the non-error
            // information in the return value of ntp_adjtime can be ignored
            Ok(())
        } else {
            Err(convert_errno())
        }
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
