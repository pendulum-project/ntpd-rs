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

    fn set_freq(&self, freq: f64) -> Result<(), Self::Error> {
        let mut ntp_kapi_timex = EMPTY_TIMEX;
        ntp_kapi_timex.modes = libc::MOD_FREQUENCY;
        // NTP Kapi expects frequency adjustment in units of 2^-16 ppm
        // but our input is in units of seconds drift per second, so convert.
        ntp_kapi_timex.freq = (freq * 65536e6) as libc::c_long;
        if unsafe { libc::ntp_adjtime(&mut ntp_kapi_timex as *mut _) } != -1 {
            // We don't care here about the time status, so the non-error
            // information in the return value of ntp_adjtime can be ignored
            Ok(())
        } else {
            Err(convert_errno())
        }
    }

    fn step_clock(&self, offset: ntp_proto::NtpDuration) -> Result<(), Self::Error> {
        let mut tp = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };

        let (offset_secs, offset_nanos) = offset.as_seconds_nanos();

        // Begin time critical section
        // any time spend between here and the clock_settime call will reduce the
        // accuracy of the made step
        if unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut tp as *mut _) } == -1 {
            return Err(convert_errno());
        }

        tp.tv_sec += offset_secs as libc::time_t;
        tp.tv_nsec += offset_nanos as libc::c_long;
        if tp.tv_nsec >= 1_000_000_000 {
            // Deal with carry from addition of nanosecond parts
            tp.tv_nsec -= 1_000_000_000;
            tp.tv_sec += 1;
        }

        if unsafe { libc::clock_settime(libc::CLOCK_REALTIME, &tp as *const _) } == -1 {
            return Err(convert_errno());
        }
        // End time critical section

        Ok(())
    }

    fn update_clock(
        &self,
        offset: ntp_proto::NtpDuration,
        est_error: ntp_proto::NtpDuration,
        max_error: ntp_proto::NtpDuration,
        poll_interval: PollInterval,
        leap_status: NtpLeapIndicator,
    ) -> Result<(), Self::Error> {
        let mut ntp_kapi_timex = EMPTY_TIMEX;
        ntp_kapi_timex.modes = libc::MOD_OFFSET
            | libc::MOD_MAXERROR
            | libc::MOD_ESTERROR
            | libc::MOD_STATUS
            | libc::MOD_TIMECONST
            | libc::MOD_NANO;
        ntp_kapi_timex.offset = duration_in_nanos(offset);
        ntp_kapi_timex.esterror = duration_in_nanos(est_error) / 1000;
        ntp_kapi_timex.maxerror = duration_in_nanos(max_error) / 1000;
        ntp_kapi_timex.constant = poll_interval.as_log() as libc::c_long;
        ntp_kapi_timex.status = libc::STA_PLL
            | match leap_status {
                NtpLeapIndicator::Leap59 => libc::STA_DEL,
                NtpLeapIndicator::Leap61 => libc::STA_INS,
                _ => 0,
            };

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
