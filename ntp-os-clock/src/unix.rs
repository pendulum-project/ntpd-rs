// Note on unsafe usage.
//
// This module uses unsafe code to interact with the system calls that
// are used to set/get the current behaviour and time of the clock. It
// is constructed in such a way that use of the public functions is
// safe regardless of given arguments.

use crate::{Error, EPOCH_OFFSET};
use ntp_proto::{NtpClock, NtpDuration, NtpLeapIndicator, NtpTimestamp, PollInterval};

// Libc has no good other way of obtaining this, so let's at least make our functions
// more readable.
#[cfg(target_os = "linux")]
pub(crate) const EMPTY_TIMEX: libc::timex = libc::timex {
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

#[cfg(any(target_os = "freebsd", target_os = "macos"))]
pub(crate) const EMPTY_TIMEX: libc::timex = libc::timex {
    modes: 0,
    offset: 0,
    freq: 0,
    maxerror: 0,
    esterror: 0,
    status: 0,
    constant: 0,
    precision: 0,
    tolerance: 0,
    ppsfreq: 0,
    jitter: 0,
    shift: 0,
    stabil: 0,
    jitcnt: 0,
    calcnt: 0,
    errcnt: 0,
    stbcnt: 0,
};

#[cfg(target_os = "linux")]
pub(crate) const EMPTY_NTPTIMEVAL: libc::ntptimeval = libc::ntptimeval {
    time: libc::timeval {
        tv_sec: 0,
        tv_usec: 0,
    },
    maxerror: 0,
    esterror: 0,
    tai: 0,
    __glibc_reserved1: 0,
    __glibc_reserved2: 0,
    __glibc_reserved3: 0,
    __glibc_reserved4: 0,
};

#[cfg(not(target_os = "linux"))]
pub(crate) const EMPTY_NTPTIMEVAL: libc::ntptimeval = libc::ntptimeval {
    time: libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    },
    maxerror: 0,
    esterror: 0,
    tai: 0,
    time_state: 0,
};

pub(crate) fn adjtime(timex: &mut libc::timex) -> Result<(), Error> {
    // We don't care about the time status, so the non-error
    // information in the return value of ntp_adjtime can be ignored.
    // The ntp_adjtime call is safe because the reference always
    // points to a valid libc::timex.
    if unsafe { libc::ntp_adjtime(timex) } == -1 {
        Err(convert_errno())
    } else {
        Ok(())
    }
}

#[cfg_attr(target_os = "linux", allow(unused))]
fn gettime() -> Result<libc::ntptimeval, Error> {
    let mut timeval = EMPTY_NTPTIMEVAL;

    if unsafe { libc::ntp_gettime(&mut timeval) } == -1 {
        Err(convert_errno())
    } else {
        Ok(timeval)
    }
}

#[cfg_attr(target_os = "linux", allow(unused))]
fn settimeofday(timeval: libc::timeval) -> Result<(), Error> {
    if unsafe { libc::settimeofday(&timeval, std::ptr::null()) } == -1 {
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

fn error_number() -> libc::c_int {
    #[cfg(target_os = "linux")]
    unsafe {
        *libc::__errno_location()
    }

    #[cfg(not(target_os = "linux"))]
    unsafe {
        *libc::__error()
    }
}

// Convert those error numbers that can occur for the ntp_gettime and ntp_adjtimex calls
fn convert_errno() -> Error {
    match error_number() {
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

pub(crate) enum Precision {
    Nano,
    Micro,
}

#[cfg_attr(target_os = "linux", allow(unused))]
fn current_time_timespec(timespec: libc::timespec, precision: Precision) -> NtpTimestamp {
    // Negative eras are completely valid, so any wrapping is
    // perfectly reasonable here.
    NtpTimestamp::from_seconds_nanos_since_ntp_era(
        (timespec.tv_sec as u32).wrapping_add(EPOCH_OFFSET),
        match precision {
            Precision::Nano => timespec.tv_nsec as u32,
            Precision::Micro => (timespec.tv_nsec as u32) * 1000,
        },
    )
}

#[cfg_attr(not(target_os = "linux"), allow(unused))]
pub(crate) fn current_time_timeval(timespec: libc::timeval, precision: Precision) -> NtpTimestamp {
    // Negative eras are completely valid, so any wrapping is
    // perfectly reasonable here.
    NtpTimestamp::from_seconds_nanos_since_ntp_era(
        (timespec.tv_sec as u32).wrapping_add(EPOCH_OFFSET),
        match precision {
            Precision::Nano => timespec.tv_usec as u32,
            Precision::Micro => (timespec.tv_usec as u32) * 1000,
        },
    )
}

fn extract_current_time(timex: &libc::timex) -> Result<NtpTimestamp, Error> {
    let ntp_timeval = gettime()?;

    let precision = match timex.status & libc::STA_NANO {
        0 => Precision::Micro,
        _ => Precision::Nano,
    };

    #[cfg(target_os = "linux")]
    {
        Ok(current_time_timeval(ntp_timeval.time, precision))
    }

    #[cfg(not(target_os = "linux"))]
    {
        Ok(current_time_timespec(ntp_timeval.time, precision))
    }
}

impl NtpClock for UnixNtpClock {
    type Error = Error;

    fn now(&self) -> Result<ntp_proto::NtpTimestamp, Error> {
        let mut ntp_kapi_timex = EMPTY_TIMEX;

        adjtime(&mut ntp_kapi_timex)?;

        extract_current_time(&ntp_kapi_timex)
    }

    fn set_frequency(&self, freq: f64) -> Result<NtpTimestamp, Self::Error> {
        let mut ntp_kapi_timex = EMPTY_TIMEX;
        ntp_kapi_timex.modes = libc::MOD_FREQUENCY;
        // NTP Kapi expects frequency adjustment in units of 2^-16 ppm
        // but our input is in units of seconds drift per second, so convert.
        ntp_kapi_timex.freq = (freq * 65536e6) as libc::c_long;
        adjtime(&mut ntp_kapi_timex)?;
        extract_current_time(&ntp_kapi_timex)
    }

    fn step_clock(&self, offset: ntp_proto::NtpDuration) -> Result<NtpTimestamp, Self::Error> {
        let (secs, nanos) = offset.as_seconds_nanos();
        let timeval = libc::timeval {
            tv_sec: secs as libc::time_t,
            tv_usec: nanos as libc::suseconds_t,
        };

        settimeofday(timeval)?;

        let mut timex = EMPTY_TIMEX;
        timex.modes = libc::MOD_NANO;
        adjtime(&mut timex)?;

        extract_current_time(&timex)
    }

    fn enable_ntp_algorithm(&self) -> Result<(), Self::Error> {
        let mut timex = EMPTY_TIMEX;
        adjtime(&mut timex)?;
        timex.modes = libc::MOD_STATUS;
        // Enable the kernel phase locked loop
        timex.status |= libc::STA_PLL;
        // and disable the frequency locked loop,
        // pps input based time control, and pps
        // input based frequency control.
        timex.status &= !libc::STA_FLL & !libc::STA_PPSTIME & !libc::STA_PPSFREQ;
        adjtime(&mut timex)
    }

    fn disable_ntp_algorithm(&self) -> Result<(), Self::Error> {
        let mut timex = EMPTY_TIMEX;
        adjtime(&mut timex)?;
        timex.modes = libc::MOD_STATUS;
        // Disable all kernel time control loops
        // (phase lock, frequency lock, pps time
        // and pps frequency).
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
        // Clear out the leap seconds and synchronization flags
        timex.status &= !libc::STA_INS & !libc::STA_DEL & !libc::STA_UNSYNC;
        // and add back in what is needed.
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
