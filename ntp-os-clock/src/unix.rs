// Note on unsafe usage.
//
// This module uses unsafe code to interact with the system calls that
// are used to set/get the current behaviour and time of the clock. It
// is constructed in such a way that use of the public functions is
// safe regardless of given arguments.

use std::{
    os::unix::io::{AsRawFd, RawFd},
    path::Path,
};

use crate::{Error, EPOCH_OFFSET};
use ntp_proto::{NtpClock, NtpDuration, NtpLeapIndicator, NtpTimestamp, PollInterval};

// Libc has no good other way of obtaining this, so let's at least make our functions
// more readable.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
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

#[cfg(all(target_os = "linux", target_env = "musl"))]
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
    __padding: [0; 11],
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

/// NTP Clock that uses the unix NTP KAPI clock functions to get/modify the
/// current time.
// Implementation note: this is intentionally a bare struct, the NTP Clock defined
// in the NTP KAPI is unique and no state is needed to interact with it.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnixNtpClock {
    clock: libc::clockid_t,
}

impl UnixNtpClock {
    pub fn realtime() -> Self {
        Self::custom(libc::CLOCK_REALTIME)
    }

    pub fn custom(id: libc::clockid_t) -> Self {
        Self { clock: id }
    }

    pub fn from_path(path: &Path) -> Result<Self, Error> {
        match std::fs::File::options().read(true).write(true).open(path) {
            Err(_) => Err(convert_errno()),
            Ok(file) => {
                let fd = file.as_raw_fd();

                // never close the file, keep it open so clock steering can use the file descriptor
                std::mem::forget(file);

                Ok(Self::from_file_descriptor(fd))
            }
        }
    }

    pub fn from_file_descriptor(fd: RawFd) -> Self {
        // using an invalid clock id is safe. The function that take this value as an argument will
        // return an EINVAL IO error when the clock id is invalid.

        let id = ((!(fd as libc::clockid_t)) << 3) | 0b11;
        Self::custom(id)
    }

    #[cfg_attr(target_os = "linux", allow(unused))]
    fn clock_gettime(&self) -> Result<libc::timespec, Error> {
        let mut timespec = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };

        // # Safety
        //
        // using an invalid clock id is safe. `clock_adjtime` will return an EINVAL error
        // https://linux.die.net/man/3/clock_gettime
        //
        // The timespec pointer is valid.
        cerr(unsafe { libc::clock_gettime(self.clock, &mut timespec) })?;

        Ok(timespec)
    }

    #[cfg_attr(target_os = "linux", allow(unused))]
    fn clock_settime(&self, mut timespec: libc::timespec) -> Result<(), Error> {
        while timespec.tv_nsec > 1_000_000_000 {
            timespec.tv_sec += 1;
            timespec.tv_nsec -= 1_000_000_000;
        }

        // # Safety
        //
        // using an invalid clock id is safe. `clock_adjtime` will return an EINVAL error
        // https://linux.die.net/man/3/clock_settime
        //
        // The timespec pointer is valid.
        unsafe { cerr(libc::clock_settime(self.clock, &timespec))? };

        Ok(())
    }

    fn clock_adjtime(&self, timex: &mut libc::timex) -> Result<(), Error> {
        // We don't care about the time status, so the non-error
        // information in the return value of clock_adjtime can be ignored.
        //
        // # Safety
        //
        // The clock_adjtime call is safe because the reference always
        // points to a valid libc::timex.
        //
        // using an invalid clock id is safe. `clock_adjtime` will return an EINVAL error
        // https://man.archlinux.org/man/clock_adjtime.2.en#EINVAL~4
        #[cfg(target_os = "linux")]
        use libc::clock_adjtime as adjtime;

        #[cfg(any(target_os = "freebsd", target_os = "macos"))]
        let adjtime = {
            extern "C" {
                fn clock_adjtime(clk_id: libc::clockid_t, buf: *mut libc::timex) -> libc::c_int;
            }

            clock_adjtime
        };

        if unsafe { adjtime(self.clock, timex) } == -1 {
            Err(convert_errno())
        } else {
            Ok(())
        }
    }

    fn ntp_adjtime(timex: &mut libc::timex) -> Result<(), Error> {
        #[cfg(any(target_os = "freebsd", target_os = "macos", target_env = "gnu"))]
        use libc::ntp_adjtime as adjtime;

        // ntp_adjtime is equivalent to adjtimex for our purposes
        //
        // https://man7.org/linux/man-pages/man2/adjtimex.2.html
        #[cfg(all(target_os = "linux", target_env = "musl"))]
        use libc::adjtimex as adjtime;

        // We don't care about the time status, so the non-error
        // information in the return value of ntp_adjtime can be ignored.
        // The ntp_adjtime call is safe because the reference always
        // points to a valid libc::timex.
        if unsafe { adjtime(timex) } == -1 {
            Err(convert_errno())
        } else {
            Ok(())
        }
    }

    pub(crate) fn adjtime(&self, timex: &mut libc::timex) -> Result<(), Error> {
        if self.clock == libc::CLOCK_REALTIME {
            Self::ntp_adjtime(timex)
        } else {
            self.clock_adjtime(timex)
        }
    }

    #[cfg_attr(target_os = "linux", allow(unused))]
    fn step_clock_timespec(&self, offset: ntp_proto::NtpDuration) -> Result<NtpTimestamp, Error> {
        let (offset_secs, offset_nanos) = offset.as_seconds_nanos();

        let mut timespec = self.clock_gettime()?;

        // see https://github.com/rust-lang/libc/issues/1848
        #[cfg_attr(target_env = "musl", allow(deprecated))]
        {
            timespec.tv_sec += offset_secs as libc::time_t;
            timespec.tv_nsec += offset_nanos as libc::c_long;
        }

        self.clock_settime(timespec)?;

        Ok(current_time_timespec(timespec, Precision::Nano))
    }

    #[cfg(target_os = "linux")]
    fn step_clock_timex(&self, offset: ntp_proto::NtpDuration) -> Result<NtpTimestamp, Error> {
        let (secs, nanos) = offset.as_seconds_nanos();

        let mut timex = libc::timex {
            modes: libc::ADJ_SETOFFSET | libc::MOD_NANO,
            time: libc::timeval {
                tv_sec: secs as _,
                tv_usec: nanos as libc::suseconds_t,
            },
            ..crate::unix::EMPTY_TIMEX
        };

        self.adjtime(&mut timex)?;
        self.extract_current_time(&timex)
    }

    fn extract_current_time(&self, _timex: &libc::timex) -> Result<NtpTimestamp, Error> {
        #[cfg(target_os = "linux")]
        {
            // hardware clocks may not report the timestamp
            if _timex.time.tv_sec != 0 && _timex.time.tv_usec != 0 {
                // in a timex, the status flag determines precision
                let precision = match _timex.status & libc::STA_NANO {
                    0 => Precision::Micro,
                    _ => Precision::Nano,
                };

                Ok(current_time_timeval(_timex.time, precision))
            } else {
                let timespec = self.clock_gettime()?;
                Ok(current_time_timespec(timespec, Precision::Nano))
            }
        }

        #[cfg(any(target_os = "freebsd", target_os = "macos"))]
        {
            // clock_gettime always gives nanoseconds
            let timespec = self.clock_gettime()?;
            Ok(current_time_timespec(timespec, Precision::Nano))
        }
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
        other => {
            let error = std::io::Error::from_raw_os_error(other);
            unreachable!("error code `{other}` ({error:?}) should not occur")
        }
    }
}

fn cerr(c_int: libc::c_int) -> Result<(), Error> {
    if c_int == -1 {
        Err(convert_errno())
    } else {
        Ok(())
    }
}

fn duration_in_nanos(duration: NtpDuration) -> libc::c_long {
    let (secs, nanos) = duration.as_seconds_nanos();
    (secs as libc::c_long) * 1_000_000_000 + (nanos as libc::c_long)
}

pub(crate) enum Precision {
    Nano,
    #[cfg_attr(any(target_os = "freebsd", target_os = "macos"), allow(unused))]
    Micro,
}

fn micros_to_nanos(micros: u32) -> u32 {
    let msg = "microseconds out of range (this can happen when initializing hardware clocks)";

    match micros.checked_mul(1000) {
        Some(v) => v,
        None => {
            tracing::warn!(msg);
            0
        }
    }
}

#[cfg_attr(target_os = "linux", allow(unused))]
fn current_time_timespec(timespec: libc::timespec, precision: Precision) -> NtpTimestamp {
    // Negative eras are completely valid, so any wrapping is perfectly reasonable here.
    NtpTimestamp::from_seconds_nanos_since_ntp_era(
        (timespec.tv_sec as u32).wrapping_add(EPOCH_OFFSET),
        match precision {
            Precision::Nano => timespec.tv_nsec as u32,
            Precision::Micro => micros_to_nanos(timespec.tv_nsec as u32),
        },
    )
}

fn current_time_timeval(timespec: libc::timeval, precision: Precision) -> NtpTimestamp {
    // Negative eras are completely valid, so any wrapping is perfectly reasonable here.
    NtpTimestamp::from_seconds_nanos_since_ntp_era(
        (timespec.tv_sec as u32).wrapping_add(EPOCH_OFFSET),
        match precision {
            Precision::Nano => timespec.tv_usec as u32,
            Precision::Micro => micros_to_nanos(timespec.tv_usec as u32),
        },
    )
}

fn ignore_not_supported(res: Result<(), Error>) -> Result<(), Error> {
    match res {
        Err(Error::NotSupported) => Ok(()),
        other => other,
    }
}

impl NtpClock for UnixNtpClock {
    type Error = Error;

    fn now(&self) -> Result<ntp_proto::NtpTimestamp, Error> {
        let mut ntp_kapi_timex = EMPTY_TIMEX;

        self.adjtime(&mut ntp_kapi_timex)?;

        self.extract_current_time(&ntp_kapi_timex)
    }

    fn set_frequency(&self, freq: f64) -> Result<NtpTimestamp, Self::Error> {
        let mut ntp_kapi_timex = EMPTY_TIMEX;
        ntp_kapi_timex.modes = libc::MOD_FREQUENCY;
        // NTP Kapi expects frequency adjustment in units of 2^-16 ppm
        // but our input is in units of seconds drift per second, so convert.
        ntp_kapi_timex.freq = (freq * 65536e6) as libc::c_long;
        ntp_kapi_timex.status =
            !libc::STA_PLL & !libc::STA_PPSFREQ & !libc::STA_FLL & !libc::STA_PPSTIME;

        self.adjtime(&mut ntp_kapi_timex)?;
        self.extract_current_time(&ntp_kapi_timex)
    }

    #[cfg(target_os = "linux")]
    fn step_clock(&self, offset: ntp_proto::NtpDuration) -> Result<NtpTimestamp, Self::Error> {
        self.step_clock_timex(offset)
    }

    #[cfg(any(target_os = "freebsd", target_os = "macos"))]
    fn step_clock(&self, offset: ntp_proto::NtpDuration) -> Result<NtpTimestamp, Self::Error> {
        self.step_clock_timespec(offset)
    }

    fn enable_ntp_algorithm(&self) -> Result<(), Self::Error> {
        let mut timex = EMPTY_TIMEX;
        self.adjtime(&mut timex)?;
        timex.modes = libc::MOD_STATUS;

        // Enable the kernel phase locked loop
        timex.status |= libc::STA_PLL;
        // and disable the frequency locked loop,
        // pps input based time control, and pps
        // input based frequency control.
        timex.status &= !libc::STA_FLL & !libc::STA_PPSTIME & !libc::STA_PPSFREQ;
        self.adjtime(&mut timex)
    }

    fn disable_ntp_algorithm(&self) -> Result<(), Self::Error> {
        let mut timex = EMPTY_TIMEX;
        self.adjtime(&mut timex)?;
        timex.modes = libc::MOD_STATUS;

        // Disable all kernel time control loops (phase lock, frequency lock, pps time and pps frequency).
        timex.status &= !libc::STA_PLL & !libc::STA_FLL & !libc::STA_PPSTIME & !libc::STA_PPSFREQ;

        // ignore if we cannot disable the kernel time control loops (e.g. external clocks)
        ignore_not_supported(self.adjtime(&mut timex))
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
        ignore_not_supported(self.adjtime(&mut timex))
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
        ignore_not_supported(self.adjtime(&mut timex))
    }

    fn status_update(&self, leap_status: NtpLeapIndicator) -> Result<(), Self::Error> {
        let mut timex = EMPTY_TIMEX;
        self.adjtime(&mut timex)?;
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
        ignore_not_supported(self.adjtime(&mut timex))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_time_now_does_not_crash() {
        let clock = UnixNtpClock::realtime();
        assert_ne!(
            clock.now().unwrap(),
            NtpTimestamp::from_seconds_nanos_since_ntp_era(0, 0)
        );
    }

    #[test]
    fn realtime_gettime() {
        let clock = UnixNtpClock::realtime();
        let time = clock.clock_gettime().unwrap();

        assert_ne!((time.tv_sec, time.tv_nsec), (0, 0))
    }

    #[test]
    #[ignore = "requires permissions, useful for testing permissions"]
    fn ptp0_gettime() {
        let clock = UnixNtpClock::realtime();
        let time = clock.clock_gettime().unwrap();

        assert_ne!((time.tv_sec, time.tv_nsec), (0, 0))
    }

    #[test]
    #[ignore = "requires permissions, useful for testing permissions"]
    fn step_clock() {
        UnixNtpClock::realtime()
            .step_clock(NtpDuration::from_seconds(0.0))
            .unwrap();
    }
}
