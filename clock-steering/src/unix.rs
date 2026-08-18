#[cfg(target_os = "linux")]
use crate::linux_ioctls::{ptp_clock_getcaps, PtpClockCaps};
use crate::{Clock, ClockCapabilities, LeapIndicator, TimeOffset, Timestamp};
#[cfg(target_os = "linux")]
use std::mem::MaybeUninit;
use std::time::Duration;
#[cfg(target_os = "linux")]
use std::{
    os::unix::io::{IntoRawFd, RawFd},
    path::Path,
};

/// A Unix OS clock
#[derive(Debug, Clone, Copy)]
pub struct UnixClock {
    clock: libc::clockid_t,
    #[cfg(target_os = "linux")]
    fd: Option<RawFd>,
}

impl UnixClock {
    /// The standard realtime clock on unix systems.
    ///
    /// ```no_run
    /// use clock_steering::{Clock, unix::UnixClock};
    ///
    /// fn main() -> std::io::Result<()> {
    ///     let clock = UnixClock::CLOCK_REALTIME;
    ///     let now = clock.now()?;
    ///
    ///     println!("{now:?}");
    ///
    ///     Ok(())
    /// }
    /// ```
    pub const CLOCK_REALTIME: Self = UnixClock {
        clock: libc::CLOCK_REALTIME,
        #[cfg(target_os = "linux")]
        fd: None,
    };

    /// TAI time on linux systems.
    ///
    /// ```no_run
    /// use clock_steering::{Clock, unix::UnixClock};
    ///
    /// fn main() -> std::io::Result<()> {
    ///     let clock = UnixClock::CLOCK_TAI;
    ///     let now = clock.now()?;
    ///
    ///     println!("{now:?}");
    ///
    ///     Ok(())
    /// }
    /// ```
    #[cfg(target_os = "linux")]
    pub const CLOCK_TAI: Self = UnixClock {
        clock: libc::CLOCK_TAI,
        fd: None,
    };

    /// Open a clock device.
    ///
    /// ```no_run
    /// use clock_steering::{Clock, unix::UnixClock};
    ///
    /// fn main() -> std::io::Result<()> {
    ///     let clock = UnixClock::open("/dev/ptp0")?;
    ///     let now = clock.now()?;
    ///
    ///     println!("{now:?}");
    ///
    ///     Ok(())
    /// }
    /// ```
    #[cfg(target_os = "linux")]
    pub fn open(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let file = std::fs::OpenOptions::new()
            .write(true)
            .read(true)
            .open(path)?;

        // we need an owned fd. the file will be closed when the process exits.
        let clock = Self::safe_from_raw_fd(file.into_raw_fd());

        Ok(clock)
    }

    // Consume an fd and produce a clock id. Clock id is only valid
    // so long as the fd is open, so the RawFd here should
    // not be borrowed.
    #[cfg(target_os = "linux")]
    fn safe_from_raw_fd(fd: RawFd) -> Self {
        let clock = ((!(fd as libc::clockid_t)) << 3) | 3;

        Self {
            clock,
            fd: Some(fd),
        }
    }

    /// Determine offset between file clock and TAI clock (if any)
    /// Returns two system timestamps sandwhiching a timestamp from the
    /// hardware clock.
    #[cfg(target_os = "linux")]
    pub fn system_offset(&self) -> Result<(Timestamp, Timestamp, Timestamp), Error> {
        use libc::{ptp_clock_time, ptp_sys_offset, PTP_SYS_OFFSET};

        let Some(fd) = self.fd else {
            return Err(Error::Invalid);
        };

        let default_ptp_clock_time = ptp_clock_time {
            sec: 0,
            nsec: 0,
            reserved: 0,
        };

        let mut offset = ptp_sys_offset {
            n_samples: 1,
            rsv: [0u32; 3],
            ts: [default_ptp_clock_time; 51],
        };

        // # Safety
        //
        // PTP_SYS_OFFSET receives a valid ptp_sys_offset mutable pointer
        if unsafe { libc::ioctl(fd, PTP_SYS_OFFSET as _, &mut offset) } != 0 {
            let t1 = Self::CLOCK_TAI.now();
            let tp = self.now();
            let t2 = Self::CLOCK_TAI.now();

            Ok((t1?, tp?, t2?))
        } else {
            let tai_offset = Self::CLOCK_TAI.get_tai()?;

            Ok((
                Timestamp {
                    seconds: (offset.ts[0].sec + tai_offset as i64) as _,
                    nanos: offset.ts[0].nsec as _,
                },
                Timestamp {
                    seconds: offset.ts[1].sec as _,
                    nanos: offset.ts[1].nsec as _,
                },
                Timestamp {
                    seconds: (offset.ts[2].sec + tai_offset as i64) as _,
                    nanos: offset.ts[2].nsec as _,
                },
            ))
        }
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
        // using an invalid clock id is safe. `clock_adjtime` will return an EINVAL
        // error https://man.archlinux.org/man/clock_adjtime.2.en#EINVAL~4
        #[cfg(target_os = "linux")]
        use libc::clock_adjtime as adjtime;

        #[cfg(any(target_os = "freebsd", target_os = "macos"))]
        unsafe fn adjtime(clk_id: libc::clockid_t, buf: *mut libc::timex) -> libc::c_int {
            assert_eq!(
                clk_id,
                libc::CLOCK_REALTIME,
                "only the REALTIME clock is supported"
            );

            libc::ntp_adjtime(buf)
        }

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

    /// Adjust the clock state with a [`libc::timex`] specifying the desired changes.
    ///
    /// This is a lowlevel function. If possible, use more specialized (trait) methods.
    ///
    /// Note that [`libc::timex`] has a different layout between different operating systems, and
    /// not all fields are available on all operating systems. Keep this in mind when writing
    /// platform-independent code.
    fn adjtime(&self, timex: &mut libc::timex) -> Result<(), Error> {
        if self.clock == libc::CLOCK_REALTIME {
            Self::ntp_adjtime(timex)
        } else {
            self.clock_adjtime(timex)
        }
    }

    #[cfg_attr(target_os = "linux", allow(unused))]
    fn clock_gettime(&self) -> Result<libc::timespec, Error> {
        let mut timespec = libc::timespec::default();

        // # Safety
        //
        // using an invalid clock id is safe. `clock_adjtime` will return an EINVAL
        // error https://linux.die.net/man/3/clock_gettime
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
        // using an invalid clock id is safe. `clock_adjtime` will return an EINVAL
        // error https://linux.die.net/man/3/clock_settime
        //
        // The timespec pointer is valid.
        unsafe { cerr(libc::clock_settime(self.clock, &timespec))? };

        Ok(())
    }

    #[cfg_attr(target_os = "linux", allow(unused))]
    fn step_clock_by_timespec(&self, offset: TimeOffset) -> Result<Timestamp, Error> {
        let mut timespec = self.clock_gettime()?;

        // see https://github.com/rust-lang/libc/issues/1848
        #[cfg_attr(target_env = "musl", allow(deprecated))]
        {
            timespec.tv_sec += offset.seconds as libc::time_t;
            timespec.tv_nsec += offset.nanos as libc::c_long;
        }

        self.clock_settime(timespec)?;

        Ok(current_time_timespec(timespec, Precision::Nano))
    }

    fn error_estimate_timex(est_error: Duration, max_error: Duration) -> libc::timex {
        let modes = libc::MOD_ESTERROR | libc::MOD_MAXERROR;

        // these fields are always in microseconds
        let esterror = est_error.as_nanos() as libc::c_long / 1000;
        let maxerror = max_error.as_nanos() as libc::c_long / 1000;

        libc::timex {
            modes,
            esterror,
            maxerror,
            ..EMPTY_TIMEX
        }
    }

    #[cfg(target_os = "linux")]
    fn step_clock_timex(offset: TimeOffset) -> libc::timex {
        // we provide the offset in nanoseconds
        let modes = libc::ADJ_SETOFFSET | libc::ADJ_NANO;

        let time = libc::timeval {
            tv_sec: offset.seconds,
            tv_usec: offset.nanos as libc::suseconds_t,
        };

        libc::timex {
            modes,
            time,
            ..EMPTY_TIMEX
        }
    }

    #[cfg(target_os = "linux")]
    fn step_clock_by_timex(&self, offset: TimeOffset) -> Result<Timestamp, Error> {
        let mut timex = Self::step_clock_timex(offset);
        self.adjtime(&mut timex)?;
        self.extract_current_time(&timex)
    }

    fn extract_current_time(&self, _timex: &libc::timex) -> Result<Timestamp, Error> {
        #[cfg(target_os = "linux")]
        // hardware clocks may not report the timestamp
        if _timex.time.tv_sec != 0 && _timex.time.tv_usec != 0 {
            // in a timex, the status flag determines precision
            let precision = match _timex.status & libc::STA_NANO {
                0 => Precision::Micro,
                _ => Precision::Nano,
            };

            return Ok(current_time_timeval(_timex.time, precision));
        }

        // clock_gettime always gives nanoseconds
        let timespec = self.clock_gettime()?;
        Ok(current_time_timespec(timespec, Precision::Nano))
    }

    #[inline(always)]
    fn update_timex<F>(&self, f: F) -> Result<(), Error>
    where
        F: FnOnce(libc::timex) -> libc::timex,
    {
        let mut timex = EMPTY_TIMEX;
        self.adjtime(&mut timex)?;

        timex = f(timex);

        self.adjtime(&mut timex)
    }

    #[inline(always)]
    fn update_status<F>(&self, f: F) -> Result<(), Error>
    where
        F: FnOnce(libc::c_int) -> libc::c_int,
    {
        self.update_timex(|mut timex| {
            // We are setting the status bits
            timex.modes = libc::MOD_STATUS;

            // update the status flags
            timex.status = f(timex.status);

            timex
        })
    }

    fn set_frequency_timex(ppm: f64) -> libc::timex {
        // We do an offset with precision
        let mut timex = EMPTY_TIMEX;

        // set the frequency (MOD_FREQUENCY is an alias for ADJ_FREQUENCY on linux)
        timex.modes = libc::MOD_FREQUENCY;

        // NTP Kapi expects frequency adjustment in units of 2^-16 ppm
        // but our input is in units of seconds drift per second, so convert.
        let frequency = (ppm * 65536.0).round() as libc::c_long;

        // Since Linux 2.6.26, the supplied value is clamped to the range (-32768000,
        // +32768000). In older kernels, an EINVAL error occurs if the supplied value is
        // out of range. (32768000 is 500 << 16)
        timex.freq = frequency.clamp(-32_768_000 + 1, 32_768_000 - 1);

        timex
    }
}

impl UnixClock {
    #[cfg(target_os = "linux")]
    fn detect_ptp_capabilities(&self) -> Result<ClockCapabilities, Error> {
        if let Some(fd) = self.fd {
            let mut caps = MaybeUninit::<PtpClockCaps>::zeroed();

            if unsafe { ptp_clock_getcaps(fd, caps.as_mut_ptr()) } == 0 {
                let caps = unsafe { caps.assume_init() };

                Ok(ClockCapabilities {
                    max_frequency_adjustment_ppm: caps.max_adj as f64 / 1000.0,
                    max_offset_adjustment_ns: caps.max_phase_adj as u32,
                })
            } else if error_number() == libc::ENOTTY {
                // Not a PTP device, use system clock defaults
                Ok(ClockCapabilities::default())
            } else {
                Err(convert_errno())
            }
        } else {
            // System clock, use system defaults
            Ok(ClockCapabilities::default())
        }
    }
}

impl Clock for UnixClock {
    type Error = Error;

    fn now(&self) -> Result<Timestamp, Self::Error> {
        let mut ntp_kapi_timex = EMPTY_TIMEX;

        if self.adjtime(&mut ntp_kapi_timex).is_ok() {
            self.extract_current_time(&ntp_kapi_timex)
        } else {
            self.clock_gettime()
                .map(|ts| current_time_timespec(ts, Precision::Nano))
        }
    }

    fn resolution(&self) -> Result<Timestamp, Self::Error> {
        let mut timespec = libc::timespec::default();

        cerr(unsafe { libc::clock_getres(self.clock, &mut timespec) })?;

        Ok(current_time_timespec(timespec, Precision::Nano))
    }

    #[cfg(target_os = "linux")]
    fn capabilities(&self) -> Result<ClockCapabilities, Self::Error> {
        self.detect_ptp_capabilities()
    }

    #[cfg(not(target_os = "linux"))]
    fn capabilities(&self) -> Result<ClockCapabilities, Self::Error> {
        // Non-Linux systems use system clock defaults
        Ok(ClockCapabilities::default())
    }

    fn get_frequency(&self) -> Result<f64, Self::Error> {
        let mut timex = EMPTY_TIMEX;
        self.adjtime(&mut timex)?;

        Ok((timex.freq as f64) / 65536.0)
    }

    fn set_frequency(&self, frequency: f64) -> Result<Timestamp, Self::Error> {
        let mut timex = Self::set_frequency_timex(frequency);
        self.adjtime(&mut timex)?;
        self.extract_current_time(&timex)
    }

    #[cfg(target_os = "linux")]
    fn step_clock(&self, offset: TimeOffset) -> Result<Timestamp, Self::Error> {
        self.step_clock_by_timex(offset)
    }

    #[cfg(any(target_os = "freebsd", target_os = "macos"))]
    fn step_clock(&self, offset: TimeOffset) -> Result<Timestamp, Self::Error> {
        self.step_clock_by_timespec(offset)
    }

    fn set_leap_seconds(&self, leap_status: LeapIndicator) -> Result<(), Self::Error> {
        self.update_status(|status| {
            (status & !(libc::STA_UNSYNC | libc::STA_INS | libc::STA_DEL))
                | leap_status.as_status_bit()
        })
    }

    fn error_estimate_update(
        &self,
        est_error: Duration,
        max_error: Duration,
    ) -> Result<(), Self::Error> {
        let mut timex = Self::error_estimate_timex(est_error, max_error);
        Error::ignore_not_supported(self.adjtime(&mut timex))
    }

    fn disable_kernel_ntp_algorithm(&self) -> Result<(), Self::Error> {
        let mut timex = EMPTY_TIMEX;
        self.adjtime(&mut timex)?;

        // We are setting the status bits
        timex.modes = libc::MOD_STATUS;

        // Disable all kernel time control loops (phase lock, frequency lock, pps time and pps frequency).
        timex.status &= !(libc::STA_PLL | libc::STA_FLL | libc::STA_PPSTIME | libc::STA_PPSFREQ);

        // ignore if we cannot disable the kernel time control loops (e.g. external clocks)
        Error::ignore_not_supported(self.adjtime(&mut timex))
    }

    #[cfg(target_os = "linux")]
    fn set_tai(&self, tai_offset: i32) -> Result<(), Error> {
        let mut timex = libc::timex {
            modes: libc::ADJ_TAI,
            constant: tai_offset as _,
            ..EMPTY_TIMEX
        };

        self.clock_adjtime(&mut timex)
    }

    #[cfg(not(target_os = "linux"))]
    fn set_tai(&self, _tai_offset: i32) -> Result<(), Error> {
        Err(Error::NotSupported)
    }

    #[cfg(target_os = "linux")]
    fn get_tai(&self) -> Result<i32, Error> {
        let mut timex = EMPTY_TIMEX;
        if self.clock_adjtime(&mut timex).is_ok() {
            Ok(timex.tai)
        } else {
            // hardware clock which doesn't have an offset anyway
            Ok(0)
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn get_tai(&self) -> Result<i32, Error> {
        Err(Error::NotSupported)
    }
}

/// Errors that can be thrown by modifying a unix clock
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum Error {
    /// Insufficient permissions to interact with the clock.
    NoPermission,
    /// No access to the clock.
    NoAccess,
    /// Invalid operation requested
    Invalid,
    /// Clock device has gone away
    NoDevice,
    /// Clock operation requested is not supported by operating system.
    NotSupported,
    /// Clock adjustment failed because the provided value was out of range
    OutOfRange,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use Error::*;

        let msg = match self {
            NoPermission => "Insufficient permissions to interact with the clock.",
            NoAccess => "No access to the clock.",
            Invalid => "Invalid operation requested",
            NoDevice => "Clock device has gone away",
            NotSupported => "Clock operation requested is not supported by operating system.",
            OutOfRange => "Value out of range",
        };

        f.write_str(msg)
    }
}

impl std::error::Error for Error {}

impl Error {
    /// Turn the `Error::NotSupported` error variant into `Ok(())`, to silently
    /// ignore operations that are not supported by the current clock. All
    /// other input values are untouched.
    pub fn ignore_not_supported(res: Result<(), Error>) -> Result<(), Error> {
        match res {
            Err(Error::NotSupported) => Ok(()),
            other => other,
        }
    }

    // TODO: use https://doc.rust-lang.org/std/io/type.RawOsError.html when stable
    fn into_raw_os_error(self) -> i32 {
        match self {
            Self::NoPermission => libc::EPERM,
            Self::NoAccess => libc::EACCES,
            Self::Invalid => libc::EINVAL,
            Self::NoDevice => libc::ENODEV,
            Self::NotSupported => libc::EOPNOTSUPP,
            Self::OutOfRange => libc::ERANGE,
        }
    }
}

impl From<Error> for std::io::Error {
    fn from(value: Error) -> Self {
        std::io::Error::from_raw_os_error(value.into_raw_os_error())
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

// Convert those error numbers that can occur for calls to the following
// functions
// - ntp_adjtimex https://man7.org/linux/man-pages/man3/ntp_adjtime.3.html
// - clock_gettime & clock_settime https://man7.org/linux/man-pages/man3/clock_gettime.3.html
fn convert_errno() -> Error {
    match error_number() {
        libc::EINVAL => Error::Invalid,
        // The documentation is a bit unclear if this can happen with
        // non-dynamic clocks like the ntp kapi clock, however deal with it just in case.
        libc::ENODEV => Error::NoDevice,
        libc::EOPNOTSUPP => Error::NotSupported,
        libc::EPERM => Error::NoPermission,
        libc::EACCES => Error::NoAccess,
        libc::ERANGE => Error::OutOfRange,
        libc::EFAULT => unreachable!("we always pass in valid (accessible) buffers"),
        // No other errors should occur
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

pub(crate) enum Precision {
    Nano,
    #[cfg_attr(any(target_os = "freebsd", target_os = "macos"), allow(unused))]
    Micro,
}

#[cfg_attr(target_os = "linux", allow(unused))]
fn current_time_timespec(timespec: libc::timespec, precision: Precision) -> Timestamp {
    let mut seconds = timespec.tv_sec;

    let nanos: i32 = timespec.tv_nsec as _;

    let mut nanos = match precision {
        Precision::Nano => nanos,
        Precision::Micro => nanos.checked_mul(1000).unwrap_or_default(),
    };

    // on macOS (at least) we've observed higher nanosecond counts than appear valid
    while nanos > 1_000_000_000 {
        seconds = seconds.wrapping_add(1);
        nanos -= 1_000_000_000;
    }

    // we disallow negative nanoseconds
    while nanos < 0 {
        seconds = seconds.wrapping_sub(1);
        nanos += 1_000_000_000;
    }

    Timestamp {
        seconds,
        nanos: nanos as u32,
    }
}

#[cfg_attr(not(target_os = "linux"), allow(unused))]
fn current_time_timeval(timespec: libc::timeval, precision: Precision) -> Timestamp {
    let seconds = timespec.tv_sec;
    let nanos = match precision {
        Precision::Nano => timespec.tv_usec as u32,
        Precision::Micro => (timespec.tv_usec as u32)
            .checked_mul(1000)
            .unwrap_or_default(),
    };

    Timestamp { seconds, nanos }
}

// Libc has no good other way of obtaining this, so let's at least make our
// functions more readable.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
pub const EMPTY_TIMEX: libc::timex = libc::timex {
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
pub const EMPTY_TIMEX: libc::timex = libc::timex {
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
pub const EMPTY_TIMEX: libc::timex = libc::timex {
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

impl LeapIndicator {
    fn as_status_bit(self) -> libc::c_int {
        match self {
            LeapIndicator::NoWarning => 0,
            LeapIndicator::Leap61 => libc::STA_INS,
            LeapIndicator::Leap59 => libc::STA_DEL,
            LeapIndicator::Unknown => libc::STA_UNSYNC,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_time_now_does_not_crash() {
        let clock = UnixClock::CLOCK_REALTIME;
        assert_ne!(clock.now().unwrap(), Timestamp::default(),);
    }

    #[test]
    fn realtime_gettime() {
        let clock = UnixClock::CLOCK_REALTIME;
        let time = clock.clock_gettime().unwrap();

        assert_ne!((time.tv_sec, time.tv_nsec), (0, 0))
    }

    #[test]
    #[ignore = "requires permissions, useful for testing permissions"]
    fn ptp0_gettime() {
        let clock = UnixClock::CLOCK_REALTIME;
        let time = clock.clock_gettime().unwrap();

        assert_ne!((time.tv_sec, time.tv_nsec), (0, 0))
    }

    #[test]
    #[ignore = "requires permissions, useful for testing permissions"]
    fn step_clock() {
        UnixClock::CLOCK_REALTIME
            .step_clock(TimeOffset {
                seconds: 0,
                nanos: 0,
            })
            .unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_step_clock() {
        let offset = TimeOffset {
            seconds: 1,
            nanos: 200000000,
        };
        let timex = UnixClock::step_clock_timex(offset);

        assert_eq!(timex.modes, libc::ADJ_SETOFFSET | libc::ADJ_NANO);

        assert_eq!(timex.time.tv_sec, 1);
        assert_eq!(timex.time.tv_usec, 200_000_000);
    }

    #[test]
    fn test_error_estimate() {
        let est_error = Duration::from_secs_f64(0.5);
        let max_error = Duration::from_secs_f64(1.2);
        let timex = UnixClock::error_estimate_timex(est_error, max_error);

        assert_eq!(timex.modes, libc::MOD_ESTERROR | libc::MOD_MAXERROR);

        // these fields are always in microseconds
        assert_eq!(timex.esterror, 500_000);
        assert_eq!(timex.maxerror, 1_200_000);
    }

    #[test]
    fn test_now() {
        let resolution = UnixClock::CLOCK_REALTIME.now().unwrap();

        assert_ne!(resolution, Timestamp::default());
    }

    #[test]
    fn test_resolution() {
        let resolution = UnixClock::CLOCK_REALTIME.resolution().unwrap();

        assert_ne!(resolution, Timestamp::default());
    }

    #[test]
    fn test_capabilities() {
        let clock = UnixClock::CLOCK_REALTIME;

        assert!(clock.capabilities().is_ok());
    }
}
