use std::{ffi::CString, fmt::Display};

use libc::{clockid_t, timespec};
use statime::{ClockAccuracy, ClockQuality, Duration, Instant};

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Default)]
pub enum LeapIndicator {
    #[default]
    NoWarning,
    Leap61,
    Leap59,
    #[allow(unused)]
    Unknown,
}

/// A type for precisely adjusting the time of a linux clock.
///
/// Probably best used with the CLOCK_REALTIME clock.
///
/// Using the clocks probably requires root access.
///
/// # Example
///
/// ```no_run
/// use statime_linux::clock::RawLinuxClock;
///
/// let mut test_clock = RawLinuxClock::get_realtime_clock();
/// println!("{}", test_clock);
/// test_clock.adjust_clock(0.000_001, 1.000_000_001).unwrap();
/// ```
#[derive(Debug, Clone)]
pub struct RawLinuxClock {
    id: clockid_t,
    name: String,
    quality: ClockQuality,
}

impl RawLinuxClock {
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

        if unsafe { adjtime(self.id, timex) } == -1 {
            Err(convert_errno())
        } else {
            Ok(())
        }
    }

    fn ntp_adjtime(timex: &mut libc::timex) -> Result<(), Error> {
        // ntp_adjtime is equivalent to adjtimex for our purposes
        //
        // https://man7.org/linux/man-pages/man2/adjtimex.2.html
        #[cfg(all(target_os = "linux", target_env = "musl"))]
        use libc::adjtimex as adjtime;
        #[cfg(any(target_os = "freebsd", target_os = "macos", target_env = "gnu"))]
        use libc::ntp_adjtime as adjtime;

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
        if self.id == libc::CLOCK_REALTIME {
            Self::ntp_adjtime(timex)
        } else {
            self.clock_adjtime(timex)
        }
    }

    /// Adjusts the clock
    ///
    /// - The time_offset is given in seconds.
    /// - The frequency_multiplier is the value that the *current* frequency
    ///   should be multiplied with to get to the target frequency.
    ///
    /// For example, if the clock is at 10.0 mhz, but should run at 10.1 mhz,
    /// then the frequency_multiplier should be 1.01.
    ///
    /// If the time offset is higher than 0.5 seconds, then the clock will be
    /// set directly and no frequency change will be made.
    pub fn adjust_clock(
        &mut self,
        time_offset: f64,
        frequency_multiplier: f64,
    ) -> Result<(), Error> {
        log::trace!("Adjusting clock: {time_offset}s, {frequency_multiplier}x");

        self.adjust_frequency(frequency_multiplier)?;
        self.adjust_offset(time_offset)
    }

    fn adjust_frequency(&mut self, frequency_multiplier: f64) -> Result<(), Error> {
        let mut timex = EMPTY_TIMEX;
        self.adjtime(&mut timex)?;

        let mut timex = Self::adjust_frequency_timex(timex.freq, frequency_multiplier);
        self.adjtime(&mut timex)
    }

    fn adjust_frequency_timex(frequency: libc::c_long, frequency_multiplier: f64) -> libc::timex {
        const M: f64 = 1_000_000.0;

        // In struct timex, freq, ppsfreq, and stabil are ppm (parts per million) with a
        // 16-bit fractional part, which means that a value of 1 in one of those fields
        // actually means 2^-16 ppm, and 2^16=65536 is 1 ppm.  This is the case for both
        // input values (in the case of freq) and output values.
        let current_ppm = frequency as f64 / 65536.0;

        // we need to recover the current frequency multiplier from the PPM value.
        // The ppm is an offset from the main frequency, so it's the base +- the ppm
        // expressed as a percentage. PPM is in the opposite direction from the
        // speed factor. A postive ppm means the clock is running slower, so we use its
        // negative.
        let current_frequency_multiplier = 1.0 + (-current_ppm / M);

        // Now multiply the frequencies
        let new_frequency_multiplier = current_frequency_multiplier * frequency_multiplier;

        // Get back the new ppm value by subtracting the 1.0 base from it, changing the
        // percentage to the ppm again and then negating it.
        let new_ppm = -((new_frequency_multiplier - 1.0) * M);

        Self::set_frequency_timex(new_ppm)
    }

    fn set_frequency_timex(ppm: f64) -> libc::timex {
        // We do an offset with precision
        let mut timex = EMPTY_TIMEX;

        // set the frequency and the status (for STA_FREQHOLD)
        timex.modes = libc::ADJ_FREQUENCY;

        // NTP Kapi expects frequency adjustment in units of 2^-16 ppm
        // but our input is in units of seconds drift per second, so convert.
        let frequency = (ppm * 65536.0).round() as libc::c_long;

        // Since Linux 2.6.26, the supplied value is clamped to the range (-32768000,
        // +32768000). In older kernels, an EINVAL error occurs if the supplied value is
        // out of range. (32768000 is 500 << 16)
        timex.freq = frequency.clamp(-32_768_000 + 1, 32_768_000 - 1);

        timex
    }

    fn adjust_offset(&mut self, time_offset: f64) -> Result<(), Error> {
        let mut timex = EMPTY_TIMEX;

        // set set an offset, it is in nanoseconds
        timex.modes = libc::ADJ_SETOFFSET | libc::ADJ_NANO;

        // Start with a seconds value of 0 and express the full time offset in nanos
        timex.time.tv_sec = time_offset as _;
        timex.time.tv_usec = (time_offset.fract() * 1_000_000_000.0) as _;

        // The nanos must not be negative. In that case the timestamp must be delivered
        // as a negative seconds with a postive nanos value
        while timex.time.tv_usec < 0 {
            timex.time.tv_sec -= 1;
            timex.time.tv_usec += 1_000_000_000;
        }

        self.adjtime(&mut timex)
    }

    fn get_clocks() -> impl Iterator<Item = Self> {
        const SYSTEM_CLOCKS: [(clockid_t, &str); 11] = [
            (libc::CLOCK_BOOTTIME, "CLOCK_BOOTTIME"),
            (libc::CLOCK_BOOTTIME_ALARM, "CLOCK_BOOTTIME_ALARM"),
            (libc::CLOCK_MONOTONIC, "CLOCK_MONOTONIC"),
            (libc::CLOCK_MONOTONIC_COARSE, "CLOCK_MONOTONIC_COARSE"),
            (libc::CLOCK_MONOTONIC_RAW, "CLOCK_MONOTONIC_RAW"),
            (libc::CLOCK_PROCESS_CPUTIME_ID, "CLOCK_PROCESS_CPUTIME_ID"),
            (libc::CLOCK_REALTIME, "CLOCK_REALTIME"),
            (libc::CLOCK_REALTIME_ALARM, "CLOCK_REALTIME_ALARM"),
            (libc::CLOCK_REALTIME_COARSE, "CLOCK_REALTIME_COARSE"),
            (libc::CLOCK_TAI, "CLOCK_TAI"),
            (libc::CLOCK_THREAD_CPUTIME_ID, "CLOCK_THREAD_CPUTIME_ID"),
        ];

        SYSTEM_CLOCKS.into_iter().map(|(id, name)| Self {
            id,
            name: name.into(),
            quality: ClockQuality {
                clock_class: 248,
                clock_accuracy: ClockAccuracy::MS10,
                offset_scaled_log_variance: 0xffff,
            },
        })
    }

    pub fn get_realtime_clock() -> Self {
        Self::get_clocks()
            .find(|c| c.id == libc::CLOCK_REALTIME)
            .unwrap()
    }

    pub fn get_from_file(filename: &str) -> Result<Self, i32> {
        let filename_c = CString::new(filename).unwrap();
        let fd = unsafe { libc::open(filename_c.as_ptr(), libc::O_RDWR) };
        if fd == -1 {
            return Err(unsafe { *libc::__errno_location() });
        }

        // TODO: Add a more reasonable clock quality
        Ok(Self {
            id: ((!(fd as libc::clockid_t)) << 3) | 3,
            name: filename.into(),
            quality: ClockQuality {
                clock_class: 248,
                clock_accuracy: ClockAccuracy::MS10,
                offset_scaled_log_variance: 0xffff,
            },
        })
    }

    pub fn quality(&self) -> ClockQuality {
        self.quality
    }

    pub fn set_leap_seconds(&self, leap_61: bool, leap_59: bool) -> Result<(), Error> {
        let leap_status = if leap_61 {
            LeapIndicator::Leap61
        } else if leap_59 {
            LeapIndicator::Leap59
        } else {
            LeapIndicator::NoWarning
        };

        self.status_update(leap_status)
    }

    fn status_update(&self, leap_status: LeapIndicator) -> Result<(), Error> {
        let mut timex = EMPTY_TIMEX;
        self.adjtime(&mut timex)?;

        // we will update the status
        timex.modes = libc::MOD_STATUS;

        // and add back in what is needed.
        match leap_status {
            LeapIndicator::NoWarning => {}
            LeapIndicator::Leap61 => timex.status |= libc::STA_INS,
            LeapIndicator::Leap59 => timex.status |= libc::STA_DEL,
            LeapIndicator::Unknown => timex.status |= libc::STA_UNSYNC,
        }

        self.adjtime(&mut timex)
    }

    pub fn get_timespec(&self) -> std::io::Result<libc::timespec> {
        let mut time = EMPTY_TIMESPEC;

        cerr(unsafe { libc::clock_gettime(self.id, &mut time as *mut _) })?;

        Ok(time)
    }

    pub fn get_time(&self) -> std::io::Result<Instant> {
        let timespec = self.get_timespec()?;

        let secs = Instant::from_secs(timespec.tv_sec.unsigned_abs() as _);
        let nanos = Duration::from_nanos(timespec.tv_nsec as _);

        Ok(secs + nanos)
    }
}

impl Display for RawLinuxClock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        const SECS_IN_DAY: libc::time_t = 24 * 60 * 60;

        let mut timespec = EMPTY_TIMESPEC;
        let time = match unsafe { libc::clock_gettime(self.id, &mut timespec as *mut _) } {
            -1 => None,
            _ => Some(timespec),
        };

        let mut timespec = EMPTY_TIMESPEC;
        let resolution = match unsafe { libc::clock_getres(self.id, &mut timespec as *mut _) } {
            -1 => None,
            _ => Some(timespec),
        };

        write!(f, "{:<15}: ", self.name)?;
        match time {
            Some(time) => {
                write!(f, "{:10}.{:03} (", time.tv_sec, time.tv_nsec / 1000000)?;
                let days = time.tv_sec / SECS_IN_DAY;
                if days > 0 {
                    write!(f, "{days} days + ")?;
                }

                let h = (time.tv_sec % SECS_IN_DAY) / 3600;
                let m = (time.tv_sec % 3600) / 60;
                let s = time.tv_sec % 60;

                writeln!(f, "{h:2}h {m:2}m {s:2}s)",)?;
            }
            None => writeln!(f, "TIME ERROR")?,
        }

        match resolution {
            Some(resolution) => writeln!(
                f,
                "     resolution: {:10}.{:09}",
                resolution.tv_sec, resolution.tv_nsec
            )?,
            None => writeln!(f, "     resolution: RESOLUTION ERROR")?,
        }

        Ok(())
    }
}

#[derive(Debug, Copy, Clone, thiserror::Error)]
pub enum Error {
    #[error("Insufficient permissions to interact with the clock.")]
    NoPermission,
    #[error("Invalid operation requested")]
    Invalid,
    #[error("Clock device has gone away")]
    NoDevice,
    #[error("Clock operation requested is not supported by operating system.")]
    NotSupported,
    #[error("Invalid clock path")]
    InvalidClockPath,
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

// Convert those error numbers that can occur for the ntp_gettime and
// ntp_adjtimex calls
fn convert_errno() -> Error {
    match error_number() {
        libc::EINVAL => Error::Invalid,
        // The documentation is a bit unclear if this can happen with
        // non-dynamic clocks like the ntp kapi clock, however lets
        // deal with it just in case.
        libc::ENODEV => Error::NoDevice,
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

/// Turn a C failure (-1 is returned) into a rust Result
pub(crate) fn cerr(t: libc::c_int) -> std::io::Result<libc::c_int> {
    match t {
        -1 => Err(std::io::Error::last_os_error()),
        _ => Ok(t),
    }
}

const EMPTY_TIMESPEC: libc::timespec = timespec {
    tv_sec: 0,
    tv_nsec: 0,
};

// Libc has no good other way of obtaining this, so let's at least make our
// functions more readable.
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

#[cfg(test)]
mod tests {
    use super::RawLinuxClock;

    #[test]
    fn test_adjust_frequency_timex_identity() {
        let frequency = 1;
        let frequency_multiplier = 1.0;

        let timex = RawLinuxClock::adjust_frequency_timex(frequency, frequency_multiplier);

        assert_eq!(timex.freq, frequency);

        assert_eq!(timex.modes, libc::ADJ_FREQUENCY);
    }

    #[test]
    fn test_adjust_frequency_timex_one_percent() {
        let frequency = 20 << 16;
        let frequency_multiplier = 1.0 + 5e-6;

        let new_frequency =
            RawLinuxClock::adjust_frequency_timex(frequency, frequency_multiplier).freq;

        assert_eq!(new_frequency, 983047);
    }

    #[test]
    fn test_adjust_frequency_timex_clamp_low() {
        let frequency = 20 << 16;
        let frequency_multiplier = 0.5;

        let new_frequency =
            RawLinuxClock::adjust_frequency_timex(frequency, frequency_multiplier).freq;

        assert_eq!(new_frequency, (500 << 16) - 1);
    }

    #[test]
    fn test_adjust_frequency_timex_clamp_high() {
        let frequency = 20 << 16;
        let frequency_multiplier = 1.5;

        let new_frequency =
            RawLinuxClock::adjust_frequency_timex(frequency, frequency_multiplier).freq;

        assert_eq!(new_frequency, -((500 << 16) - 1));
    }
}
