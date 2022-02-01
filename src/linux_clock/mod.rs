use self::timex::{StatusFlags, Timex};
use crate::linux_clock::timex::AdjustFlags;
use libc::{clockid_t, timespec};
use std::{fmt::Display, ops::DerefMut};

mod timex;

#[cfg(target_pointer_width = "64")]
type Fixed = fixed::types::I48F16;
#[cfg(target_pointer_width = "32")]
type Fixed = fixed::types::I16F16;
#[cfg(target_pointer_width = "64")]
type Int = i64;
#[cfg(target_pointer_width = "32")]
type Int = i32;

/// A type for precisely adjusting the time of a linux clock.
/// Not every clock supports the used API so that's a bit trial and error.
///
/// Probably best used with the CLOCK_REALTIME clock.
/// 
/// Using the clocks probably requires root access.
///
/// # Example
///
/// ```no_run
/// use ptp::linux_clock::LinuxClock;
/// 
/// println!("Available clocks:");
/// for clock in LinuxClock::get_clocks() {
///     println!("{}", clock);
/// }
///
/// let mut test_clock = LinuxClock::get_realtime_clock();
/// test_clock.adjust_clock(0.000_001, 1.000_000_001).unwrap();
/// ```
#[derive(Debug, Clone)]
pub struct LinuxClock {
    id: clockid_t,
    name: String,
}
impl LinuxClock {
    /// https://manpages.debian.org/testing/manpages-dev/ntp_adjtime.3.en.html#DESCRIPTION
    fn get_clock_state(&self) -> Result<(Timex, ClockState), i32> {
        let mut value = Timex::new();
        match unsafe { libc::clock_adjtime(self.id, value.deref_mut() as *mut _) } {
            libc::TIME_OK => Ok((value, ClockState::OK)),
            libc::TIME_INS => Ok((value, ClockState::INS)),
            libc::TIME_DEL => Ok((value, ClockState::DEL)),
            libc::TIME_OOP => Ok((value, ClockState::OOP)),
            libc::TIME_WAIT => Ok((value, ClockState::WAIT)),
            libc::TIME_ERROR => Ok((value, ClockState::ERROR)),
            -1 => {
                let errno = unsafe { *libc::__errno_location() };
                Err(errno)
            }
            _ => unreachable!(),
        }
    }

    /// Adjusts the clock
    /// 
    /// - The time_offset is given in seconds.
    /// - The frequency_multiplier is the value that the *current* frequency should be multiplied with to get to the target frequency.
    /// 
    /// For example, if the clock is at 10.0 mhz, but should run at 10.1 mhz, then the frequency_multiplier should be 1.01.
    /// 
    /// If the time offset is higher than 0.5 seconds, then the clock will be set directly and no frequency change will be made.
    pub fn adjust_clock(&mut self, time_offset: f64, frequency_multiplier: f64) -> Result<(), i32> {
        let (current_timex, _clock_state) = self.get_clock_state()?;

        if time_offset.abs() > 0.5 {
            // The time offset is more than we can change with precision, so we're just going to set the current time

            let current_nanos = if current_timex.get_status().contains(StatusFlags::NANO) {
                current_timex.time.tv_usec
            } else {
                current_timex.time.tv_usec * 1000
            };

            // We need to be careful. The nanos may only be 1_000_000_000 at the most
            let new_nanos = current_nanos + (time_offset.fract() * 1_000_000_000.0) as Int;
            let new_seconds =
                current_timex.time.tv_sec + time_offset.floor() as Int + new_nanos / 1_000_000_000;

            let new_time = libc::timespec {
                tv_sec: new_seconds,
                tv_nsec: new_nanos % 1_000_000_000,
            };

            // Set the clock time using the 'normal' clock api
            let error = unsafe { libc::clock_settime(self.id, &new_time as *const _) };
            match error {
                -1 => Err(unsafe { *libc::__errno_location() }),
                _ => Ok(()),
            }
        } else {
            // We do an offset with precision
            let mut new_timex = current_timex.clone();

            new_timex.set_status(
                StatusFlags::PLL // We want to change the PLL, a major component in the clock circuit
                    | StatusFlags::PPSFREQ // We want the PPS signal to change as well
                    | StatusFlags::PPSTIME // The PPS time should be changed
                    | StatusFlags::FREQHOLD, // We want no automatic frequency updates
            );

            new_timex.set_mode(
                AdjustFlags::SETOFFSET // We have an offset to set
                | AdjustFlags::FREQUENCY // We'll be setting the frequency as well
                | AdjustFlags::NANO // We're using nanoseconds
            );

            // Start with a seconds value of 0 and express the full time offset in nanos
            new_timex.time.tv_sec = 0;
            new_timex.time.tv_usec = (time_offset * 1_000_000_000.0) as Int;

            // The nanos must not be negative. In that case the timestamp must be delivered as a negative seconds with a postive nanos value
            while new_timex.time.tv_usec < 0 {
                new_timex.time.tv_sec -= 1;
                new_timex.time.tv_usec += 1_000_000_000;
            }

            // We need to change the ppm value to a speed factor so we can use multiplication to get the new frequency
            let current_ppm = current_timex.get_frequency();
            // The ppm is an offset from the main frequency, so it's the base +- the ppm expressed as a percentage.
            // Ppm is in the opposite direction from the speed factor. A postive ppm means the clock is running slower, so we use its negative.
            let current_frequency_multiplier = 1.0 + -current_ppm.to_num::<f64>() / 1_000_000.0;
            // Now multiply the frequencies
            let new_frequency_multiplier = current_frequency_multiplier * frequency_multiplier;
            // Get back the new ppm value by subtracting the 1.0 base from it, changing the percentage to the ppm again and then taking the negative of that.
            let new_ppm = -Fixed::from_num((new_frequency_multiplier - 1.0) * 1_000_000.0);

            new_timex.set_frequency(new_ppm);

            // Adjust the clock time and handle its errors
            let error = unsafe { libc::clock_adjtime(self.id, new_timex.deref_mut() as *mut _) };
            match error {
                -1 => Err(unsafe { *libc::__errno_location() }),
                _ => Ok(()),
            }
        }
    }

    pub fn get_clocks() -> impl Iterator<Item = Self> {
        const CLOCKS: [(clockid_t, &str); 11] = [
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

        CLOCKS.into_iter().map(|(id, name)| Self {
            id,
            name: name.into(),
        })
    }

    pub fn get_realtime_clock() -> Self {
        Self::get_clocks().find(|c| c.id == libc::CLOCK_REALTIME).unwrap()
    }
}

impl Display for LinuxClock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        const SECS_IN_DAY: Int = 24 * 60 * 60;

        let mut time = Some(timespec {
            tv_sec: 0,
            tv_nsec: 0,
        });
        if unsafe { libc::clock_gettime(self.id, time.as_mut().unwrap_unchecked() as *mut _) } == -1
        {
            time = None;
        }

        let mut resolution = Some(timespec {
            tv_sec: 0,
            tv_nsec: 0,
        });
        if unsafe { libc::clock_getres(self.id, resolution.as_mut().unwrap_unchecked() as *mut _) }
            == -1
        {
            resolution = None;
        }

        write!(f, "{:<15}: ", self.name)?;
        match time {
            Some(time) => {
                write!(f, "{:10}.{:03} (", time.tv_sec, time.tv_nsec / 1000000)?;
                let days = time.tv_sec / SECS_IN_DAY;
                if days > 0 {
                    write!(f, "{} days + ", days)?;
                }
                writeln!(
                    f,
                    "{:2}h {:2}m {:2}s)",
                    (time.tv_sec % SECS_IN_DAY) / 3600,
                    (time.tv_sec % 3600) / 60,
                    time.tv_sec % 60
                )?;
            }
            None => writeln!(f, "TIME ERROR")?,
        }

        match resolution {
            Some(resolution) => writeln!(
                f,
                "     resolution: {:10}.{:09}",
                resolution.tv_sec, resolution.tv_nsec
            )?,
            None => writeln!(f, "     resolution: RESOLUTION ERROR",)?,
        }

        Ok(())
    }
}

/// Reflects: https://manpages.debian.org/testing/manpages-dev/ntp_adjtime.3.en.html#RETURN_VALUE
#[derive(Debug, Clone)]
pub enum ClockState {
    OK,
    INS,
    DEL,
    OOP,
    WAIT,
    ERROR,
}
