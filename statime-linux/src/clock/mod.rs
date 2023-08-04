//! Implementation of the abstract clock for the linux platform

use std::path::Path;

use clock_steering::unix::UnixClock;
use statime::{Clock, Duration, Time, TimePropertiesDS};

#[derive(Debug, Clone)]
pub struct LinuxClock {
    clock: clock_steering::unix::UnixClock,
}

impl LinuxClock {
    pub const CLOCK_REALTIME: Self = Self {
        clock: UnixClock::CLOCK_REALTIME,
    };

    pub fn open(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let clock = UnixClock::open(path)?;

        Ok(Self { clock })
    }

    pub fn timespec(&self) -> std::io::Result<libc::timespec> {
        use clock_steering::Clock;

        let now = self.clock.now()?;
        Ok(libc::timespec {
            tv_sec: now.seconds,
            tv_nsec: now.nanos as _,
        })
    }
}

impl clock_steering::Clock for LinuxClock {
    type Error = clock_steering::unix::Error;

    fn now(&self) -> Result<clock_steering::Timestamp, Self::Error> {
        self.clock.now()
    }

    fn resolution(&self) -> Result<clock_steering::Timestamp, Self::Error> {
        self.clock.resolution()
    }

    fn set_frequency(&self, frequency: f64) -> Result<clock_steering::Timestamp, Self::Error> {
        self.clock.set_frequency(frequency)
    }

    fn step_clock(
        &self,
        offset: std::time::Duration,
    ) -> Result<clock_steering::Timestamp, Self::Error> {
        self.clock.step_clock(offset)
    }

    fn set_leap_seconds(
        &self,
        leap_status: clock_steering::LeapIndicator,
    ) -> Result<(), Self::Error> {
        self.clock.set_leap_seconds(leap_status)
    }

    fn error_estimate_update(
        &self,
        estimated_error: std::time::Duration,
        maximum_error: std::time::Duration,
    ) -> Result<(), Self::Error> {
        self.clock
            .error_estimate_update(estimated_error, maximum_error)
    }
}

impl Clock for LinuxClock {
    type Error = clock_steering::unix::Error;

    fn now(&self) -> Time {
        use clock_steering::Clock;

        let timestamp = self.clock.now().unwrap();
        let seconds: u64 = timestamp.seconds.try_into().unwrap();

        let nanos = seconds * 1_000_000_000 + timestamp.nanos as u64;
        Time::from_nanos_subnanos(nanos, timestamp.subnanos)
    }

    fn adjust(
        &mut self,
        time_offset: Duration,
        frequency_multiplier: f64,
        time_properties: &TimePropertiesDS,
    ) -> Result<(), Self::Error> {
        use clock_steering::Clock;

        let leap_indicator = match time_properties.leap_indicator() {
            statime::LeapIndicator::NoLeap => clock_steering::LeapIndicator::NoWarning,
            statime::LeapIndicator::Leap61 => clock_steering::LeapIndicator::Leap61,
            statime::LeapIndicator::Leap59 => clock_steering::LeapIndicator::Leap59,
        };

        if time_properties.is_ptp() {
            self.clock.set_leap_seconds(leap_indicator)?
        }

        // a statime Duration has 96 bits to store nanoseconds, but the linux api only
        // has 64. So potentially we lose information, but more than 64 bits of
        // nanoseconds seems very unlikely.
        let offset = std::time::Duration::from_nanos(time_offset.nanos_lossy() as u64);

        log::trace!(
            "Adjusting clock: {:e}ns, 1 + {:e}x",
            offset.as_nanos(),
            frequency_multiplier - 1.0
        );

        self.clock.adjust_frequency(frequency_multiplier)?;
        self.clock.step_clock(offset)?;

        Ok(())
    }
}

pub fn libc_timespec_into_instant(spec: libc::timespec) -> Time {
    Time::from_fixed_nanos(spec.tv_sec as i128 * 1_000_000_000i128 + spec.tv_nsec as i128)
}
