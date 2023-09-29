//! Implementation of the abstract clock for the linux platform

use std::path::Path;

use clock_steering::{unix::UnixClock, TimeOffset};
use statime::{Clock, Duration, Time, TimePropertiesDS};

#[derive(Debug, Clone)]
pub struct LinuxClock {
    pub clock: clock_steering::unix::UnixClock,
}

impl LinuxClock {
    pub const CLOCK_REALTIME: Self = Self {
        clock: UnixClock::CLOCK_REALTIME,
    };

    pub fn open(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let clock = UnixClock::open(path)?;

        Ok(Self { clock })
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

    fn step_clock(&self, offset: TimeOffset) -> Result<clock_steering::Timestamp, Self::Error> {
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

fn time_from_timestamp(timestamp: clock_steering::Timestamp, fallback: Time) -> Time {
    let Ok(seconds): Result<u64, _> = timestamp.seconds.try_into() else {
        return fallback;
    };

    let nanos = seconds * 1_000_000_000 + timestamp.nanos as u64;
    Time::from_nanos_subnanos(nanos, 0)
}

impl Clock for LinuxClock {
    type Error = clock_steering::unix::Error;

    fn now(&self) -> Time {
        use clock_steering::Clock;

        let timestamp = self.clock.now().unwrap();
        time_from_timestamp(timestamp, Time::from_fixed_nanos(0))
    }

    fn set_frequency(&mut self, freq: f64) -> Result<Time, Self::Error> {
        use clock_steering::Clock;
        log::trace!("Setting clock frequency to {:e}ppm", freq);
        let timestamp = self.clock.set_frequency(freq)?;
        Ok(time_from_timestamp(timestamp, statime::Clock::now(self)))
    }

    fn step_clock(&mut self, time_offset: Duration) -> Result<Time, Self::Error> {
        use clock_steering::Clock;

        // Since we want nanos to be in [0,1_000_000_000), we need
        // euclidean division and remainder.
        let offset_nanos: i128 = time_offset.nanos_rounded();
        let offset = TimeOffset {
            seconds: offset_nanos
                .div_euclid(1_000_000_000)
                .try_into()
                .expect("Unexpected jump larger than 2^64 seconds"),
            nanos: offset_nanos.rem_euclid(1_000_000_000) as _, // Result will always fit in u32
        };

        log::trace!(
            "Stepping clock {:e}ns",
            (offset.seconds as f64) * 1e9 + (offset.nanos as f64)
        );

        let timestamp = self.clock.step_clock(offset)?;
        Ok(time_from_timestamp(timestamp, statime::Clock::now(self)))
    }

    fn set_properties(&mut self, _time_properties: &TimePropertiesDS) -> Result<(), Self::Error> {
        // For now just ignore these

        Ok(())
    }
}

pub fn libc_timespec_into_instant(spec: libc::timespec) -> Time {
    Time::from_fixed_nanos(spec.tv_sec as i128 * 1_000_000_000i128 + spec.tv_nsec as i128)
}
