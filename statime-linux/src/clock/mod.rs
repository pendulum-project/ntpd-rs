//! Implementation of the abstract clock for the linux platform

use std::path::Path;

use clock_steering::{unix::UnixClock, TimeOffset};
use statime::{Clock, Duration, Time, TimePropertiesDS};

#[derive(Debug, Clone)]
pub struct LinuxClock {
    clock: clock_steering::unix::UnixClock,
    is_tai: bool,
}

impl LinuxClock {
    pub const CLOCK_TAI: Self = Self {
        clock: UnixClock::CLOCK_TAI,
        is_tai: true,
    };

    pub fn open(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let clock = UnixClock::open(path)?;

        Ok(Self {
            clock,
            is_tai: false,
        })
    }

    /// Return three timestamps t1 t2 and t3 minted in that order.
    /// T1 and T3 are minted using the system TAI clock and T2 by the hardware
    /// clock
    pub fn system_offset(&self) -> Result<(Time, Time, Time), clock_steering::unix::Error> {
        // The clock crate's system offset gives the T1 and T3 timestamps on the
        // CLOCK_REALTIME timescale which is UTC, not TAI, so we need to correct
        // here.
        self.clock.system_offset().map(|(mut t1, t2, mut t3)| {
            let tai_offset = UnixClock::CLOCK_REALTIME.get_tai().unwrap();
            t1.seconds += tai_offset as libc::time_t;
            t3.seconds += tai_offset as libc::time_t;
            (
                clock_timestamp_to_time(t1),
                clock_timestamp_to_time(t2),
                clock_timestamp_to_time(t3),
            )
        })
    }

    pub fn get_tai_offset(&self) -> Result<i32, clock_steering::unix::Error> {
        if self.is_tai {
            UnixClock::CLOCK_REALTIME.get_tai()
        } else {
            self.clock.get_tai()
        }
    }
}

fn clock_timestamp_to_time(t: clock_steering::Timestamp) -> statime::Time {
    Time::from_nanos((t.seconds as u64) * 1_000_000_000 + (t.nanos as u64))
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
        let timestamp = if self.is_tai {
            // Clock tai can't directly adjust frequency, so drive this through
            // clock_realtime and adjust the received timestamp
            let mut ts = UnixClock::CLOCK_REALTIME.set_frequency(freq)?;
            ts.seconds += UnixClock::CLOCK_REALTIME.get_tai()? as libc::time_t;
            ts
        } else {
            self.clock.set_frequency(freq)?
        };
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

        let timestamp = if self.is_tai {
            // Clock tai can't directly step, so drive this through clock_realtime
            // and adjust the received timestamp
            let mut ts = UnixClock::CLOCK_REALTIME.step_clock(offset)?;
            ts.seconds += UnixClock::CLOCK_REALTIME.get_tai()? as libc::time_t;
            ts
        } else {
            self.clock.step_clock(offset)?
        };
        Ok(time_from_timestamp(timestamp, statime::Clock::now(self)))
    }

    fn set_properties(&mut self, time_properties: &TimePropertiesDS) -> Result<(), Self::Error> {
        use clock_steering::Clock;

        // These properties should always be communicated to the system clock.

        if let Some(offset) = time_properties.utc_offset() {
            UnixClock::CLOCK_REALTIME.set_tai(offset as _)?;
        }

        UnixClock::CLOCK_REALTIME.set_leap_seconds(match time_properties.leap_indicator() {
            statime::LeapIndicator::NoLeap => clock_steering::LeapIndicator::NoWarning,
            statime::LeapIndicator::Leap61 => clock_steering::LeapIndicator::Leap61,
            statime::LeapIndicator::Leap59 => clock_steering::LeapIndicator::Leap59,
        })?;

        Ok(())
    }
}

pub fn libc_timespec_into_instant(spec: libc::timespec) -> Time {
    Time::from_fixed_nanos(spec.tv_sec as i128 * 1_000_000_000i128 + spec.tv_nsec as i128)
}
