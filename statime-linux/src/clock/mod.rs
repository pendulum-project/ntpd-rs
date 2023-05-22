//! Implementation of the abstract clock for the linux platform

use fixed::traits::LossyInto;
pub use raw::RawLinuxClock;
use statime::{Clock, ClockQuality, Duration, Instant, TimePropertiesDS, Timer};

mod raw;
mod timex;

#[derive(Debug, Clone)]
pub enum Error {
    LinuxError(i32),
}

#[derive(Debug, Clone)]
pub struct LinuxClock {
    clock: RawLinuxClock,
}

impl LinuxClock {
    pub fn new(clock: RawLinuxClock) -> Self {
        Self { clock }
    }

    pub fn timespec(&self) -> std::io::Result<libc::timespec> {
        self.clock.get_timespec()
    }
}

impl Clock for LinuxClock {
    type Error = Error;

    fn now(&self) -> Instant {
        self.clock.get_time().unwrap()
    }

    fn quality(&self) -> ClockQuality {
        self.clock.quality()
    }

    fn adjust(
        &mut self,
        time_offset: Duration,
        frequency_multiplier: f64,
        time_properties: &TimePropertiesDS,
    ) -> Result<(), Self::Error> {
        if time_properties.is_ptp() {
            self.clock
                .set_leap_seconds(time_properties.leap61(), time_properties.leap59())
                .map_err(Error::LinuxError)?;
        }

        let time_offset_float: f64 = time_offset.nanos().lossy_into();

        self.clock
            .adjust_clock(time_offset_float / 1e9, frequency_multiplier)
            .map_err(Error::LinuxError)
    }
}

pub struct LinuxTimer;

impl Timer for LinuxTimer {
    async fn after(&self, duration: Duration) {
        tokio::time::sleep(duration.into()).await
    }
}

pub fn libc_timespec_into_instant(spec: libc::timespec) -> Instant {
    Instant::from_fixed_nanos(spec.tv_sec as i128 * 1_000_000_000i128 + spec.tv_nsec as i128)
}
