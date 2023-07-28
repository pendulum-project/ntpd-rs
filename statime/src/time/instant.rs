//! Implementation of the [Time] type

use core::{
    fmt::Display,
    ops::{Add, AddAssign, Sub, SubAssign},
};

use fixed::{
    traits::{LosslessTryInto, LossyInto, ToFixed},
    types::{U112F16, U96F32},
};

use super::duration::Duration;
use crate::datastructures::common::WireTimestamp;

/// Time represents a specific moment in time.
///
/// The starting 0 point depends on the timescale being used by PTP, but
/// for most uses will be the unix epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct Time {
    /// Time in nanos since start of timescale
    inner: U96F32,
}

impl Time {
    /// Create an instance with the given amount of seconds from the origin
    pub fn from_secs(secs: u64) -> Self {
        let inner = secs.to_fixed::<U96F32>() * 1_000_000_000.to_fixed::<U96F32>();
        Self { inner }
    }
    /// Create an instance with the given amount of milliseconds from the origin
    pub fn from_millis(millis: u64) -> Self {
        let inner = millis.to_fixed::<U96F32>() * 1_000_000.to_fixed::<U96F32>();
        Self { inner }
    }
    /// Create an instance with the given amount of microseconds from the origin
    pub fn from_micros(micros: u64) -> Self {
        let inner = micros.to_fixed::<U96F32>() * 1_000.to_fixed::<U96F32>();
        Self { inner }
    }
    /// Create an instance with the given amount of nanoseconds from the origin
    pub fn from_nanos(nanos: u64) -> Self {
        let inner = nanos.to_fixed::<U96F32>();
        Self { inner }
    }
    /// Create an instance with the given amount of nanoseconds from the origin,
    /// using a fixed point number so the subnanoseconds can be specified as
    /// well
    pub fn from_fixed_nanos<F: ToFixed>(nanos: F) -> Self {
        Self {
            inner: nanos.to_fixed(),
        }
    }

    pub fn from_nanos_subnanos(nanos: u64, subnanos: u32) -> Self {
        let bits = (nanos as u128) << 32 | (subnanos as u128);
        let inner = U96F32::from_bits(bits);
        Self { inner }
    }

    /// Get the total amount of nanoseconds since the origin
    pub fn nanos(&self) -> U96F32 {
        self.inner
    }
    /// Get all the nanoseconds that are under a second
    pub fn subsec_nanos(&self) -> u32 {
        (self.inner % 1_000_000_000.to_fixed::<U96F32>()).to_num()
    }
    /// Get the total amount of seconds since the origin
    pub fn secs(&self) -> u64 {
        (self.inner / 1_000_000_000.to_fixed::<U96F32>()).to_num()
    }
    // Get the subnanosecond amount
    pub fn subnano(&self) -> crate::datastructures::common::TimeInterval {
        let inter: U112F16 = self.inner.frac().lossy_into();
        // unwrap is ok since always less than 1.
        crate::datastructures::common::TimeInterval(inter.lossless_try_into().unwrap())
    }
}

impl From<WireTimestamp> for Time {
    fn from(ts: WireTimestamp) -> Self {
        Self::from_fixed_nanos(ts.seconds as i128 * 1_000_000_000i128 + ts.nanos as i128)
    }
}

impl Add<Duration> for Time {
    type Output = Time;

    fn add(self, rhs: Duration) -> Self::Output {
        if rhs.nanos().is_negative() {
            Time {
                inner: self.nanos() - rhs.nanos().unsigned_abs(),
            }
        } else {
            Time {
                inner: self.nanos() + rhs.nanos().unsigned_abs(),
            }
        }
    }
}

impl AddAssign<Duration> for Time {
    fn add_assign(&mut self, rhs: Duration) {
        *self = *self + rhs;
    }
}

impl Sub<Duration> for Time {
    type Output = Time;

    fn sub(self, rhs: Duration) -> Self::Output {
        self + -rhs
    }
}

impl SubAssign<Duration> for Time {
    fn sub_assign(&mut self, rhs: Duration) {
        *self = *self - rhs;
    }
}

impl Sub<Time> for Time {
    type Output = Duration;

    fn sub(self, rhs: Time) -> Self::Output {
        Duration::from_fixed_nanos(self.inner) - Duration::from_fixed_nanos(rhs.inner)
    }
}

impl Display for Time {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values() {
        assert_eq!(
            Time::from_secs(10).nanos(),
            10_000_000_000u64.to_fixed::<U96F32>()
        );
        assert_eq!(
            Time::from_millis(10).nanos(),
            10_000_000u64.to_fixed::<U96F32>()
        );
        assert_eq!(
            Time::from_micros(10).nanos(),
            10_000u64.to_fixed::<U96F32>()
        );
        assert_eq!(Time::from_nanos(10).nanos(), 10u64.to_fixed::<U96F32>());
        assert_eq!(
            Time::from_fixed_nanos(10.123f64).nanos(),
            10.123f64.to_fixed::<U96F32>()
        );
        assert_eq!(Time::from_secs(10).secs(), 10);
        assert_eq!(Time::from_millis(10).secs(), 0);
        assert_eq!(Time::from_millis(1001).secs(), 1);
    }
}
