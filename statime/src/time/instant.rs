use super::duration::Duration;
use crate::datastructures::common::Timestamp;
use fixed::{traits::ToFixed, types::U96F32};
use std::{
    fmt::Display,
    ops::{Add, AddAssign, Sub, SubAssign},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct Instant {
    /// Time in nanos
    inner: U96F32,
}

impl Instant {
    pub fn from_secs(secs: u64) -> Self {
        let inner = secs.to_fixed::<U96F32>() * 1_000_000_000.to_fixed::<U96F32>();
        Self { inner }
    }
    pub fn from_millis(millis: u64) -> Self {
        let inner = millis.to_fixed::<U96F32>() * 1_000_000.to_fixed::<U96F32>();
        Self { inner }
    }
    pub fn from_micros(micros: u64) -> Self {
        let inner = micros.to_fixed::<U96F32>() * 1_000.to_fixed::<U96F32>();
        Self { inner }
    }
    pub fn from_nanos(nanos: u64) -> Self {
        let inner = nanos.to_fixed::<U96F32>();
        Self { inner }
    }
    pub fn from_fixed_nanos<F: ToFixed>(nanos: F) -> Self {
        Self {
            inner: nanos.to_fixed(),
        }
    }
    pub fn nanos(&self) -> U96F32 {
        self.inner
    }
    pub fn sub_nanos(&self) -> u32 {
        (self.inner % 1_000_000_000.to_fixed::<U96F32>()).to_num()
    }
    pub fn secs(&self) -> u64 {
        (self.inner / 1_000_000_000.to_fixed::<U96F32>()).to_num()
    }

    pub fn from_timestamp(ts: &Timestamp) -> Self {
        Self::from_fixed_nanos(ts.seconds as i128 * 1_000_000_000i128 + ts.nanos as i128)
    }

    pub fn to_timestamp(&self) -> Timestamp {
        Timestamp {
            seconds: self.secs(),
            nanos: self.sub_nanos(),
        }
    }
}

impl Add<Duration> for Instant {
    type Output = Instant;

    fn add(self, rhs: Duration) -> Self::Output {
        if rhs.nanos().is_negative() {
            Instant {
                inner: self.nanos() - rhs.nanos().unsigned_abs(),
            }
        } else {
            Instant {
                inner: self.nanos() + rhs.nanos().unsigned_abs(),
            }
        }
    }
}

impl AddAssign<Duration> for Instant {
    fn add_assign(&mut self, rhs: Duration) {
        *self = *self + rhs;
    }
}

impl Sub<Duration> for Instant {
    type Output = Instant;

    fn sub(self, rhs: Duration) -> Self::Output {
        self + -rhs
    }
}

impl SubAssign<Duration> for Instant {
    fn sub_assign(&mut self, rhs: Duration) {
        *self = *self - rhs;
    }
}

impl Sub<Instant> for Instant {
    type Output = Duration;

    fn sub(self, rhs: Instant) -> Self::Output {
        Duration::from_fixed_nanos(self.inner) - Duration::from_fixed_nanos(rhs.inner)
    }
}

impl Display for Instant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values() {
        assert_eq!(
            Instant::from_secs(10).nanos(),
            10_000_000_000u64.to_fixed::<U96F32>()
        );
        assert_eq!(
            Instant::from_millis(10).nanos(),
            10_000_000u64.to_fixed::<U96F32>()
        );
        assert_eq!(
            Instant::from_micros(10).nanos(),
            10_000u64.to_fixed::<U96F32>()
        );
        assert_eq!(Instant::from_nanos(10).nanos(), 10u64.to_fixed::<U96F32>());
        assert_eq!(
            Instant::from_fixed_nanos(10.123f64).nanos(),
            10.123f64.to_fixed::<U96F32>()
        );
        assert_eq!(Instant::from_secs(10).secs(), 10);
        assert_eq!(Instant::from_millis(10).secs(), 0);
        assert_eq!(Instant::from_millis(1001).secs(), 1);
    }
}
