use crate::datastructures::common::TimeInterval;
use fixed::{traits::ToFixed, types::I96F32};
use std::{
    fmt::Display,
    ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Rem, RemAssign, Sub, SubAssign},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct Duration {
    /// Time in nanos
    inner: I96F32,
}

impl Duration {
    pub fn from_secs(secs: i64) -> Self {
        let inner = secs.to_fixed::<I96F32>() * 1_000_000_000.to_fixed::<I96F32>();
        Self { inner }
    }
    pub fn from_millis(millis: i64) -> Self {
        let inner = millis.to_fixed::<I96F32>() * 1_000_000.to_fixed::<I96F32>();
        Self { inner }
    }
    pub fn from_micros(micros: i64) -> Self {
        let inner = micros.to_fixed::<I96F32>() * 1_000.to_fixed::<I96F32>();
        Self { inner }
    }
    pub fn from_nanos(nanos: i64) -> Self {
        let inner = nanos.to_fixed::<I96F32>();
        Self { inner }
    }

    pub fn from_fixed_nanos<F: ToFixed>(nanos: F) -> Self {
        Self {
            inner: nanos.to_fixed(),
        }
    }

    pub fn nanos(&self) -> I96F32 {
        self.inner
    }

    pub fn secs(&self) -> i64 {
        (self.inner / 1_000_000_000.to_fixed::<I96F32>()).to_num()
    }

    pub fn from_interval(interval: &TimeInterval) -> Self {
        Self::from_fixed_nanos(interval.0)
    }

    pub fn to_interval(&self) -> TimeInterval {
        let val = (self.inner.to_bits() >> 16) as i64;
        TimeInterval(fixed::types::I48F16::from_bits(val))
    }

    pub fn from_log_interval(log_interval: i8) -> Self {
        let seconds = 2.0f64.powi(log_interval as i32);
        let nanos = seconds * 1_000_000_000.0;
        Self::from_fixed_nanos(nanos)
    }

    pub fn abs(self) -> Duration {
        Duration::from_fixed_nanos(self.nanos().abs())
    }
}

impl Neg for Duration {
    type Output = Duration;

    fn neg(self) -> Self::Output {
        Self::from_fixed_nanos(-self.nanos())
    }
}

impl Add for Duration {
    type Output = Duration;

    fn add(self, rhs: Duration) -> Self::Output {
        Duration {
            inner: self.nanos() + rhs.nanos(),
        }
    }
}

impl AddAssign for Duration {
    fn add_assign(&mut self, rhs: Duration) {
        *self = *self + rhs;
    }
}

impl Sub for Duration {
    type Output = Duration;

    fn sub(self, rhs: Duration) -> Self::Output {
        self + -rhs
    }
}

impl SubAssign for Duration {
    fn sub_assign(&mut self, rhs: Duration) {
        *self = *self - rhs;
    }
}

impl<TF: ToFixed> Mul<TF> for Duration {
    type Output = Duration;

    fn mul(self, rhs: TF) -> Self::Output {
        Duration::from_fixed_nanos(self.nanos() * rhs.to_fixed::<I96F32>())
    }
}

impl<TF: ToFixed> MulAssign<TF> for Duration {
    fn mul_assign(&mut self, rhs: TF) {
        *self = *self * rhs
    }
}

impl<TF: ToFixed> Div<TF> for Duration {
    type Output = Duration;

    fn div(self, rhs: TF) -> Self::Output {
        Duration::from_fixed_nanos(self.nanos() / rhs.to_fixed::<I96F32>())
    }
}

impl<TF: ToFixed> DivAssign<TF> for Duration {
    fn div_assign(&mut self, rhs: TF) {
        *self = *self / rhs
    }
}

impl Rem for Duration {
    type Output = Duration;

    fn rem(self, rhs: Self) -> Self::Output {
        Duration::from_fixed_nanos(self.nanos() % rhs.nanos())
    }
}

impl RemAssign for Duration {
    fn rem_assign(&mut self, rhs: Self) {
        *self = *self % rhs
    }
}

impl Display for Duration {
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
            Duration::from_secs(10).nanos(),
            10_000_000_000u64.to_fixed::<I96F32>()
        );
        assert_eq!(
            Duration::from_secs(-10).nanos(),
            -10_000_000_000u64.to_fixed::<I96F32>()
        );
        assert_eq!(
            Duration::from_millis(10).nanos(),
            10_000_000u64.to_fixed::<I96F32>()
        );
        assert_eq!(
            Duration::from_micros(10).nanos(),
            10_000u64.to_fixed::<I96F32>()
        );
        assert_eq!(Duration::from_nanos(10).nanos(), 10u64.to_fixed::<I96F32>());
        assert_eq!(
            Duration::from_fixed_nanos(10.123f64).nanos(),
            10.123f64.to_fixed::<I96F32>()
        );
        assert_eq!(Duration::from_secs(10).secs(), 10);
        assert_eq!(Duration::from_millis(10).secs(), 0);
        assert_eq!(Duration::from_millis(1001).secs(), 1);
    }

    #[test]
    fn log_interval() {
        assert_eq!(Duration::from_log_interval(0), Duration::from_secs(1));
        assert_eq!(Duration::from_log_interval(-1), Duration::from_millis(500));
        assert_eq!(Duration::from_log_interval(1), Duration::from_secs(2));
    }

    #[test]
    fn interval() {
        assert_eq!(
            Duration::from_fixed_nanos(2.25f64),
            Duration::from_interval(&TimeInterval(2.25f64.to_fixed()))
        );
        assert_eq!(
            Duration::from_fixed_nanos(2.25f64).to_interval(),
            TimeInterval(2.25f64.to_fixed())
        );
    }
}
