//! Time types useful for time synchronization daemons
//!
//! This module provides time types explicitly designed for use in time
//! synchronization daemons. This includes support for marking the timescale
//! used, as well as support for signed durations, which are useful for
//! representing offsets between clocks.

use core::{
    marker::PhantomData,
    ops::{Add, AddAssign, Div, Mul, MulAssign, Sub, SubAssign},
};

/// A timestamp in the scale `Timescale`.
///
/// Arithmetic on timestamps is implemented as wrapping.
///
/// The timescale ensures that arithmetic done with timescales
/// is done with the correct timescale on both sides. This ensures
/// that for example the following doesn't compile:
///
/// ```compile_fail
/// # use statime_base::{Timestamp, UTC, TAI};
/// let delta = Timestamp::<UTC>::from_seconds_nanos_since_unix_epoch(100, 0) - Timestamp::<TAI>::from_seconds_nanos_since_unix_epoch(50, 0);
/// ```
// The internal value is in units of 2^-64ths of a second, with the UNIX EPOCH as 0
pub struct Timestamp<Timescale>(u128, PhantomData<Timescale>);

/// Marker for the UTC timescale
pub struct UTC;
/// Marker for the TAI timescale
pub struct TAI;

/// A span of time, or a difference of two timestamps.
///
/// Arithmetic on durations is implemented as saturating.
// The internal value is in units of 2^-64ths of a second.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Duration(i128);

impl<A> Timestamp<A> {
    /// Representation of the UNIX EPOCH in this timescale.
    ///
    /// In other words: midnight on the first of januari 1970, as defined in
    /// the given timescale.
    pub const UNIX_EPOCH: Timestamp<A> = Timestamp(0, PhantomData);

    /// Create a new timestamp on the timescale, the given number of seconds
    /// and nanoseconds since the unix epoch.
    #[must_use]
    pub fn from_seconds_nanos_since_unix_epoch(seconds: u64, nanos: u32) -> Timestamp<A> {
        let converted_nanos = (u128::from(nanos) << 64) / 1_000_000_000;
        Timestamp((u128::from(seconds) << 64) + converted_nanos, PhantomData)
    }
}

impl<A> core::fmt::Debug for Timestamp<A> {
    #[expect(
        clippy::cast_precision_loss,
        reason = "Loss of precision isn't important for debug printing."
    )]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_fmt(format_args!(
            "Timestamp<{}>({}s)",
            core::any::type_name::<A>(),
            ((self.0 as f64) / ((1u128 << 64) as f64))
        ))
    }
}

impl<A> Clone for Timestamp<A> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<A> Copy for Timestamp<A> {}

impl<A> PartialEq for Timestamp<A> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<A> Eq for Timestamp<A> {}

impl<A> core::hash::Hash for Timestamp<A> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl Duration {
    /// The length of the duration as a floating point number of seconds.
    #[must_use]
    #[expect(
        clippy::cast_precision_loss,
        reason = "The expressive range of the target type of the operation as a whole is smaller, so precision loss is to be expected."
    )]
    pub fn as_seconds(self) -> f64 {
        (self.0 as f64) / ((1u128 << 64) as f64)
    }

    /// Create a duration from a given number of seconds, plus the given number
    /// of nanoseconds.
    ///
    /// The nanoseconds are always applied in the positive direction, so for
    /// example `from_seconds_nanos(-1, 500_000_000)` represents minus half a
    /// second.
    #[must_use]
    pub fn from_seconds_nanos(seconds: i64, nanos: u32) -> Self {
        let converted_nanos = (i128::from(nanos) << 64) / 1_000_000_000;
        Duration((i128::from(seconds) << 64) + converted_nanos)
    }
}

impl core::fmt::Debug for Duration {
    #[expect(
        clippy::cast_precision_loss,
        reason = "Loss of precision isn't important for debug printing."
    )]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_fmt(format_args!(
            "Duration({}s)",
            ((self.0 as f64) / ((1u128 << 64) as f64))
        ))
    }
}

impl<A> Sub<Timestamp<A>> for Timestamp<A> {
    type Output = Duration;

    fn sub(self, rhs: Timestamp<A>) -> Self::Output {
        Duration(self.0.wrapping_sub(rhs.0).cast_signed())
    }
}

impl<A> Add<Duration> for Timestamp<A> {
    type Output = Timestamp<A>;

    fn add(self, rhs: Duration) -> Self::Output {
        Timestamp(self.0.wrapping_add(rhs.0.cast_unsigned()), PhantomData)
    }
}

impl<A> AddAssign<Duration> for Timestamp<A> {
    fn add_assign(&mut self, rhs: Duration) {
        self.0 = self.0.wrapping_add(rhs.0.cast_unsigned());
    }
}

impl<A> Sub<Duration> for Timestamp<A> {
    type Output = Timestamp<A>;

    fn sub(self, rhs: Duration) -> Self::Output {
        Timestamp(self.0.wrapping_sub(rhs.0.cast_unsigned()), PhantomData)
    }
}

impl<A> SubAssign<Duration> for Timestamp<A> {
    fn sub_assign(&mut self, rhs: Duration) {
        self.0 = self.0.wrapping_sub(rhs.0.cast_unsigned());
    }
}

impl Add<Duration> for Duration {
    type Output = Duration;

    fn add(self, rhs: Duration) -> Self::Output {
        Duration(self.0.saturating_add(rhs.0))
    }
}

impl AddAssign<Duration> for Duration {
    fn add_assign(&mut self, rhs: Duration) {
        self.0 = self.0.saturating_add(rhs.0);
    }
}

impl Sub<Duration> for Duration {
    type Output = Duration;

    fn sub(self, rhs: Duration) -> Self::Output {
        Duration(self.0.saturating_sub(rhs.0))
    }
}

impl SubAssign<Duration> for Duration {
    fn sub_assign(&mut self, rhs: Duration) {
        self.0 = self.0.saturating_sub(rhs.0);
    }
}

macro_rules! duration_mul {
    ($intty:ident) => {
        impl Mul<Duration> for $intty {
            type Output = Duration;

            fn mul(self, rhs: Duration) -> Self::Output {
                Duration(rhs.0.saturating_mul(i128::from(self)))
            }
        }

        impl Mul<$intty> for Duration {
            type Output = Duration;

            fn mul(self, rhs: $intty) -> Self::Output {
                Duration(self.0.saturating_mul(i128::from(rhs)))
            }
        }

        impl MulAssign<$intty> for Duration {
            fn mul_assign(&mut self, rhs: $intty) {
                self.0 = self.0.saturating_mul(i128::from(rhs));
            }
        }
    };
}

macro_rules! duration_div {
    ($intty:ident) => {
        impl Div<$intty> for Duration {
            type Output = Duration;

            fn div(self, rhs: $intty) -> Self::Output {
                Duration(self.0.saturating_div(i128::from(rhs)))
            }
        }
    };
}

duration_mul!(u8);
duration_mul!(i8);
duration_mul!(u16);
duration_mul!(i16);
duration_mul!(u32);
duration_mul!(i32);
duration_mul!(u64);
duration_mul!(i64);

duration_div!(u8);
duration_div!(i8);
duration_div!(u16);
duration_div!(i16);
duration_div!(u32);
duration_div!(i32);
duration_div!(u64);
duration_div!(i64);

#[cfg(test)]
mod tests {
    use core::hash::Hasher;
    use std::hash::DefaultHasher;

    use super::{Duration, Timestamp, UTC};

    #[test]
    fn test_timestamp_creation() {
        assert_eq!(
            Timestamp::<UTC>::from_seconds_nanos_since_unix_epoch(100, 0).0,
            100 << 64
        );
        assert_eq!(
            Timestamp::<UTC>::from_seconds_nanos_since_unix_epoch(0, 250_000_000).0,
            1 << 62
        );
    }

    #[test]
    fn test_timestamp_math() {
        assert_eq!(
            Timestamp::<UTC>::from_seconds_nanos_since_unix_epoch(100, 0)
                - Timestamp::<UTC>::from_seconds_nanos_since_unix_epoch(50, 0),
            Duration(50 << 64)
        );
        assert_eq!(
            Timestamp::<UTC>::from_seconds_nanos_since_unix_epoch(100, 0)
                - Timestamp::<UTC>::from_seconds_nanos_since_unix_epoch(150, 0),
            Duration(-50 << 64)
        );

        assert_eq!(
            Timestamp::<UTC>::from_seconds_nanos_since_unix_epoch(50, 0)
                + Duration::from_seconds_nanos(50, 0),
            Timestamp::<UTC>::from_seconds_nanos_since_unix_epoch(100, 0)
        );
        assert_eq!(
            Timestamp::<UTC>::from_seconds_nanos_since_unix_epoch(150, 0)
                - Duration::from_seconds_nanos(50, 0),
            Timestamp::<UTC>::from_seconds_nanos_since_unix_epoch(100, 0)
        );

        let mut ts = Timestamp::<UTC>::from_seconds_nanos_since_unix_epoch(50, 0);
        ts += Duration::from_seconds_nanos(50, 0);
        assert_eq!(
            ts,
            Timestamp::<UTC>::from_seconds_nanos_since_unix_epoch(100, 0)
        );

        let mut ts = Timestamp::<UTC>::from_seconds_nanos_since_unix_epoch(150, 0);
        ts -= Duration::from_seconds_nanos(50, 0);
        assert_eq!(
            ts,
            Timestamp::<UTC>::from_seconds_nanos_since_unix_epoch(100, 0)
        );
    }

    #[test]
    fn test_timestamp_clone() {
        let ts = Timestamp::<UTC>::from_seconds_nanos_since_unix_epoch(500, 0);
        let ts_clone = ts.clone();
        assert_eq!(ts.0, ts_clone.0);
    }

    #[test]
    fn test_timestamp_hash() {
        fn hash<A: core::hash::Hash>(a: A) -> u64 {
            let mut s = DefaultHasher::new();
            a.hash(&mut s);
            s.finish()
        }

        assert_eq!(
            hash(Timestamp::<UTC>::from_seconds_nanos_since_unix_epoch(
                100,
                125_000_000
            )),
            hash(Timestamp::<UTC>::from_seconds_nanos_since_unix_epoch(
                100,
                125_000_000
            ))
        );
        assert_ne!(
            hash(Timestamp::<UTC>::from_seconds_nanos_since_unix_epoch(
                100,
                125_000_000
            )),
            hash(Timestamp::<UTC>::from_seconds_nanos_since_unix_epoch(
                150,
                250_000_000
            ))
        );
    }

    #[test]
    fn test_timestamp_debug_formatting() {
        assert_eq!(
            std::format!(
                "{:?}",
                Timestamp::<UTC>::from_seconds_nanos_since_unix_epoch(5, 500_000_000)
            ),
            std::format!("Timestamp<{}>(5.5s)", core::any::type_name::<UTC>())
        );
    }

    #[test]
    fn test_duration_creation() {
        assert_eq!(Duration::from_seconds_nanos(100, 0).0, 100 << 64);
        assert_eq!(Duration::from_seconds_nanos(0, 250_000_000).0, 1 << 62);
        assert_eq!(Duration::from_seconds_nanos(-1, 500_000_000).0, -1 << 63);
    }

    #[test]
    fn test_duration_as_seconds() {
        assert_eq!(Duration(1 << 64).as_seconds(), 1.0);
        assert_eq!(Duration(10 << 64).as_seconds(), 10.0);
        assert_eq!(Duration(5 << 62).as_seconds(), 1.25);
    }

    #[test]
    fn test_duration_debug_formatting() {
        assert_eq!(
            std::format!("{:?}", Duration::from_seconds_nanos(-5, 500_000_000)),
            "Duration(-4.5s)"
        );
    }

    #[test]
    fn test_duration_math() {
        assert_eq!(
            Duration::from_seconds_nanos(50, 0) + Duration::from_seconds_nanos(75, 0),
            Duration::from_seconds_nanos(125, 0)
        );
        assert_eq!(
            Duration::from_seconds_nanos(200, 0) - Duration::from_seconds_nanos(75, 0),
            Duration::from_seconds_nanos(125, 0)
        );

        let mut duration = Duration::from_seconds_nanos(50, 0);
        duration += Duration::from_seconds_nanos(75, 0);
        assert_eq!(duration, Duration::from_seconds_nanos(125, 0));

        let mut duration = Duration::from_seconds_nanos(200, 0);
        duration -= Duration::from_seconds_nanos(75, 0);
        assert_eq!(duration, Duration::from_seconds_nanos(125, 0));

        assert_eq!(
            Duration::from_seconds_nanos(0, 250_000_000) * 4u8,
            Duration::from_seconds_nanos(1, 0)
        );
        assert_eq!(
            6u8 * Duration::from_seconds_nanos(0, 250_000_000),
            Duration::from_seconds_nanos(1, 500_000_000)
        );

        assert_eq!(
            Duration::from_seconds_nanos(0, 250_000_000) * 4u16,
            Duration::from_seconds_nanos(1, 0)
        );
        assert_eq!(
            6u16 * Duration::from_seconds_nanos(0, 250_000_000),
            Duration::from_seconds_nanos(1, 500_000_000)
        );

        assert_eq!(
            Duration::from_seconds_nanos(0, 250_000_000) * 4u32,
            Duration::from_seconds_nanos(1, 0)
        );
        assert_eq!(
            6u32 * Duration::from_seconds_nanos(0, 250_000_000),
            Duration::from_seconds_nanos(1, 500_000_000)
        );

        assert_eq!(
            Duration::from_seconds_nanos(0, 250_000_000) * 4u64,
            Duration::from_seconds_nanos(1, 0)
        );
        assert_eq!(
            6u64 * Duration::from_seconds_nanos(0, 250_000_000),
            Duration::from_seconds_nanos(1, 500_000_000)
        );

        assert_eq!(
            Duration::from_seconds_nanos(0, 250_000_000) * 4i8,
            Duration::from_seconds_nanos(1, 0)
        );
        assert_eq!(
            6i8 * Duration::from_seconds_nanos(0, 250_000_000),
            Duration::from_seconds_nanos(1, 500_000_000)
        );

        assert_eq!(
            Duration::from_seconds_nanos(0, 250_000_000) * 4i16,
            Duration::from_seconds_nanos(1, 0)
        );
        assert_eq!(
            6i16 * Duration::from_seconds_nanos(0, 250_000_000),
            Duration::from_seconds_nanos(1, 500_000_000)
        );

        assert_eq!(
            Duration::from_seconds_nanos(0, 250_000_000) * 4i32,
            Duration::from_seconds_nanos(1, 0)
        );
        assert_eq!(
            6i32 * Duration::from_seconds_nanos(0, 250_000_000),
            Duration::from_seconds_nanos(1, 500_000_000)
        );

        assert_eq!(
            Duration::from_seconds_nanos(0, 250_000_000) * 4i64,
            Duration::from_seconds_nanos(1, 0)
        );
        assert_eq!(
            6i64 * Duration::from_seconds_nanos(0, 250_000_000),
            Duration::from_seconds_nanos(1, 500_000_000)
        );

        let mut duration = Duration::from_seconds_nanos(0, 125_000_000);
        duration *= 9u8;
        assert_eq!(duration, Duration::from_seconds_nanos(1, 125_000_000));

        let mut duration = Duration::from_seconds_nanos(0, 125_000_000);
        duration *= 9u16;
        assert_eq!(duration, Duration::from_seconds_nanos(1, 125_000_000));

        let mut duration = Duration::from_seconds_nanos(0, 125_000_000);
        duration *= 9u32;
        assert_eq!(duration, Duration::from_seconds_nanos(1, 125_000_000));

        let mut duration = Duration::from_seconds_nanos(0, 125_000_000);
        duration *= 9u64;
        assert_eq!(duration, Duration::from_seconds_nanos(1, 125_000_000));

        let mut duration = Duration::from_seconds_nanos(0, 125_000_000);
        duration *= 9i8;
        assert_eq!(duration, Duration::from_seconds_nanos(1, 125_000_000));

        let mut duration = Duration::from_seconds_nanos(0, 125_000_000);
        duration *= 9i16;
        assert_eq!(duration, Duration::from_seconds_nanos(1, 125_000_000));

        let mut duration = Duration::from_seconds_nanos(0, 125_000_000);
        duration *= 9i32;
        assert_eq!(duration, Duration::from_seconds_nanos(1, 125_000_000));

        let mut duration = Duration::from_seconds_nanos(0, 125_000_000);
        duration *= 9i64;
        assert_eq!(duration, Duration::from_seconds_nanos(1, 125_000_000));

        assert_eq!(
            Duration::from_seconds_nanos(1, 750_000_000) / 7u8,
            Duration::from_seconds_nanos(0, 250_000_000)
        );
        assert_eq!(
            Duration::from_seconds_nanos(1, 750_000_000) / 7i8,
            Duration::from_seconds_nanos(0, 250_000_000)
        );
        assert_eq!(
            Duration::from_seconds_nanos(1, 750_000_000) / 7u16,
            Duration::from_seconds_nanos(0, 250_000_000)
        );
        assert_eq!(
            Duration::from_seconds_nanos(1, 750_000_000) / 7i16,
            Duration::from_seconds_nanos(0, 250_000_000)
        );
        assert_eq!(
            Duration::from_seconds_nanos(1, 750_000_000) / 7u32,
            Duration::from_seconds_nanos(0, 250_000_000)
        );
        assert_eq!(
            Duration::from_seconds_nanos(1, 750_000_000) / 7i32,
            Duration::from_seconds_nanos(0, 250_000_000)
        );
        assert_eq!(
            Duration::from_seconds_nanos(1, 750_000_000) / 7u64,
            Duration::from_seconds_nanos(0, 250_000_000)
        );
        assert_eq!(
            Duration::from_seconds_nanos(1, 750_000_000) / 7i64,
            Duration::from_seconds_nanos(0, 250_000_000)
        );
    }
}
