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

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

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

#[cfg(feature = "serde")]
#[derive(Deserialize, Serialize)]
struct SerializationTimestamp {
    upper: u64,
    lower: u64,
}

#[cfg(feature = "serde")]
impl<T> Serialize for Timestamp<T> {
    #[expect(clippy::cast_possible_truncation, reason = "Cast will never truncate")]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        SerializationTimestamp {
            upper: (self.0 >> 64) as u64,
            lower: (self.0 & u128::from(u64::MAX)) as u64,
        }
        .serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de, T> Deserialize<'de> for Timestamp<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let st = SerializationTimestamp::deserialize(deserializer)?;
        Ok(Self(
            (u128::from(st.upper) << 64) | u128::from(st.lower),
            PhantomData,
        ))
    }
}

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

#[cfg(feature = "serde")]
#[derive(Serialize, Deserialize)]
struct SerializationDuration {
    upper: i64,
    lower: u64,
}

#[cfg(feature = "serde")]
impl Serialize for Duration {
    #[expect(clippy::cast_possible_truncation, reason = "Cast will never truncate")]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let raw = self.0.cast_unsigned();
        SerializationDuration {
            upper: ((raw >> 64) as u64).cast_signed(),
            lower: (raw & u128::from(u64::MAX)) as u64,
        }
        .serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Duration {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let sd = SerializationDuration::deserialize(deserializer)?;
        Ok(Self(
            ((u128::from(sd.upper.cast_unsigned()) << 64) | u128::from(sd.lower)).cast_signed(),
        ))
    }
}

/// A timestamp that can be in either the UTC or TAI timescales.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UniversalTimestamp {
    /// A UTC timestamp
    Utc(Timestamp<UTC>),
    /// A TAI timestamp
    Tai(Timestamp<TAI>),
}

impl From<Timestamp<UTC>> for UniversalTimestamp {
    fn from(value: Timestamp<UTC>) -> Self {
        Self::Utc(value)
    }
}

impl From<Timestamp<TAI>> for UniversalTimestamp {
    fn from(value: Timestamp<TAI>) -> Self {
        Self::Tai(value)
    }
}

impl UniversalTimestamp {
    /// Get the timestamp converted to a UTC timestamp, given the difference TAI-UTC.
    #[must_use]
    pub fn as_utc(self, tai_offset: i64) -> Timestamp<UTC> {
        match self {
            UniversalTimestamp::Utc(timestamp) => timestamp,
            UniversalTimestamp::Tai(timestamp) => {
                Timestamp::UNIX_EPOCH - Duration::from_seconds_nanos(tai_offset, 0)
                    + (timestamp - Timestamp::UNIX_EPOCH)
            }
        }
    }

    /// Get the timestamp converted to a TAI timestamp, given the difference TAI-UTC.
    #[must_use]
    pub fn as_tai(self, tai_offset: i64) -> Timestamp<TAI> {
        match self {
            UniversalTimestamp::Utc(timestamp) => {
                Timestamp::UNIX_EPOCH
                    + Duration::from_seconds_nanos(tai_offset, 0)
                    + (timestamp - Timestamp::UNIX_EPOCH)
            }
            UniversalTimestamp::Tai(timestamp) => timestamp,
        }
    }
}

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
    /// A zero-length duration.
    pub const ZERO: Duration = Duration(0);

    /// The length of the duration as a floating point number of seconds.
    ///
    /// Note: Very large durations will loose precision when converted
    /// to a floating point.
    #[must_use]
    #[expect(
        clippy::cast_precision_loss,
        reason = "Power of two u128 to float cast is exact, other precision rounding errors are acceptable"
    )]
    pub fn as_seconds(self) -> f64 {
        (self.0 as f64) / ((1u128 << 64) as f64)
    }

    /// The length of the duration in steps (2^-64ths of a second)
    #[must_use]
    pub fn as_raw_steps(self) -> i128 {
        self.0
    }

    /// The length of the duration in nanoseconds, rounded.
    #[must_use]
    pub fn as_nanos(self) -> i128 {
        // We split and do the subsecond and second parts separately to avoid overflows.
        let subseconds = (self.0.cast_unsigned() & u128::from(u64::MAX)) * 1_000_000_000;
        let seconds = self.0 >> 64;
        let nanos_subseconds = (subseconds >> 64)
            + u128::from((subseconds & 0xFFFF_FFFF_FFFF_FFFF) >= 0x8000_0000_0000_0000);
        seconds * 1_000_000_000 + nanos_subseconds.cast_signed()
    }

    /// Create a duration from a length in steps (2^-64ths of a second)
    #[must_use]
    pub fn from_raw_steps(steps: i128) -> Self {
        Self(steps)
    }

    /// Log2 length of the duration
    #[must_use]
    #[expect(
        clippy::cast_possible_truncation,
        reason = "The casts to i32 and i8 always fit"
    )]
    pub fn log2(self) -> i8 {
        if self == Duration::ZERO {
            return i8::MIN;
        }

        ((self.0.ilog2().cast_signed()) - 64) as i8
    }

    /// Create a duration from a floating point number of seconds.
    ///
    /// Note: If the provided value is too large or too small to representable as a
    /// duration, the result will be clamped to the maximum or minimum respectively.
    #[must_use]
    #[expect(
        clippy::cast_precision_loss,
        reason = "Power of two u128 to float cast is exact, other precision rounding errors are acceptable"
    )]
    #[expect(
        clippy::cast_possible_truncation,
        reason = "Acceptable: large durations may truncate to the maximum/minimum representable number."
    )]
    pub fn from_f64_seconds(value: f64) -> Self {
        Duration((value * ((1u128 << 64) as f64)) as i128)
    }

    /// Create a duration from a given number of seconds, plus the given number
    /// of nanoseconds.
    ///
    /// The nanoseconds are always applied in the positive direction, so for
    /// example `from_seconds_nanos(-1, 500_000_000)` represents minus half a
    /// second.
    #[must_use]
    pub const fn from_seconds_nanos(seconds: i64, nanos: u32) -> Self {
        let converted_nanos = ((nanos as i128) << 64) / 1_000_000_000;
        Duration(((seconds as i128) << 64) + converted_nanos)
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

#[cfg(all(test, feature = "std"))]
#[expect(clippy::float_cmp, reason = "Test code")]
mod tests {
    use core::hash::Hasher;
    use std::hash::DefaultHasher;

    use crate::{TAI, UniversalTimestamp};

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
        #[expect(
            clippy::clone_on_copy,
            reason = "Clone implementation of type is under test"
        )]
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
    #[expect(clippy::too_many_lines, reason = "Test code")]
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

    #[test]
    fn test_universal_timestamp() {
        let universal_utc: UniversalTimestamp =
            Timestamp::<UTC>::from_seconds_nanos_since_unix_epoch(63, 0).into();
        assert_eq!(
            universal_utc.as_utc(37),
            Timestamp::from_seconds_nanos_since_unix_epoch(63, 0)
        );
        assert_eq!(
            universal_utc.as_tai(37),
            Timestamp::from_seconds_nanos_since_unix_epoch(100, 0)
        );

        let universal_tai: UniversalTimestamp =
            Timestamp::<TAI>::from_seconds_nanos_since_unix_epoch(100, 0).into();
        assert_eq!(
            universal_tai.as_utc(37),
            Timestamp::from_seconds_nanos_since_unix_epoch(63, 0)
        );
        assert_eq!(
            universal_tai.as_tai(37),
            Timestamp::from_seconds_nanos_since_unix_epoch(100, 0)
        );
    }
}
