use std::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Sub, SubAssign};

#[derive(Debug, Copy, Clone, Eq, PartialEq, PartialOrd, Ord, Default)]
pub struct NtpTimestamp {
    timestamp: u64,
}

/// Unix uses an epoch located at 1/1/1970-00:00h (UTC) and NTP uses 1/1/1900-00:00h.
/// This leads to an offset equivalent to 70 years in seconds
/// there are 17 leap years between the two dates so the offset is
const EPOCH_OFFSET: u64 = (70 * 365 + 17) * 86400;

impl NtpTimestamp {
    pub(crate) const fn from_bits(bits: [u8; 8]) -> NtpTimestamp {
        NtpTimestamp {
            timestamp: u64::from_be_bytes(bits),
        }
    }

    pub(crate) const fn to_bits(self) -> [u8; 8] {
        self.timestamp.to_be_bytes()
    }

    pub(crate) fn from_system_time(time: std::time::SystemTime) -> Self {
        let dur = time.duration_since(std::time::UNIX_EPOCH).unwrap();
        let secs = dur.as_secs() + EPOCH_OFFSET;
        let nanos = dur.subsec_nanos();

        Self::from_seconds_nanos_since_ntp_epoch(secs, nanos)
    }

    pub(crate) fn from_seconds_nanos_since_ntp_epoch(seconds: u64, nanos: u32) -> Self {
        // NTP uses 1/2^32 sec as its unit of fractional time.
        // our time is in nanoseconds, so 1/1e9 seconds
        let fraction = ((nanos as u64) << 32) / 1_000_000_000;

        // alternatively, abuse FP arithmetic to save an instruction
        // let fraction = (nanos as f64 * 4.294967296) as u64;

        let timestamp = (seconds << 32) + fraction;
        NtpTimestamp::from_bits(timestamp.to_be_bytes())
    }

    #[cfg(test)]
    pub(crate) fn duration_since_unix_epoch(self) -> std::time::Duration {
        let seconds = (self.timestamp >> 32) - EPOCH_OFFSET;
        let nanos = ((self.timestamp & 0x00000000FFFFFFFF) * 1_000_000_000 / (1u64 << 32)) as u32;

        std::time::Duration::new(seconds, nanos)
    }

    #[cfg(test)]
    pub(crate) const fn from_fixed_int(timestamp: u64) -> NtpTimestamp {
        NtpTimestamp { timestamp }
    }
}

impl Add<NtpDuration> for NtpTimestamp {
    type Output = NtpTimestamp;

    fn add(self, rhs: NtpDuration) -> Self::Output {
        // In order to properly deal with ntp era changes, timestamps
        // need to roll over. Converting the duration to u64 here
        // still gives desired effects because of how two's complement
        // arithmetic works.
        NtpTimestamp {
            timestamp: self.timestamp.wrapping_add(rhs.duration as u64),
        }
    }
}

impl AddAssign<NtpDuration> for NtpTimestamp {
    fn add_assign(&mut self, rhs: NtpDuration) {
        // In order to properly deal with ntp era changes, timestamps
        // need to roll over. Converting the duration to u64 here
        // still gives desired effects because of how two's complement
        // arithmetic works.
        self.timestamp = self.timestamp.wrapping_add(rhs.duration as u64);
    }
}

impl Sub for NtpTimestamp {
    type Output = NtpDuration;

    fn sub(self, rhs: Self) -> Self::Output {
        // In order to properly deal with ntp era changes, timestamps
        // need to roll over. Doing a wrapping substract to a signed
        // integer type always gives us the result as if the eras of
        // the timestamps were chosen to minimize the norm of the
        // difference, which is the desired behaviour
        NtpDuration {
            duration: self.timestamp.wrapping_sub(rhs.timestamp) as i64,
        }
    }
}

impl Sub<NtpDuration> for NtpTimestamp {
    type Output = NtpTimestamp;

    fn sub(self, rhs: NtpDuration) -> Self::Output {
        // In order to properly deal with ntp era changes, timestamps
        // need to roll over. Converting the duration to u64 here
        // still gives desired effects because of how two's complement
        // arithmetic works.
        NtpTimestamp {
            timestamp: self.timestamp.wrapping_sub(rhs.duration as u64),
        }
    }
}

impl SubAssign<NtpDuration> for NtpTimestamp {
    fn sub_assign(&mut self, rhs: NtpDuration) {
        // In order to properly deal with ntp era changes, timestamps
        // need to roll over. Converting the duration to u64 here
        // still gives desired effects because of how two's complement
        // arithmetic works.
        self.timestamp = self.timestamp.wrapping_sub(rhs.duration as u64);
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, PartialOrd, Ord, Default)]
pub struct NtpDuration {
    duration: i64,
}

impl NtpDuration {
    pub(crate) const fn from_bits_short(bits: [u8; 4]) -> NtpDuration {
        NtpDuration {
            duration: (u32::from_be_bytes(bits) as i64) << 16,
        }
    }

    pub(crate) const fn to_bits_short(self) -> [u8; 4] {
        // serializing negative durations should never happen
        // and indicates a programming error elsewhere.
        // as for duration that are too large, saturating is
        // the safe option.
        assert!(self.duration >= 0);
        match self.duration > 0x0000FFFFFFFFFFFF {
            true => 0xFFFFFFFF_u32,
            false => ((self.duration & 0x0000FFFFFFFF0000) >> 16) as u32,
        }
        .to_be_bytes()
    }

    #[cfg(test)]
    pub(crate) const fn from_fixed_int(duration: i64) -> NtpDuration {
        NtpDuration { duration }
    }
}

impl Add for NtpDuration {
    type Output = NtpDuration;

    fn add(self, rhs: Self) -> Self::Output {
        // For duration, saturation is safer as that ensures
        // addition or substraction of two big durations never
        // unintentionally cancel, ensuring that filtering
        // can properly reject on the result.
        NtpDuration {
            duration: self.duration.saturating_add(rhs.duration),
        }
    }
}

impl AddAssign for NtpDuration {
    fn add_assign(&mut self, rhs: Self) {
        // For duration, saturation is safer as that ensures
        // addition or substraction of two big durations never
        // unintentionally cancel, ensuring that filtering
        // can properly reject on the result.
        self.duration = self.duration.saturating_add(rhs.duration);
    }
}

impl Sub for NtpDuration {
    type Output = NtpDuration;

    fn sub(self, rhs: Self) -> Self::Output {
        // For duration, saturation is safer as that ensures
        // addition or substraction of two big durations never
        // unintentionally cancel, ensuring that filtering
        // can properly reject on the result.
        NtpDuration {
            duration: self.duration.saturating_sub(rhs.duration),
        }
    }
}

impl SubAssign for NtpDuration {
    fn sub_assign(&mut self, rhs: Self) {
        // For duration, saturation is safer as that ensures
        // addition or substraction of two big durations never
        // unintentionally cancel, ensuring that filtering
        // can properly reject on the result.
        self.duration = self.duration.saturating_sub(rhs.duration);
    }
}

macro_rules! ntp_duration_scalar_mul {
    ($scalar_type:ty) => {
        impl Mul<NtpDuration> for $scalar_type {
            type Output = NtpDuration;

            fn mul(self, rhs: NtpDuration) -> NtpDuration {
                // For duration, saturation is safer as that ensures
                // addition or substraction of two big durations never
                // unintentionally cancel, ensuring that filtering
                // can properly reject on the result.
                NtpDuration {
                    duration: rhs.duration.saturating_mul(self as i64),
                }
            }
        }

        impl Mul<$scalar_type> for NtpDuration {
            type Output = NtpDuration;

            fn mul(self, rhs: $scalar_type) -> NtpDuration {
                // For duration, saturation is safer as that ensures
                // addition or substraction of two big durations never
                // unintentionally cancel, ensuring that filtering
                // can properly reject on the result.
                NtpDuration {
                    duration: self.duration.saturating_mul(rhs as i64),
                }
            }
        }

        impl MulAssign<$scalar_type> for NtpDuration {
            fn mul_assign(&mut self, rhs: $scalar_type) {
                // For duration, saturation is safer as that ensures
                // addition or substraction of two big durations never
                // unintentionally cancel, ensuring that filtering
                // can properly reject on the result.
                self.duration = self.duration.saturating_mul(rhs as i64);
            }
        }
    };
}

ntp_duration_scalar_mul!(i8);
ntp_duration_scalar_mul!(i16);
ntp_duration_scalar_mul!(i32);
ntp_duration_scalar_mul!(i64);
ntp_duration_scalar_mul!(isize);
ntp_duration_scalar_mul!(u8);
ntp_duration_scalar_mul!(u16);
ntp_duration_scalar_mul!(u32);
// u64 and usize deliberately excluded as they can result in overflows

macro_rules! ntp_duration_scalar_div {
    ($scalar_type:ty) => {
        impl Div<$scalar_type> for NtpDuration {
            type Output = NtpDuration;

            fn div(self, rhs: $scalar_type) -> NtpDuration {
                // No overflow risks for division
                NtpDuration {
                    duration: self.duration / (rhs as i64),
                }
            }
        }

        impl DivAssign<$scalar_type> for NtpDuration {
            fn div_assign(&mut self, rhs: $scalar_type) {
                // No overflow risks for division
                self.duration /= (rhs as i64);
            }
        }
    };
}

ntp_duration_scalar_div!(i8);
ntp_duration_scalar_div!(i16);
ntp_duration_scalar_div!(i32);
ntp_duration_scalar_div!(i64);
ntp_duration_scalar_div!(isize);
ntp_duration_scalar_div!(u8);
ntp_duration_scalar_div!(u16);
ntp_duration_scalar_div!(u32);
// u64 and usize deliberately excluded as they can result in overflows

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timestamp_sub() {
        let a = NtpTimestamp::from_fixed_int(5);
        let b = NtpTimestamp::from_fixed_int(3);
        assert_eq!(a - b, NtpDuration::from_fixed_int(2));
        assert_eq!(b - a, NtpDuration::from_fixed_int(-2));
    }

    #[test]
    fn test_timestamp_era_change() {
        let mut a = NtpTimestamp::from_fixed_int(1);
        let b = NtpTimestamp::from_fixed_int(0xFFFFFFFFFFFFFFFF);
        assert_eq!(a - b, NtpDuration::from_fixed_int(2));
        assert_eq!(b - a, NtpDuration::from_fixed_int(-2));

        let c = NtpDuration::from_fixed_int(2);
        let d = NtpDuration::from_fixed_int(-2);
        assert_eq!(b + c, a);
        assert_eq!(b - d, a);
        assert_eq!(a - c, b);
        assert_eq!(a + d, b);

        a -= c;
        assert_eq!(a, b);
        a += c;
        assert_eq!(a, NtpTimestamp::from_fixed_int(1));
    }

    #[test]
    fn test_timestamp_duration_math() {
        let mut a = NtpTimestamp::from_fixed_int(5);
        let b = NtpDuration::from_fixed_int(2);
        assert_eq!(a + b, NtpTimestamp::from_fixed_int(7));
        assert_eq!(a - b, NtpTimestamp::from_fixed_int(3));
        a += b;
        assert_eq!(a, NtpTimestamp::from_fixed_int(7));
        a -= b;
        assert_eq!(a, NtpTimestamp::from_fixed_int(5));
    }

    #[test]
    fn test_duration_math() {
        let mut a = NtpDuration::from_fixed_int(5);
        let b = NtpDuration::from_fixed_int(2);
        assert_eq!(a + b, NtpDuration::from_fixed_int(7));
        assert_eq!(a - b, NtpDuration::from_fixed_int(3));
        a += b;
        assert_eq!(a, NtpDuration::from_fixed_int(7));
        a -= b;
        assert_eq!(a, NtpDuration::from_fixed_int(5));
    }

    macro_rules! ntp_duration_scaling_test {
        ($name:ident, $scalar_type:ty) => {
            #[test]
            fn $name() {
                let mut a = NtpDuration::from_fixed_int(31);
                let b: $scalar_type = 2;
                assert_eq!(a * b, NtpDuration::from_fixed_int(62));
                assert_eq!(b * a, NtpDuration::from_fixed_int(62));
                assert_eq!(a / b, NtpDuration::from_fixed_int(15));
                a /= b;
                assert_eq!(a, NtpDuration::from_fixed_int(15));
                a *= b;
                assert_eq!(a, NtpDuration::from_fixed_int(30));
            }
        };
    }

    ntp_duration_scaling_test!(ntp_duration_scaling_i8, i8);
    ntp_duration_scaling_test!(ntp_duration_scaling_i16, i16);
    ntp_duration_scaling_test!(ntp_duration_scaling_i32, i32);
    ntp_duration_scaling_test!(ntp_duration_scaling_i64, i64);
    ntp_duration_scaling_test!(ntp_duration_scaling_isize, isize);
    ntp_duration_scaling_test!(ntp_duration_scaling_u8, u8);
    ntp_duration_scaling_test!(ntp_duration_scaling_u16, u16);
    ntp_duration_scaling_test!(ntp_duration_scaling_u32, u32);
}
