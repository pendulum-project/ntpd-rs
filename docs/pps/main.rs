use std::fs::File;
use std::io::{self, Result};
use std::os::unix::io::{AsRawFd, RawFd};
use std::mem::MaybeUninit;
use libc::{timespec, clock_gettime, CLOCK_REALTIME};
use std::thread::sleep;
use std::time::{Duration, Instant, UNIX_EPOCH};
use std::ops::Sub;
use chrono::{DateTime, NaiveDateTime, Utc};

#[derive(Debug, Copy, Clone, Eq, PartialEq, PartialOrd, Ord)]
pub struct NtpDuration {
    duration: i64,
}

impl NtpDuration {
    pub const ZERO: Self = Self { duration: 0 };

    pub(crate) const fn from_bits(bits: [u8; 8]) -> Self {
        Self {
            duration: i64::from_be_bytes(bits),
        }
    }

    pub(crate) const fn from_bits_short(bits: [u8; 4]) -> Self {
        NtpDuration {
            duration: (u32::from_be_bytes(bits) as i64) << 16,
        }
    }

    pub fn to_seconds(self) -> f64 {
        self.duration as f64 / u32::MAX as f64
    }

    pub fn from_seconds(seconds: f64) -> Self {
        debug_assert!(!(seconds.is_nan() || seconds.is_infinite()));

        let i = seconds.floor();
        let f = seconds - i;

        let duration = match i as i64 {
            i if i >= std::i32::MIN as i64 && i <= std::i32::MAX as i64 => {
                (i << 32) | (f * u32::MAX as f64) as i64
            }
            i if i < std::i32::MIN as i64 => std::i64::MIN,
            i if i > std::i32::MAX as i64 => std::i64::MAX,
            _ => unreachable!(),
        };

        Self { duration }
    }

    pub const fn abs(self) -> Self {
        Self {
            duration: self.duration.abs(),
        }
    }

    pub fn abs_diff(self, other: Self) -> Self {
        (self - other).abs()
    }

    pub const fn as_seconds_nanos(self) -> (i32, u32) {
        (
            (self.duration >> 32) as i32,
            (((self.duration & 0xFFFFFFFF) * 1_000_000_000) >> 32) as u32,
        )
    }

    pub fn from_exponent(input: i8) -> Self {
        Self {
            duration: match input {
                exp if exp > 30 => std::i64::MAX,
                exp if exp > 0 && exp <= 30 => 0x1_0000_0000_i64 << exp,
                exp if (-32..=0).contains(&exp) => 0x1_0000_0000_i64 >> -exp,
                _ => 0,
            },
        }
    }

    pub fn log2(self) -> Option<i8> {
        if self.duration == 0 {
            return None; 
        }
        Some(63 - self.duration.leading_zeros() as i8) 
    }

    pub fn from_system_duration(duration: Duration) -> Self {
        let seconds = duration.as_secs();
        let nanos = duration.subsec_nanos();
        debug_assert!(nanos < 1_000_000_000);

        let fraction = ((nanos as u64) << 32) / 1_000_000_000;

        let timestamp = (seconds << 32) + fraction;
        NtpDuration::from_bits(timestamp.to_be_bytes())
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, PartialOrd, Ord)]
struct NtpTimestamp {
    timestamp: u64,
}

impl NtpTimestamp {
    pub const fn from_bits(bits: [u8; 8]) -> NtpTimestamp {
        NtpTimestamp {
            timestamp: u64::from_be_bytes(bits),
        }
    }

    pub const fn to_bits(self) -> [u8; 8] {
        self.timestamp.to_be_bytes()
    }

    pub const fn from_seconds_nanos_since_ntp_era(seconds: u32, nanos: u32) -> Self {
        debug_assert!(nanos < 1_000_000_000);

        let fraction = ((nanos as u64) << 32) / 1_000_000_000;
        let timestamp = ((seconds as u64) << 32) + fraction;
        NtpTimestamp::from_bits(timestamp.to_be_bytes())
    }

    pub fn from_unix_timestamp(unix_timestamp: u64, nanos: u32) -> Self {
        const UNIX_TO_NTP_OFFSET: u64 = 2_208_988_800; // Offset in seconds between Unix epoch and NTP epoch
        const NTP_SCALE_FRAC: u64 = 4_294_967_296; // 2^32 for scaling nanoseconds to fraction
        // Calculate NTP seconds
        let ntp_seconds = unix_timestamp + UNIX_TO_NTP_OFFSET;

        // Calculate the fractional part of the NTP timestamp
        let fraction = ((nanos as u64 * NTP_SCALE_FRAC) / 1_000_000_000) as u64;

        // Combine NTP seconds and fraction to form the complete NTP timestamp
        let timestamp = (ntp_seconds << 32) | fraction;

        println!("Unix Timestamp: {}, Nanos: {}, NTP Seconds: {}, Fraction: {}", unix_timestamp, nanos, ntp_seconds, fraction);
        println!("Combined NTP Timestamp: {:#018X}", timestamp);

        NtpTimestamp { timestamp }
    }
}

impl Sub for NtpTimestamp {
    type Output = NtpDuration;

    fn sub(self, rhs: Self) -> Self::Output {
        NtpDuration {
            duration: self.timestamp.wrapping_sub(rhs.timestamp) as i64,
        }
    }
}

impl Sub for NtpDuration {
    type Output = NtpDuration;

    fn sub(self, rhs: Self) -> Self::Output {
        NtpDuration {
            duration: self.duration.saturating_sub(rhs.duration),
        }
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, PartialOrd, Ord)]
pub struct NtpInstant {
    instant: Instant,
}

impl NtpInstant {
    pub fn now() -> Self {
        Self {
            instant: Instant::now(),
        }
    }

    pub fn abs_diff(self, rhs: Self) -> NtpDuration {
        let duration = if self.instant >= rhs.instant {
            self.instant - rhs.instant
        } else {
            rhs.instant - self.instant
        };

        NtpDuration::from_system_duration(duration)
    }

    pub fn elapsed(&self) -> NtpDuration {
        let duration = self.instant.elapsed();
        NtpDuration::from_system_duration(duration)
    }

    pub fn from_unix_timestamp(unix_timestamp: u64, nanos: u32) -> Self {
        let system_time = UNIX_EPOCH + Duration::from_secs(unix_timestamp) + Duration::from_nanos(nanos as u64);
        let duration_since_epoch = system_time.duration_since(UNIX_EPOCH).unwrap();
        NtpInstant {
            instant: Instant::now() - duration_since_epoch,
        }
    }
    
}

fn get_pps_time(_fd: RawFd, last_ntp_timestamp: &mut NtpTimestamp) -> Result<()> {
    let mut ts = MaybeUninit::<timespec>::uninit();

    unsafe {
        if clock_gettime(CLOCK_REALTIME, ts.as_mut_ptr()) != 0 {
            return Err(io::Error::last_os_error());
        }
    }

    let ts = unsafe { ts.assume_init() };
    let timestamp = ts.tv_sec as u64;
    let nanos = ts.tv_nsec as u32;

    // Debugging: print raw Unix timestamp and nanoseconds
    println!("Raw Unix Timestamp: {}, Nanoseconds: {}", timestamp, nanos);

    let ntp_timestamp = NtpTimestamp::from_unix_timestamp(timestamp, nanos);

    // Debugging: print the converted NTP timestamp
    println!("Current NTP Timestamp: {:?}", ntp_timestamp);

    let time_diff = ntp_timestamp - *last_ntp_timestamp;

    // Debugging: print the time difference
    println!("Time difference: {:?}", time_diff);

    *last_ntp_timestamp = ntp_timestamp;

    // Convert the timestamp to a readable format using chrono for verification
    let naive_datetime = NaiveDateTime::from_timestamp(timestamp as i64, nanos);
    let datetime: DateTime<Utc> = DateTime::from_utc(naive_datetime, Utc);
    println!("Readable time: {}", datetime);

    Ok(())
}

fn main() -> io::Result<()> {
    let path = "/dev/pps0";
    let file = File::open(path)?;
    let fd = file.as_raw_fd();

    let mut last_ntp_timestamp = NtpTimestamp::from_unix_timestamp(0, 0);

    loop {
        get_pps_time(fd, &mut last_ntp_timestamp)?;
        sleep(Duration::from_secs(1));
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    //NtpDuration Tests:
    #[test]
    fn test_ntp_duration_from_bits() {
        let bits = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00];
        let duration = NtpDuration::from_bits(bits);
        assert_eq!(duration.duration, 256);
    }

    #[test]
    fn test_ntp_duration_from_bits_short() {
        let bits = [0x00, 0x00, 0x01, 0x00];
        let duration = NtpDuration::from_bits_short(bits);
        assert_eq!(duration.duration, 16777216); 
    }

    #[test]
    fn test_ntp_duration_to_seconds() {
        let duration = NtpDuration { duration: 4294967296 }; 
        assert!((duration.to_seconds() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_ntp_duration_from_seconds() {
        let duration = NtpDuration::from_seconds(1.0);
        assert_eq!(duration.duration, 4294967296); 
    }

    #[test]
    fn test_ntp_duration_abs() {
        let duration = NtpDuration { duration: -5 };
        assert_eq!(duration.abs().duration, 5);
    }

    #[test]
    fn test_ntp_duration_abs_diff() {
        let duration1 = NtpDuration { duration: 10 };
        let duration2 = NtpDuration { duration: 2 };
        assert_eq!(duration1.abs_diff(duration2).duration, 8);
    }

    #[test]
    fn test_ntp_duration_as_seconds_nanos() {
        let duration = NtpDuration { duration: 4294967296 }; 
        assert_eq!(duration.as_seconds_nanos(), (1, 0));
    }

    #[test]
    fn test_ntp_duration_from_exponent() {
        let duration = NtpDuration::from_exponent(3);
        assert_eq!(duration.duration, 34359738368); 
    }

    #[test]
    fn test_ntp_duration_log2() {
        let duration = NtpDuration { duration: 4294967296 }; 
        assert_eq!(duration.log2(), Some(32)); 
    
        let duration = NtpDuration { duration: 1 }; 
        assert_eq!(duration.log2(), Some(0)); 
    
        let duration = NtpDuration { duration: 2 }; 
        assert_eq!(duration.log2(), Some(1)); 
    
        let duration = NtpDuration { duration: 16 }; 
        assert_eq!(duration.log2(), Some(4)); 
    
        let duration = NtpDuration { duration: 0 }; 
        assert_eq!(duration.log2(), None); 
    }

    #[test]
    fn test_ntp_duration_from_system_duration() {
        let system_duration = Duration::new(1, 0);
        let ntp_duration = NtpDuration::from_system_duration(system_duration);
        assert_eq!(ntp_duration.duration, 4294967296); 
    }

    #[test]
    fn test_ntp_duration_sub() {
        let duration1 = NtpDuration { duration: 8 };
        let duration2 = NtpDuration { duration: 2 };
        assert_eq!((duration1 - duration2).duration, 6);
    }

    
     //NtpTimestamp Tests: 
    #[test]
    fn test_ntp_timestamp_from_bits() {
        let bits = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00];
        let timestamp = NtpTimestamp::from_bits(bits);
        assert_eq!(timestamp.timestamp, 256);
    }

    #[test]
    fn test_ntp_timestamp_to_bits() {
        let timestamp = NtpTimestamp { timestamp: 256 };
        assert_eq!(timestamp.to_bits(), [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00]);
    }

    #[test]
    fn test_ntp_timestamp_from_seconds_nanos_since_ntp_era() {
        let timestamp = NtpTimestamp::from_seconds_nanos_since_ntp_era(1, 0);
        assert_eq!(timestamp.timestamp, 1u64 << 32);

        let timestamp = NtpTimestamp::from_seconds_nanos_since_ntp_era(1, 500000000);
        assert_eq!(timestamp.timestamp, (1u64 << 32) + (1u64 << 31));

        let timestamp = NtpTimestamp::from_seconds_nanos_since_ntp_era(0, 500000000);
        assert_eq!(timestamp.timestamp, 1u64 << 31);

        let timestamp = NtpTimestamp::from_seconds_nanos_since_ntp_era(0, 0);
        assert_eq!(timestamp.timestamp, 0);
    }

    #[test]
    fn test_ntp_timestamp_from_unix_timestamp() {
        let timestamp = NtpTimestamp::from_unix_timestamp(1620000000, 0);
        assert_eq!(timestamp.timestamp, 3828988800u64 << 32);

        let timestamp = NtpTimestamp::from_unix_timestamp(1620000000, 500000000);
        assert_eq!(timestamp.timestamp, (3828988800u64 << 32) + (1u64 << 31));

        let timestamp = NtpTimestamp::from_unix_timestamp(0, 500000000);
        assert_eq!(timestamp.timestamp, (2208988800u64 << 32) + (1u64 << 31));

        let timestamp = NtpTimestamp::from_unix_timestamp(0, 0);
        assert_eq!(timestamp.timestamp, 2208988800u64 << 32);
    }

    #[test]
    fn test_ntp_timestamp_sub() {
        let timestamp1 = NtpTimestamp { timestamp: 9 };
        let timestamp2 = NtpTimestamp { timestamp: 7 };
        let duration = timestamp1 - timestamp2;
        assert_eq!(duration.duration, 2);
    }
}
