use std::os::unix::io::{AsRawFd, RawFd};
use std::io::{Error, Result};
use std::fs::File;
use std::mem::MaybeUninit;
use libc::{self, timespec, clock_gettime, CLOCK_REALTIME};
use chrono::{NaiveDateTime, NaiveTimeZone, Utc};
use std::time::{Duration, Instant};
use std::ops::Sub;

/// NtpDuration is used to represent signed intervals between NtpTimestamps.
/// A negative duration interval is interpreted to mean that the first
/// timestamp used to define the interval represents a point in time after
/// the second timestamp.
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

    pub(crate) const fn to_bits_short(self) -> [u8; 4] {
        assert!(self.duration >= 0);
        debug_assert!(self.duration <= 0x0000FFFFFFFFFFFF);

        match self.duration > 0x0000FFFFFFFFFFFF {
            true => [0xFF, 0xFF, 0xFF, 0xFF],
            false => ((self.duration & 0x0000FFFFFFFF0000) >> 16) as u32,
        }
        .to_be_bytes()
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

    pub fn log2(self) -> i8 {
        if self == NtpDuration::ZERO {
            return i8::MIN;
        }

        31 - (self.duration.leading_zeros() as i8)
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

// Define the NtpTimestamp struct and its implementation
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
    /// Create an NTP timestamp from the number of seconds and nanoseconds that have
    /// passed since the last ntp era boundary.
    pub const fn from_seconds_nanos_since_ntp_era(seconds: u32, nanos: u32) -> Self {
        // Although having a valid interpretation, providing more
        // than 1 second worth of nanoseconds as input probably
        // indicates an error from the caller.        
        debug_assert!(nanos < 1_000_000_000);
        // NTP uses 1/2^32 sec as its unit of fractional time.
        // our time is in nanoseconds, so 1/1e9 seconds        
        let fraction = ((nanos as u64) << 32) / 1_000_000_000;

        // alternatively, abuse FP arithmetic to save an instruction
        // let fraction = (nanos as f64 * 4.294967296) as u64;        
        let timestamp = ((seconds as u64) << 32) + fraction;
        NtpTimestamp::from_bits(timestamp.to_be_bytes())
    }

    pub fn from_unix_timestamp(unix_timestamp: u64) -> Self {
        let system_time = std::time::UNIX_EPOCH + std::time::Duration::from_secs(unix_timestamp);
        let duration_since_epoch = system_time.duration_since(std::time::UNIX_EPOCH).unwrap();
        let seconds = duration_since_epoch.as_secs() as u32;
        let nanos = duration_since_epoch.subsec_nanos();
        NtpTimestamp::from_seconds_nanos_since_ntp_era(seconds, nanos)
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

/// NtpInstant is a monotonically increasing value modelling the uptime of the NTP service
/// It is used to validate packets that we send out, and to order internal operations.
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

    pub const fn from_unix_timestamp(unix_timestamp: u64) -> Self {
        let system_time = std::time::UNIX_EPOCH + std::time::Duration::from_secs(unix_timestamp);
        let duration_since_epoch = system_time.duration_since(std::time::UNIX_EPOCH).unwrap();
        NtpInstant {
            instant: Instant::from(duration_since_epoch),
        }
    }
}

fn get_pps_time(fd: RawFd, last_ntp_timestamp: &mut NtpTimestamp) -> Result<(), Error> {
    let mut ts = MaybeUninit::<timespec>::uninit();

    unsafe {
        if clock_gettime(CLOCK_REALTIME, ts.as_mut_ptr()) != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }

    let ts = unsafe { ts.assume_init() };
    let timestamp = ts.tv_sec as u64;

    // Convert Unix timestamp to NtpTimestamp
    let ntp_timestamp = NtpTimestamp::from_unix_timestamp(timestamp);

    println!("Current NTP Timestamp: {:?}", ntp_timestamp);

    // Convert Unix timestamp to NtpInstant
    let ntp_instant = NtpInstant::from_unix_timestamp(timestamp);

    println!("Current NTP Instant: {:?}", ntp_instant);

    // Print the difference between two timestamps
    let time_diff = ntp_timestamp - *last_ntp_timestamp; // Dereference last_ntp_timestamp
    println!("Time difference: {:?}", time_diff);
    // Update the last NTP timestamp
    *last_ntp_timestamp = ntp_timestamp; // Update last_ntp_timestamp

    Ok(())
}

fn main() -> std::io::Result<()> {
    let path = "/dev/pps0";
    let file = File::open(path)?;
    let fd = file.as_raw_fd();

    // Initialize the last NTP timestamp to 0
    let mut last_ntp_timestamp = NtpTimestamp::from_unix_timestamp(0);

    loop {
        get_pps_time(fd, &mut last_ntp_timestamp)?; // Pass last_ntp_timestamp as mutable reference
    }
}

