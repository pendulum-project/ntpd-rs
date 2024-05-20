use std::fs::File;
use std::io::{self, Result};
use std::os::unix::io::{AsRawFd, RawFd};
use std::mem::MaybeUninit;
use libc::{timespec, clock_gettime, CLOCK_REALTIME};
use std::thread::sleep;
use std::time::{Duration, UNIX_EPOCH};
use chrono::{DateTime, NaiveDateTime, Utc};
use gpsd_client::*;
use std::process;
use serde::{Serialize, Deserialize};
use std::ops::Sub;
use pps_calibration::PpsCalibration;
use std::collections::VecDeque;



/// Converts ISO8601 string (what's received from the GPS) into Unix Timestamp (u64)
fn iso8601_to_u64(iso8601_string: &str) -> u64 {
    match DateTime::parse_from_rfc3339(iso8601_string) {
        Ok(dt) => dt.timestamp() as u64,
        Err(_) => 0,
    }
}

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

    pub const fn from_seconds_nanos_since_ntp_era(seconds: u32, nanos: u32) -> Self {
        let fraction = ((nanos as u64) << 32) / 1_000_000_000;
        let timestamp = ((seconds as u64) << 32) + fraction;
        NtpTimestamp::from_bits(timestamp.to_be_bytes())
    }

    pub fn from_unix_timestamp(unix_timestamp: u64, nanos: u32) -> Self {
        const UNIX_TO_NTP_OFFSET: u64 = 2_208_988_800;
        const NTP_SCALE_FRAC: u64 = 4_294_967_296;

        let ntp_seconds = unix_timestamp + UNIX_TO_NTP_OFFSET;
        let fraction = ((nanos as u64 * NTP_SCALE_FRAC) / 1_000_000_000) as u64;

        let timestamp = (ntp_seconds << 32) | fraction;
        NtpTimestamp { timestamp }
    }

    pub fn from_unix_timestamp1(unix_timestamp: u64) -> Self {
        const UNIX_TO_NTP_OFFSET: u64 = 2_208_988_800;

        let ntp_seconds = unix_timestamp + UNIX_TO_NTP_OFFSET;
        let fraction = 0u32;

        let timestamp = ((ntp_seconds as u64) << 32) | (fraction as u64);
        NtpTimestamp { timestamp }
    }
}

fn u64_to_ntpTimestamp(gps_time: u64) -> NtpTimestamp {
    NtpTimestamp::from_unix_timestamp1(gps_time)
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
    instant: std::time::Instant,
}

impl NtpInstant {
    pub fn now() -> Self {
        Self {
            instant: std::time::Instant::now(),
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
            instant: std::time::Instant::now() - duration_since_epoch,
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

    //Print raw Unix timestamp and nanoseconds
    println!("Raw Unix Timestamp: {}, Nanoseconds: {}", timestamp, nanos);

    let ntp_timestamp = NtpTimestamp::from_unix_timestamp(timestamp, nanos);

    //Print the converted NTP timestamp
    println!("Current NTP Timestamp: {:?}", ntp_timestamp);

    let time_diff = ntp_timestamp - *last_ntp_timestamp;

    //Print the time difference
    println!("Time difference: {:?}", time_diff);

    *last_ntp_timestamp = ntp_timestamp;

    /// Convert the timestamp to a readable format using chrono for verification
    let naive_datetime = NaiveDateTime::from_timestamp(timestamp as i64, nanos);
    let datetime: DateTime<Utc> = DateTime::from_utc(naive_datetime, Utc);
    println!("Readable time: {}", datetime);

    Ok(())
}

///compute the mean and standard deviation of the differences stored in VecDeque<Duration>. 
/// Used in order to evaluatethe accuracy and consistency of the PPS calibration.
fn calculate_statistics(diffs: &VecDeque<Duration>) -> (f64, f64) {
    let n = diffs.len() as f64;
    let mean: f64 = diffs.iter().map(|d| d.as_secs_f64()).sum::<f64>() / n;
    let variance: f64 = diffs.iter().map(|d| {
        let diff = d.as_secs_f64() - mean;
        diff * diff
    }).sum::<f64>() / n;
    let stddev = variance.sqrt();
    (mean, stddev)
}

fn main() -> io::Result<()> {
    let path = "/dev/pps0";
    let file = File::open(path)?;
    let fd = file.as_raw_fd();
    let mut gps: GPS = match GPS::connect() {
        Ok(t) => t,
        Err(e) => {
            println!("{e}");
            process::exit(1);
        }
    };

    let mut pps_calibration = PpsCalibration::new();
    let mut last_ntp_timestamp = NtpTimestamp::from_unix_timestamp(0, 0);

    // Warm-up period variables
    const WARM_UP_PERIOD: i32 = 10; // Number of seconds to warm up
    let mut warm_up_counter = 0;

    // Collect differences for statistical analysis
    let mut differences = VecDeque::new();
    let mut cal_diffs = VecDeque::new(); //calibarated differences


    loop {
        /// Discard initial readings in order to acquire stable gps readings
        if warm_up_counter < WARM_UP_PERIOD {
            match gps.current_data() {
                Ok(_) => {
                    // Get PPS time to discard
                    let mut ts = MaybeUninit::<libc::timespec>::uninit();
                    unsafe {
                        if libc::clock_gettime(libc::CLOCK_REALTIME, ts.as_mut_ptr()) != 0 {
                            println!("Error during PPS warm-up period: {}", std::io::Error::last_os_error());
                            sleep(Duration::from_secs(1));
                            continue;
                        }
                    }

                    println!("Warming up... {}/{}", warm_up_counter + 1, WARM_UP_PERIOD);
                    warm_up_counter += 1;
                    sleep(Duration::from_secs(1));
                    continue;
                }
                Err(e) => {
                    println!("Error during warm-up period: {}", e);
                    sleep(Duration::from_secs(1));
                    continue;
                }
            }
        }

        match gps.current_data() {
            Ok(data) => {
                let my_time: String = match data.convert_time("UTC") {
                    Ok(t) => t,
                    Err(e) => {
                        println!("Error converting time: {}", e);
                        continue;
                    }
                };
                let gps_timestamp = match DateTime::parse_from_rfc3339(&my_time) {
                    Ok(dt) => SystemTime::UNIX_EPOCH + Duration::new(dt.timestamp() as u64, dt.timestamp_subsec_nanos()),
                    Err(e) => {
                        println!("Error parsing GPS time: {}", e);
                        continue;
                    }
                };

                // Calculate PPS offset using GPS time
                if let Err(e) = pps_calibration.calculate_offset(gps_timestamp) {
                    println!("Error calculating PPS offset: {}", e);
                    continue;
                }

                // Get the PPS time and apply the offset
                let mut ts = MaybeUninit::<libc::timespec>::uninit();
                unsafe {
                    if libc::clock_gettime(libc::CLOCK_REALTIME, ts.as_mut_ptr()) != 0 {
                        println!("Error getting PPS time: {}", std::io::Error::last_os_error());
                        continue;
                    }
                }

                let ts = unsafe { ts.assume_init() };
                let pps_time = UNIX_EPOCH + Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32);
                let calibrated_pps_time = pps_calibration.apply_offset(pps_time);

                // Calculate and store differences
                let difference = gps_timestamp.duration_since(pps_time).unwrap_or(Duration::from_secs(0));
                let cal_diff = gps_timestamp.duration_since(calibrated_pps_time).unwrap_or(Duration::from_secs(0));

                differences.push_back(difference);
                cal_diffs.push_back(cal_diff);

                // Limit the size of the deque to avoid excessive memory usage
                if differences.len() > 1000 {
                    differences.pop_front();
                }
                if cal_diffs.len() > 1000 {
                    cal_diffs.pop_front();
                }

                // Print statistics every 10 iterations
                if differences.len() % 10 == 0 {
                    let (mean_raw, stddev_raw) = calculate_statistics(&differences);
                    let (mean_calibrated, stddev_calibrated) = calculate_statistics(&cal_diffs);

                    println!("Raw PPS Time difference mean: {:.6}, stddev: {:.6}", mean_raw, stddev_raw);
                    println!("Calibrated PPS Time difference mean: {:.6}, stddev: {:.6}", mean_calibrated, stddev_calibrated);
                }

                println!("GPS time: {}", pps_calibration.format_time(gps_timestamp));
                println!("PPS time (raw): {}", pps_calibration.format_time(pps_time));
                println!("PPS time (calibrated): {}", pps_calibration.format_time(calibrated_pps_time));

            },
            Err(e) => {
                println!("Error getting GPS and PPS data: {}", e);
            }
        }

        sleep(Duration::from_secs(1));
    }

    gps.close();
}