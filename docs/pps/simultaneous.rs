use std::fs::File;
use std::os::unix::io::{AsRawFd, RawFd};
use std::mem::MaybeUninit;
use libc::{timespec, clock_gettime, CLOCK_REALTIME};
use std::thread::sleep;
use chrono::{DateTime, NaiveDateTime, Utc, NaiveDate, NaiveTime};
use std::process;
use serde::{Serialize, Deserialize};
use std::ops::Sub;
use std::collections::VecDeque;
use serialport::SerialPort;
use std::io::{self, BufRead, BufReader, Result};
use std::time::{Duration, SystemTime, UNIX_EPOCH};


pub struct PpsCalibration {
    pps_offset: Duration,
}

impl PpsCalibration {
    pub fn new() -> Self {
        PpsCalibration {
            pps_offset: Duration::from_secs(0),
        }
    }

    pub fn calculate_offset(&mut self, gps_time: SystemTime) -> io::Result<()> {
        let mut ts = MaybeUninit::<timespec>::uninit();

        unsafe {
            if clock_gettime(CLOCK_REALTIME, ts.as_mut_ptr()) != 0 {
                return Err(io::Error::last_os_error());
            }
        }

        let ts = unsafe { ts.assume_init() };
        let pps_time = UNIX_EPOCH + Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32);

        self.pps_offset = gps_time.duration_since(pps_time).unwrap_or(Duration::from_secs(0));

        println!("Calculated PPS Offset: {:?}", self.pps_offset);
        Ok(())
    }

    pub fn apply_offset(&self, timestamp: SystemTime) -> SystemTime {
        timestamp + self.pps_offset
    }
}

fn nmea_time_date_to_unix_timestamp(nmea_time: &str, nmea_date: &str) -> Option<SystemTime> {
    let (hour, minute, second) = parse_nmea_time(nmea_time)?;
    let (day, month, year) = parse_nmea_date(nmea_date)?;

    let naive_date = NaiveDate::from_ymd_opt(2000 + year as i32, month, day)?;
    let naive_time = NaiveTime::from_hms_micro_opt(
        hour,
        minute,
        second.trunc() as u32,
        (second.fract() * 1_000_000.0) as u32,
    )?;

    let naive_datetime = NaiveDateTime::new(naive_date, naive_time);
    let timestamp = UNIX_EPOCH + Duration::from_secs(naive_datetime.timestamp() as u64) + Duration::from_micros(naive_datetime.timestamp_subsec_micros() as u64);

    Some(timestamp)
}

fn parse_nmea_time(nmea_time: &str) -> Option<(u32, u32, f64)> {
    let hour: u32 = nmea_time.get(0..2)?.parse().ok()?;
    let minute: u32 = nmea_time.get(2..4)?.parse().ok()?;
    let second: f64 = nmea_time.get(4..10)?.parse().ok()?;
    Some((hour, minute, second))
}

fn parse_nmea_date(nmea_date: &str) -> Option<(u32, u32, u32)> {
    let day: u32 = nmea_date.get(0..2)?.parse().ok()?;
    let month: u32 = nmea_date.get(2..4)?.parse().ok()?;
    let year: u32 = nmea_date.get(4..6)?.parse().ok()?;
    Some((day, month, year))
}

fn process_gnrmc(fields: &[&str], current_date: &mut Option<String>) {
    if is_valid_gnrmc(fields) {
        if let Some(date) = fields.get(9) {
            *current_date = Some(date.to_string());
        }
    }
}

fn is_valid_gnrmc(fields: &[&str]) -> bool {
    fields.len() > 9 && fields[2] == "A"
}

fn process_gngga(fields: &[&str], current_date: &Option<String>) -> Option<SystemTime> {
    if let Some(time) = fields.get(1) {
        if let Some(date) = current_date {
            if let Some(unix_timestamp) = nmea_time_date_to_unix_timestamp(time, date) {
                print_unix_timestamp(unix_timestamp);
                return Some(unix_timestamp);
            } else {
                eprintln!("Error: Invalid NMEA time/date format");
            }
        } else {
            eprintln!("Error: Current date is missing for GNGGA processing");
        }
    } else {
        eprintln!("Error: Time field is missing in GNGGA sentence");
    }
    None
}

fn print_unix_timestamp(timestamp: SystemTime) {
    let duration_since_epoch = timestamp.duration_since(UNIX_EPOCH).unwrap();
    println!("Unix timestamp with fractional seconds: {:.6}", duration_since_epoch.as_secs_f64());
}

fn open_serial_port(port_name: &str, baud_rate: u32, timeout: Duration) -> io::Result<Box<dyn SerialPort>> {
    match serialport::new(port_name, baud_rate).timeout(timeout).open() {
        Ok(port) => Ok(port),
        Err(e) => {
            eprintln!("Failed to open port {}: {}", port_name, e);
            Err(e.into())
        }
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

fn get_pps_time(_fd: RawFd, last_ntp_timestamp: &mut NtpTimestamp) -> io::Result<()> {
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

    let port_name = "/dev/serial0";
    let port = open_serial_port(port_name, 9600, Duration::from_secs(10))?;
    println!("Opened port successfully: {}", port_name);
    let mut reader = BufReader::new(port);
    let mut current_date = None;
    let mut pps_calibration = PpsCalibration::new();
    let mut last_ntp_timestamp = NtpTimestamp::from_unix_timestamp1(0);

    const WARM_UP_PERIOD: i32 = 10; // Number of seconds to warm up
    let mut warm_up_counter = 0;

    let mut differences = VecDeque::new();
    let mut cal_diffs = VecDeque::new(); // Calibrated differences

    let mut line = String::new();

    loop {
        if warm_up_counter < WARM_UP_PERIOD {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(_) => {
                    let fields: Vec<&str> = line.trim().split(',').collect();
                    if line.starts_with("$GNRMC") {
                        println!("raw gnrmc: {}", line);
                        process_gnrmc(&fields, &mut current_date);
                    } else if line.starts_with("$GNGGA") {
                        println!("raw ggna: {}", line);
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
                    }
                },
                Err(e) => {
                    println!("Error during warm-up period: {}", e);
                    sleep(Duration::from_secs(1));
                    continue;
                }
            }
            continue;
        }

        line.clear();
        match reader.read_line(&mut line) {
            Ok(_) => {
                let fields: Vec<&str> = line.trim().split(',').collect();
                if line.starts_with("$GNRMC") {
                    process_gnrmc(&fields, &mut current_date);
                } else if line.starts_with("$GNGGA") {
                    if let Some(gps_timestamp) = process_gngga(&fields, &current_date) {
                        if let Err(e) = pps_calibration.calculate_offset(gps_timestamp) {
                            println!("Error calculating PPS offset: {}", e);
                            continue;
                        }

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

                        let difference = gps_timestamp.duration_since(pps_time).unwrap_or(Duration::from_secs(0));
                        let cal_diff = gps_timestamp.duration_since(calibrated_pps_time).unwrap_or(Duration::from_secs(0));

                        differences.push_back(difference);
                        cal_diffs.push_back(cal_diff);

                        if differences.len() > 1000 {
                            differences.pop_front();
                        }
                        if cal_diffs.len() > 1000 {
                            cal_diffs.pop_front();
                        }

                        if differences.len() % 10 == 0 {
                            let (mean_raw, stddev_raw) = calculate_statistics(&differences);
                            let (mean_calibrated, stddev_calibrated) = calculate_statistics(&cal_diffs);

                            println!("Raw PPS Time difference mean: {:.6}, stddev: {:.6}", mean_raw, stddev_raw);
                            println!("Calibrated PPS Time difference mean: {:.6}, stddev: {:.6}", mean_calibrated, stddev_calibrated);
                        }

                        let gps_unix_timestamp = gps_timestamp.duration_since(UNIX_EPOCH).unwrap().as_secs();
                        let pps_unix_timestamp = pps_time.duration_since(UNIX_EPOCH).unwrap().as_secs();
                        let calibrated_pps_unix_timestamp = calibrated_pps_time.duration_since(UNIX_EPOCH).unwrap().as_secs();

                        // Using from_unix_timestamp and from_unix_timestamp1 to calculate NTP timestamps
                        let gps_ntp_timestamp = NtpTimestamp::from_unix_timestamp1(gps_unix_timestamp);
                        let pps_ntp_timestamp = NtpTimestamp::from_unix_timestamp(pps_unix_timestamp, ts.tv_nsec as u32);
                        let calibrated_pps_ntp_timestamp = NtpTimestamp::from_unix_timestamp(calibrated_pps_unix_timestamp, calibrated_pps_time.duration_since(UNIX_EPOCH).unwrap().subsec_nanos());

                        println!("GPS time (Unix): {}", gps_unix_timestamp);
                        println!("GPS time (NTP): {:?}", gps_ntp_timestamp);
                        println!("PPS time (Unix): {}", pps_unix_timestamp);
                        println!("PPS time (NTP): {:?}", pps_ntp_timestamp);
                        println!("Calibrated PPS time (Unix): {}", calibrated_pps_unix_timestamp);
                        println!("Calibrated PPS time (NTP): {:?}", calibrated_pps_ntp_timestamp);
                    }
                }
            },
            Err(e) => {
                println!("Error getting GPS and PPS data: {}", e);
                sleep(Duration::from_secs(1));
            }
        }

        sleep(Duration::from_secs(1));
    }
}