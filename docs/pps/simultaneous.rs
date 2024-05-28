use std::fs::File;
use std::os::unix::io::{AsRawFd, RawFd};
use std::mem::MaybeUninit;
use libc::{timespec, clock_gettime, CLOCK_REALTIME};
use std::thread::sleep;
use chrono::{DateTime, NaiveDateTime, Utc};
use std::io::{self, BufRead, BufReader, Result};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::collections::VecDeque;
use serialport::SerialPort;
use serde::{Serialize, Deserialize};
use std::ops::Sub;

mod gps_without_gpsd;
use gps_without_gpsd::{nmea_time_date_to_unix_timestamp, parse_nmea_time, parse_nmea_date, process_gnrmc, process_gngga, open_serial_port};

mod pps_calibration;
use pps_calibration::PpsCalibration;

mod kalman_filter;
use kalman_filter::KalmanFilterState;

/// Gets the PPS time and updates the last NTP timestamp.
///
/// # Arguments
///
/// * `_fd` - The file descriptor for the PPS device.
/// * `last_ntp_timestamp` - The last NTP timestamp to be updated.
///
/// # Returns
///
/// * `io::Result<()>` - The result of getting the PPS time.
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

/// Compute the mean and standard deviation of the differences stored in VecDeque<Duration>. 
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

/// The main function to run the PPS calibration process.
///
/// # Returns
///
/// * `io::Result<()>` - The result of running the main function.
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