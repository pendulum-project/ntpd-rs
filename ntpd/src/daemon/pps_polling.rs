use std::fs::File;
use std::io;
use std::os::unix::io::{AsRawFd, RawFd};
use std::mem::MaybeUninit;
use std::time::Duration;
use libc::{timespec, clock_gettime, CLOCK_REALTIME};
use ntp_proto::NtpTimestamp;
use chrono::{Utc, DateTime};

/// Struct to encapsulate the PPS polling information.
#[derive(Debug)]
pub struct Pps {
    fd: RawFd,
    latest_offset: Option<f64>,
}

impl Pps {
    /// Opens the PPS device and creates a new Pps instance.
    pub fn new(pps_path: &str) -> Result<Self, io::Error> {
        // Open PPS device
        let file = File::open(pps_path)?;
        let fd = file.as_raw_fd();

        println!("Opened PPS device at {}", pps_path);

        Ok(Pps {
            fd,
            latest_offset: None,
        })
    }

    /// Gets the PPS time and returns it as an NtpTimestamp.
    ///
    /// # Returns
    ///
    /// * `Result<(NtpTimestamp, f64, f64), String>` - The result of getting the PPS time, the system time, and the offset.
    pub async fn poll_pps_signal(&mut self) -> Result<(NtpTimestamp, f64, f64), String> {
        let mut ts = MaybeUninit::<timespec>::uninit();
        unsafe {
            if clock_gettime(CLOCK_REALTIME, ts.as_mut_ptr()) != 0 {
                return Err(io::Error::last_os_error().to_string());
            }
        }

        let ts = unsafe { ts.assume_init() };
        let pps_timestamp_secs = ts.tv_sec as u64;
        let pps_timestamp_nanos = ts.tv_nsec as u32;

        let ntp_timestamp = Self::from_unix_timestamp(pps_timestamp_secs, pps_timestamp_nanos);

        println!("PPS Timestamp - Seconds: {}, Nanoseconds: {}", pps_timestamp_secs, pps_timestamp_nanos);
        println!("NTP Timestamp: {:?}", ntp_timestamp);

        // Get the system time in seconds
        let system_time = Utc::now();
        let system_time_secs = system_time.timestamp() as f64 + system_time.timestamp_subsec_micros() as f64 * 1e-6;

        println!("System Time: {}", system_time_secs);

        // Calculate the offset
        let pps_time = pps_timestamp_secs as f64 + pps_timestamp_nanos as f64 * 1e-9;
        let offset = (system_time_secs - pps_time).abs();

        println!("Offset: {}", offset);

        // Update the struct fields with the latest values
        self.latest_offset = Some(offset);

        Ok((ntp_timestamp, system_time_secs, offset))
    }

    /// Converts Unix timestamp to NtpTimestamp.
    fn from_unix_timestamp(unix_timestamp: u64, nanos: u32) -> NtpTimestamp {
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

        NtpTimestamp::from_fixed_int(timestamp)
    }

    /// Result handling for PPS polling.
    pub fn accept_pps_time(result: Result<(NtpTimestamp, f64, f64), String>) -> AcceptResult {
        match result {
            Ok((timestamp, system_time, offset)) => {
                println!("Accepted PPS Time - NTP Timestamp: {:?}, System Time: {}, Offset: {}", timestamp, system_time, offset);
                AcceptResult::Accept(timestamp, system_time, offset)
            },
            Err(receive_error) => {
                println!("Could not receive PPS signal: {:?}", receive_error);
                AcceptResult::Ignore
            }
        }
    }
}

/// Enum to represent the result of PPS polling.
#[derive(Debug)]
pub enum AcceptResult {
    Accept(NtpTimestamp, f64, f64),
    Ignore,
}

pub fn accept_pps_time(result: Result<(NtpTimestamp, f64, f64), String>) -> AcceptResult {
    match result {
        Ok((timestamp, system_time, offset)) => AcceptResult::Accept(timestamp, system_time, offset),
        Err(receive_error) => {
            warn!(?receive_error, "could not receive PPS signal");
            AcceptResult::Ignore
        }
    }
}


pub fn from_unix_timestamp(unix_timestamp: u64, nanos: u32) -> NtpTimestamp {
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

    NtpTimestamp::from_fixed_int(timestamp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_poll_pps_signal() {
        let pps_path = "/dev/pps0"; // Replace with the actual PPS device path

        let mut pps = Pps::new(pps_path).expect("Failed to open PPS device");

        match pps.poll_pps_signal().await {
            Ok((ntp_timestamp, system_time, offset)) => {
                println!("PPS NTP Timestamp: {:?}", ntp_timestamp);
                println!("System Time: {:?}", system_time);
                println!("Offset: {:?}", offset);
            }
            Err(e) => println!("Error: {:?}", e),
        }
    }
}

