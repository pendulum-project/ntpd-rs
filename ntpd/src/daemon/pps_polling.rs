use std::mem::MaybeUninit;
use std::os::unix::io::RawFd;
use libc::{timespec, clock_gettime, CLOCK_REALTIME};
use std::io;
use ntp_proto::NtpTimestamp;
use chrono::Utc;

/// Gets the PPS time and returns it as an NtpTimestamp.
///
/// # Arguments
///
/// * `fd` - The file descriptor for the PPS device.
///
/// # Returns
///
/// * `Result<(NtpTimestamp, f64, f64), String>` - The result of getting the PPS time, the system time, and the offset.
pub async fn poll_pps_signal(fd: RawFd) -> Result<(NtpTimestamp, f64, f64), String> {
    let mut ts = MaybeUninit::<timespec>::uninit();
    unsafe {
        if clock_gettime(CLOCK_REALTIME, ts.as_mut_ptr()) != 0 {
            return Err(io::Error::last_os_error().to_string());
        }
    }

    let ts = unsafe { ts.assume_init() };
    let pps_timestamp_secs = ts.tv_sec as u64;
    let pps_timestamp_nanos = ts.tv_nsec as u32;

    let ntp_timestamp = from_unix_timestamp(pps_timestamp_secs, pps_timestamp_nanos);

    // Get the system time in seconds
    let system_time = Utc::now().timestamp() as f64 + Utc::now().timestamp_subsec_micros() as f64 * 1e-6;

    // Calculate the offset
    let pps_time = pps_timestamp_secs as f64 + pps_timestamp_nanos as f64 * 1e-9;
    let offset = (system_time - pps_time).abs();

    Ok((ntp_timestamp, system_time, offset))
}

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
        let fd: RawFd = 0; // Replace with actual file descriptor for the PPS device
        match poll_pps_signal(fd).await {
            Ok((ntp_timestamp, system_time, offset)) => {
                println!("PPS NTP Timestamp: {:?}", ntp_timestamp);
                println!("System Time: {:?}", system_time);
                println!("Offset: {:?}", offset);
            }
            Err(e) => println!("Error: {:?}", e),
        }
    }
}

