use std::io::{self, Result};
use nix::time::{clock_gettime, ClockId};
use ntp_proto::{NtpDuration, NtpTimestamp};


/// Struct to encapsulate the PPS polling information.
#[derive(Debug)]
pub struct Pps {
    latest_offset: Option<f64>,
}

impl Pps {
    /// Opens the PPS device and creates a new Pps instance.
    pub fn new() -> Result<Self,> {
        // Open PPS device

        // println!("Opened PPS device at {}", pps_path);

        Ok(Pps {
            latest_offset: None,
        })
    }

    /// Gets the PPS time and returns it as an NtpTimestamp.
    ///
    /// # Returns
    ///
    /// * `Result<(NtpTimestamp, f64, f64), String>` - The result of getting the PPS time, the system time, and the offset.
    pub async fn poll_pps_signal(&mut self) -> io::Result<Option<(f64, NtpTimestamp)>> {
        let ts = match clock_gettime(ClockId::CLOCK_REALTIME) {
            Ok(ts) => ts,
            Err(e) => {
                println!("Error getting time: {:?}", e);
                return Ok(None);
            }
        };

        let pps_timestamp_secs = ts.tv_sec() as u64;
        let pps_timestamp_nanos = ts.tv_nsec() as u32;

        let ntp_timestamp = Self::from_unix_timestamp(pps_timestamp_secs, pps_timestamp_nanos);

        let offset = 0.0 + pps_timestamp_nanos as f64 * 1e-9;

        if offset > 0.5 {
            self.latest_offset = Some(offset - 1.0);
            Ok(Some((offset - 1.0, ntp_timestamp)))
        } else {
            self.latest_offset = Some(offset);
            Ok(Some((offset, ntp_timestamp)))
        }

    }

    /// Converts Unix timestamp to NtpTimestamp.
    fn from_unix_timestamp(unix_timestamp: u64, nanos: u32) -> NtpTimestamp {
        const UNIX_TO_NTP_OFFSET: u64 = 2_208_988_800; // Offset in seconds between Unix epoch and NTP epoch
        const NTP_SCALE_FRAC: u64 = 4_294_967_296; // 2^32 for scaling nanoseconds to fraction

        // Calculate NTP seconds
        let ntp_seconds = unix_timestamp + UNIX_TO_NTP_OFFSET;

        // Calculate the fractional part of the NTP timestamp
        let fraction = (nanos as u64 * NTP_SCALE_FRAC) / 1_000_000_000;

        // Combine NTP seconds and fraction to form the complete NTP timestamp
        let timestamp = (ntp_seconds << 32) | fraction;

        // println!("Unix Timestamp: {}, Nanos: {}, NTP Seconds: {}, Fraction: {}", unix_timestamp, nanos, ntp_seconds, fraction);
        // println!("Combined NTP Timestamp: {:#018X}", timestamp);

        NtpTimestamp::from_fixed_int(timestamp)
    }


}



/// Enum to represent the result of PPS polling.
#[derive(Debug)]
pub enum AcceptResult {
    Accept(NtpDuration, NtpTimestamp),
    Ignore,
}


// #[cfg(test)]
// mod tests {
//     use super::*;

//     #[tokio::test]
//     async fn test_poll_pps_signal() {
//         let pps_path = "/dev/pps0"; // Replace with the actual PPS device path

//         let mut pps = Pps::new(pps_path).expect("Failed to open PPS device");


//         match pps.poll_pps_signal().await {
//             Ok((NtpDuration)) => {
//                 println!("PPS NTP Duration: {:?}", NtpDuration);
//             }
//             Err(e) => println!("Error: {:?}", e),
//         }
//     }
// }

