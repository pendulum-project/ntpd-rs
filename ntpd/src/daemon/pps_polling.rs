use std::process::{Command, Stdio};
use std::io::{self, BufRead, BufReader};
use ntp_proto::{NtpDuration, NtpTimestamp};

/// Struct to encapsulate the PPS polling information.
#[derive(Debug)]
pub struct Pps {
    latest_offset: Option<f64>,
}

impl Pps {
    /// Opens the PPS device and creates a new Pps instance.
    pub fn new() -> io::Result<Self> {
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
        let mut child = Command::new("sudo")
            .arg("ppstest")
            .arg("/dev/pps0")
            .stdout(Stdio::piped())
            .spawn()
            .expect("Failed to start ppstest");

        if let Some(stdout) = child.stdout.take() {
            let reader = BufReader::new(stdout);

            for line in reader.lines() {
                match line {
                    Ok(line) => {
                        if let Some((timestamp, nanos)) = Self::parse_ppstest_output(&line) {
                            let ntp_timestamp = Self::from_unix_timestamp(timestamp, nanos);
                            let offset = nanos as f64 * 1e-9;

                            if offset > 0.5 {
                                self.latest_offset = Some(offset - 1.0);
                                return Ok(Some((offset - 1.0, ntp_timestamp)));
                            } else {
                                self.latest_offset = Some(offset);
                                return Ok(Some((offset, ntp_timestamp)));
                            }
                        }
                    }
                    Err(e) => eprintln!("Error reading line: {}", e),
                }
            }
        }

        let status = child.wait()?;

        if !status.success() {
            eprintln!("ppstest exited with a non-zero status");
        }

        Ok(None)
    }

    /// Converts Unix timestamp to NtpTimestamp.
    fn from_unix_timestamp(unix_timestamp: u64, nanos: u32) -> NtpTimestamp {
        const UNIX_TO_NTP_OFFSET: u64 = 2_208_988_800; // Offset in seconds between Unix epoch and NTP epoch
        const NTP_SCALE_FRAC: u64 = 4_294_967_296; // 2^32 for scaling nanoseconds to fraction

        let ntp_seconds = unix_timestamp + UNIX_TO_NTP_OFFSET;
        let fraction = (nanos as u64 * NTP_SCALE_FRAC) / 1_000_000_000;
        let timestamp = (ntp_seconds << 32) | fraction;

        NtpTimestamp::from_fixed_int(timestamp)
    }

    fn parse_ppstest_output(line: &str) -> Option<(u64, u32)> {
        let parts: Vec<&str> = line.split_whitespace().collect();

        if parts.len() < 5 {
            return None;
        }

        if parts[0] == "source" && parts[1].starts_with('0') && parts[2] == "-" && parts[3] == "assert" {
            let timestamp_str = parts[4].trim_end_matches(',');
            if let Some((secs, nanos_str)) = timestamp_str.split_once('.') {
                let timestamp = secs.parse::<u64>().ok()?;
                let nanos = nanos_str.parse::<u32>().ok()?;
                return Some((timestamp, nanos));
            }
        }

        None
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
//         let mut pps = Pps::new().expect("Failed to open PPS device");

//         match pps.poll_pps_signal().await {
//             Ok(Some((offset, ntp_timestamp))) => {
//                 println!("PPS Offset: {}, NTP Timestamp: {:?}", offset, ntp_timestamp);
//             }
//             Ok(None) => println!("No PPS signal found."),
//             Err(e) => println!("Error: {:?}", e),
//         }
//     }
// }
