#![forbid(unsafe_op_in_unsafe_fn)]

mod interface_name;
mod raw_socket;
mod socket;

use ntp_proto::NtpTimestamp;

pub use socket::UdpSocket;

#[derive(Debug, Clone, Copy, serde::Deserialize)]
pub struct TimestampingConfig {
    #[serde(default = "bool_true")]
    pub rx_software: bool,
    #[serde(default)] // defaults to `false`
    pub tx_software: bool,
}

impl Default for TimestampingConfig {
    fn default() -> Self {
        Self {
            rx_software: true,
            tx_software: false,
        }
    }
}

impl TimestampingConfig {
    fn all_supported(udp_socket: &std::net::UdpSocket) -> std::io::Result<Self> {
        crate::raw_socket::timestamping_config::all_supported(udp_socket)
    }
}

pub(crate) enum LibcTimestamp {
    Timespec(libc::timespec),
    Timeval(libc::timeval),
}

impl LibcTimestamp {
    pub(crate) fn into_ntp_timestamp(self) -> NtpTimestamp {
        // Unix uses an epoch located at 1/1/1970-00:00h (UTC) and NTP uses 1/1/1900-00:00h.
        // This leads to an offset equivalent to 70 years in seconds
        // there are 17 leap years between the two dates so the offset is
        const EPOCH_OFFSET: u32 = (70 * 365 + 17) * 86400;

        match self {
            LibcTimestamp::Timespec(timespec) => {
                // truncates the higher bits of the i64
                let seconds = (timespec.tv_sec as u32).wrapping_add(EPOCH_OFFSET);

                // tv_nsec is always within [0, 1e10)
                let nanos = timespec.tv_nsec as u32;

                NtpTimestamp::from_seconds_nanos_since_ntp_era(seconds, nanos)
            }
            LibcTimestamp::Timeval(timeval) => {
                // truncates the higher bits of the i64
                let seconds = (timeval.tv_sec as u32).wrapping_add(EPOCH_OFFSET);

                let micros = timeval.tv_usec as u32;
                let nanos = micros * 1000;

                NtpTimestamp::from_seconds_nanos_since_ntp_era(seconds, nanos)
            }
        }
    }
}

fn bool_true() -> bool {
    true
}
