//! This crate contains networking and timestamping code for ntpd-rs and is not
//! intended as a public interface at this time. It follows the same version as the
//! main ntpd-rs crate, but that version is not intended to give any stability
//! guarantee. Use at your own risk.
//!
//! Please visit the [ntpd-rs](https://github.com/pendulum-project/ntpd-rs) project
//! for more information.
#![forbid(unsafe_op_in_unsafe_fn)]

mod interface;
mod raw_socket;
mod socket;

#[cfg(target_os = "linux")]
mod hwtimestamp;

use ntp_proto::NtpTimestamp;

pub use interface::InterfaceName;
use serde::Deserialize;
pub use socket::UdpSocket;

/// Enable the given timestamps. This is a hint!
///
/// Your OS or hardware might not actually support some timestamping modes.
/// Unsupported timestamping modes are ignored.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct EnableTimestamps {
    #[serde(default = "bool_true")]
    pub rx_software: bool,
    #[serde(default = "bool_true")]
    pub tx_software: bool,
    #[serde(default)] // defaults to `false`
    pub rx_hardware: bool,
    #[serde(default)] // defaults to `false`
    pub tx_hardware: bool,
}

impl Default for EnableTimestamps {
    fn default() -> Self {
        Self {
            rx_software: true,
            tx_software: false,
            rx_hardware: false,
            tx_hardware: false,
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum LibcTimestamp {
    #[cfg_attr(any(target_os = "macos", target_os = "freebsd"), allow(unused))]
    TimeSpec {
        seconds: i64,
        nanos: i64,
    },
    TimeVal {
        seconds: i64,
        micros: i64,
    },
}

impl LibcTimestamp {
    #[cfg_attr(any(target_os = "macos", target_os = "freebsd"), allow(unused))]
    fn from_timespec(timespec: libc::timespec) -> Self {
        Self::TimeSpec {
            seconds: timespec.tv_sec as _,
            nanos: timespec.tv_nsec as _,
        }
    }

    #[cfg_attr(target_os = "linux", allow(unused))]
    fn from_timeval(timespec: libc::timeval) -> Self {
        Self::TimeVal {
            seconds: timespec.tv_sec as _,
            micros: timespec.tv_usec as _,
        }
    }
}

impl LibcTimestamp {
    pub(crate) fn into_ntp_timestamp(self) -> NtpTimestamp {
        // Unix uses an epoch located at 1/1/1970-00:00h (UTC) and NTP uses 1/1/1900-00:00h.
        // This leads to an offset equivalent to 70 years in seconds
        // there are 17 leap years between the two dates so the offset is
        const EPOCH_OFFSET: u32 = (70 * 365 + 17) * 86400;

        match self {
            LibcTimestamp::TimeSpec { seconds, nanos } => {
                // truncates the higher bits of the i64
                let seconds = (seconds as u32).wrapping_add(EPOCH_OFFSET);

                // tv_nsec is always within [0, 1e10)
                let nanos = nanos as u32;

                NtpTimestamp::from_seconds_nanos_since_ntp_era(seconds, nanos)
            }
            LibcTimestamp::TimeVal { seconds, micros } => {
                // truncates the higher bits of the i64
                let seconds = (seconds as u32).wrapping_add(EPOCH_OFFSET);
                let nanos = micros as u32 * 1000;

                NtpTimestamp::from_seconds_nanos_since_ntp_era(seconds, nanos)
            }
        }
    }
}

fn bool_true() -> bool {
    true
}
