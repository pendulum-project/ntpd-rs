#![forbid(unsafe_op_in_unsafe_fn)]

mod hwtimestamp;
mod interface_name;
mod raw_socket;
mod socket;

use std::{ops::Deref, str::FromStr};

use ntp_proto::NtpTimestamp;

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
    #[serde(default)] // defaults to `false`
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

#[derive(Debug, Clone, Copy)]
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

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct InterfaceName {
    bytes: [u8; libc::IFNAMSIZ],
}

impl Deref for InterfaceName {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.bytes.as_slice()
    }
}

impl<'de> Deserialize<'de> for InterfaceName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use InterfaceNameParseError::*;

        let name: String = Deserialize::deserialize(deserializer)?;

        match Self::from_str(&name) {
            Ok(v) => Ok(v),
            Err(Empty) => Err(serde::de::Error::custom("interface name empty")),
            Err(TooLong) => Err(serde::de::Error::custom("interface name too long")),
        }
    }
}

#[derive(Debug)]
pub enum InterfaceNameParseError {
    Empty,
    TooLong,
}

impl FromStr for InterfaceName {
    type Err = InterfaceNameParseError;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        if name.is_empty() {
            return Err(InterfaceNameParseError::Empty);
        }

        let mut it = name.bytes();
        let bytes = std::array::from_fn(|_| it.next().unwrap_or_default());

        if it.next().is_some() {
            Err(InterfaceNameParseError::TooLong)
        } else {
            Ok(InterfaceName { bytes })
        }
    }
}

impl InterfaceName {
    pub const DEFAULT: Option<Self> = None;

    fn as_str(&self) -> &str {
        std::str::from_utf8(self.bytes.as_slice())
            .unwrap_or_default()
            .trim_end_matches('\0')
    }
}

impl std::fmt::Debug for InterfaceName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("InterfaceName")
            .field(&self.as_str())
            .finish()
    }
}

impl std::fmt::Display for InterfaceName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.as_str().fmt(f)
    }
}
