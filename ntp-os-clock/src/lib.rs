//! This crate contains the system clock interfaces for ntpd-rs and is not intended
//! as a public interface at this time. It follows the same version as the main
//! ntpd-rs crate, but that version is not intended to give any stability guarantee.
//! Use at your own risk.
//!
//! Please visit the [ntpd-rs](https://github.com/pendulum-project/ntpd-rs) project
//! for more information.

mod unix;

#[cfg(unix)]
pub type DefaultNtpClock = unix::UnixNtpClock;

/// Errors that can be thrown by modifying a unix clock
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum Error {
    /// Insufficient permissions to interact with the clock.
    NoPermission,
    /// No access to the clock.
    NoAccess,
    /// Invalid operation requested
    Invalid,
    /// Clock device has gone away
    NoDevice,
    /// Clock operation requested is not supported by operating system.
    NotSupported,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use Error::*;

        let msg = match self {
            NoPermission => "Insufficient permissions to interact with the clock.",
            NoAccess => "No access to the clock.",
            Invalid => "Invalid operation requested",
            NoDevice => "Clock device has gone away",
            NotSupported => "Clock operation requested is not supported by operating system.",
        };

        f.write_str(msg)
    }
}

impl std::error::Error for Error {}

// Unix uses an epoch located at 1/1/1970-00:00h (UTC) and NTP uses 1/1/1900-00:00h.
// This leads to an offset equivalent to 70 years in seconds
// there are 17 leap years between the two dates so the offset is
pub(crate) const EPOCH_OFFSET: u32 = (70 * 365 + 17) * 86400;
