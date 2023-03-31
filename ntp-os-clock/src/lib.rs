mod unix;

#[cfg(unix)]
pub type DefaultNtpClock = unix::UnixNtpClock;

#[derive(Debug, Copy, Clone, thiserror::Error)]
pub enum Error {
    #[error("Insufficient permissions to interact with the clock.")]
    NoPermission,
    #[error("Invalid operation requested")]
    Invalid,
    #[error("Clock device has gone away")]
    NoDev,
    #[error("Clock operation requested is not supported by operating system.")]
    NotSupported,
    #[error("Invalid clock path")]
    InvalidClockPath,
}

// Unix uses an epoch located at 1/1/1970-00:00h (UTC) and NTP uses 1/1/1900-00:00h.
// This leads to an offset equivalent to 70 years in seconds
// there are 17 leap years between the two dates so the offset is
pub(crate) const EPOCH_OFFSET: u32 = (70 * 365 + 17) * 86400;
