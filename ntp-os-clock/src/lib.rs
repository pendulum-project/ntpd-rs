#[cfg(target_os = "linux")]
mod linux;
mod unix;

#[cfg(target_os = "linux")]
pub type DefaultNtpClock = linux::LinuxNtpClock;

#[cfg(any(target_os = "freebsd", target_os = "macos"))]
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
}

// Unix uses an epoch located at 1/1/1970-00:00h (UTC) and NTP uses 1/1/1900-00:00h.
// This leads to an offset equivalent to 70 years in seconds
// there are 17 leap years between the two dates so the offset is
pub(crate) const EPOCH_OFFSET: u32 = (70 * 365 + 17) * 86400;
