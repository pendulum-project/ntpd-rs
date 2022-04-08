use crate::{NtpDuration, NtpTimestamp};

/// Interface for a clock settable by the ntp implementation.
pub trait NtpClock {
    type Error: std::error::Error;

    fn now(&self) -> Result<NtpTimestamp, Self::Error>;

    fn adjust_clock(offset: NtpDuration, freq_offset_ppm: f64) -> Result<(), Self::Error>;
}
