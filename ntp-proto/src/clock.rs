use crate::{NtpDuration, NtpTimestamp};

/// Interface for a clock settable by the ntp implementation.
/// This needs to be a trait as a single system can have multiple clocks
/// which need different implementation for steering and/or now.
pub trait NtpClock {
    type Error: std::error::Error;

    fn now(&self) -> Result<NtpTimestamp, Self::Error>;

    fn adjust_clock(offset: NtpDuration, freq_offset_ppm: f64) -> Result<(), Self::Error>;
}
