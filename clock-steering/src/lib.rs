//! Logic for steering OS clocks, aimed at NTP and PTP.
//!
//! This code is used in our implementations of NTP [ntpd-rs](https://github.com/pendulum-project/ntpd-rs) and PTP [statime](https://github.com/pendulum-project/statime).
use core::time::Duration;

#[cfg(target_os = "linux")]
mod linux_ioctls;

#[cfg(unix)]
pub mod unix;

/// A moment in time.
///
/// The format makes it easy to convert into libc data structures, and supports subnanoseconds that
/// certain hardware can provide for additional precision. The value is an offset from the [unix epoch](https://en.wikipedia.org/wiki/Unix_time).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Timestamp {
    pub seconds: libc::time_t,
    /// Nanos must be between 0 and 999999999 inclusive
    pub nanos: u32,
}

/// Clock adjustment capabilities
///
/// Describes the capabilities of a clock for frequency and offset adjustment.
/// Values are specified in parts-per-million (ppm) for frequency and nanoseconds for offset.
/// For realtime clocks, the values are hard-coded in the OS kernel.
/// For PTP clocks, the values are determined by the PTP hardware.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ClockCapabilities {
    /// Maximum frequency adjustment capability in parts per million.
    pub max_frequency_adjustment_ppm: f64,

    /// Maximum offset adjustment capability in nanoseconds.
    pub max_offset_adjustment_ns: u32,
}

impl Default for ClockCapabilities {
    fn default() -> Self {
        Self {
            max_frequency_adjustment_ppm: 500.0,   // 500 ppm
            max_offset_adjustment_ns: 500_000_000, // 0.5 seconds
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct TimeOffset {
    pub seconds: libc::time_t,
    /// Nanos must be between 0 and 999999999 inclusive
    pub nanos: u32,
}

/// Indicate whether a leap second must be applied
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Default)]
pub enum LeapIndicator {
    /// No leap second warning
    #[default]
    NoWarning,
    /// Last minute of the day has 61 seconds
    Leap61,
    /// Last minute of the day has 59 seconds
    Leap59,
    /// Unknown leap second status (the clock is unsynchronized)
    Unknown,
}

/// Trait for reading information from and modifying an OS clock
pub trait Clock {
    type Error: std::error::Error;

    // feature(error_in_core) https://github.com/rust-lang/rust/issues/103765
    // type Error: core::error::Error;

    /// Get the current time.
    fn now(&self) -> Result<Timestamp, Self::Error>;

    /// Get the clock's resolution.
    ///
    /// The output [`Timestamp`] will be all zeros when the resolution is
    /// unavailable.
    fn resolution(&self) -> Result<Timestamp, Self::Error>;

    /// Get the clock's adjustment capabilities.
    ///
    /// This returns information about the clock's capabilities.
    fn capabilities(&self) -> Result<ClockCapabilities, Self::Error>;

    /// Change the frequency of the clock.
    /// Returns the time at which the change was applied.
    ///
    /// The unit of the input is milliseconds (of drift) per second,
    /// compared to the "natural" frequency of the clock.
    fn set_frequency(&self, frequency: f64) -> Result<Timestamp, Self::Error>;

    /// Get the frequency of the clock
    /// The unit of the output is milliseconds (of drift) per second,
    /// compared to the "natural" frequency of the clock.
    fn get_frequency(&self) -> Result<f64, Self::Error>;

    /// Change the current time of the clock by an offset.
    /// Returns the time at which the change was applied.
    fn step_clock(&self, offset: TimeOffset) -> Result<Timestamp, Self::Error>;

    /// Change the indicators for upcoming leap seconds.
    fn set_leap_seconds(&self, leap_status: LeapIndicator) -> Result<(), Self::Error>;

    /// Disable all standard NTP kernel clock discipline. It is all your responsibility now.
    ///
    /// The disabled settings are:
    ///
    /// - [`libc::STA_PLL`]: kernel phase-locked loop
    /// - [`libc::STA_FLL`]: kernel frequency-locked loop
    /// - [`libc::STA_PPSTIME`]: pulse-per-second time
    /// - [`libc::STA_PPSFREQ`]: pulse-per-second frequency discipline
    fn disable_kernel_ntp_algorithm(&self) -> Result<(), Self::Error>;

    /// Set the offset between TAI and UTC.
    fn set_tai(&self, tai_offset: i32) -> Result<(), Self::Error>;

    /// Get the offset between TAI and UTC.
    fn get_tai(&self) -> Result<i32, Self::Error>;

    /// Provide the system with the current best estimates for the statistical
    /// error of the clock, and the maximum deviation due to frequency error and
    /// distance to the root clock.
    fn error_estimate_update(
        &self,
        estimated_error: Duration,
        maximum_error: Duration,
    ) -> Result<(), Self::Error>;
}
