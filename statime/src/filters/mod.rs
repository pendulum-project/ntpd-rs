//! Definitions and implementations for the abstracted measurement filters

pub mod basic;

use crate::{port::Measurement, time::Duration};

/// A filter for post-processing time measurements.
///
/// Filters are responsible for dealing with the network noise, and should
/// average out the input a bit so minor network variations are not immediately
/// reflected in the synchronization of the clock.
///
/// This crate provides a simple [`BasicFilter`](basic::BasicFilter) which is
/// suitable for most needs, but users can implement their own if desired.
pub trait Filter {
    /// Put a new measurement in the filter.
    /// The filter can then do some processing and return what it thinks should
    /// be the offset and frequency multiplier that the clock should be
    /// adjusted with.
    ///
    /// *Note*: The returned values aren't necessarily the 'real' offset from
    /// the master time. To prevent overshooting, oscillating, etc, the
    /// filter is allowed to apply some algorithms to prevent that.
    fn absorb(&mut self, m: Measurement) -> (Duration, f64);
}
