//! Definitions and implementations for the abstracted measurement filters

pub mod basic;

use crate::{port::Measurement, time::Duration};

/// A filter abstraction with which time measurements are post-processed.
/// This allows for the development of multiple filter kinds that work better or
/// worse depending on the rest of the setup.
pub trait Filter {
    /// Put a new measurement in the filter.
    /// The filter can then do some processing and return what it thinks should
    /// be the offset and frequency multiplier that the clock should be
    /// adjusted with.
    ///
    /// *Note*: The returned values aren't necessarily the 'real' offset from
    /// the master time. To prevent overshooting, oscillating, etc, the
    /// filter will apply some algorithms to prevent that.
    fn absorb(&mut self, m: Measurement) -> (Duration, f64);
}
