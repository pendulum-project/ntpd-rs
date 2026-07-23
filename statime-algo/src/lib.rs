//! General datastructures as defined by the ptp spec
#![no_std]

#[cfg(feature = "std")]
extern crate std;

/// Unique identifier for a clock
// FIXME: Move to statime-base once that exists
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct ClockId(usize);

impl ClockId {
    /// Get a new identifier for a clock.
    pub fn new() -> ClockId {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        ClockId(COUNTER.fetch_add(1, core::sync::atomic::Ordering::Relaxed))
    }
}

/// Unique identifier for a clock
// FIXME: Move to statime-base once that exists
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct LinkId(usize);

impl LinkId {
    /// Get a new identifier for a clock.
    pub fn new() -> LinkId {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        LinkId(COUNTER.fetch_add(1, core::sync::atomic::Ordering::Relaxed))
    }
}

#[cfg(test)]
macro_rules! assert_almost_eq {
    ($left:expr, $right:expr) => {
        match (&$left, &$right) {
            (left_val, right_val) => {
                assert!(
                    (*left_val - *right_val).abs() <= 1e-6 * right_val.abs(),
                    "Floating point values not almost equal.\nLeft={left_val}\nRight={right_val}"
                )
            }
        }
    };
}

mod estimator;
mod filter;
mod link_noise;
mod matrix;
mod ringbuffer;

use core::sync::atomic::AtomicUsize;

pub use estimator::{EstimatorError, EstimatorState};
pub use link_noise::{LinkNoiseError, LinkNoiseEstimator};
