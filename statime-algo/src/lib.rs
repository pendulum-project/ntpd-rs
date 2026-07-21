//! General datastructures as defined by the ptp spec
#![no_std]

#[cfg(feature = "std")]
extern crate std;

/// TODO: replace
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ClockId(u64);

/// TODO: replace
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LinkId(u64);

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
mod link_noise;
mod matrix;

pub use estimator::{EstimatorError, EstimatorState};
pub use link_noise::{LinkNoiseError, LinkNoiseEstimator};
