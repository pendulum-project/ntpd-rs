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

mod estimator;
mod matrix;

pub use estimator::{EstimatorError, EstimatorState};
