//! General datastructures as defined by the ptp spec
#![no_std]

#[cfg(feature = "std")]
extern crate std;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct ClockId(u64);
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct LinkId(u64);

mod matrix;
mod estimator;
