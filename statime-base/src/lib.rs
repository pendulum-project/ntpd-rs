//! Base types and traits for time management.
#![no_std]

mod algorithm;
mod clock;
mod identifiers;
mod time_types;

pub use algorithm::*;
pub use clock::*;
pub use identifiers::*;
pub use time_types::*;

#[cfg(feature = "std")]
extern crate std;
