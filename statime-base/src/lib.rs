//! Base types and traits for time management.
#![no_std]

mod clock;
mod identifiers;
mod time_types;

pub use clock::*;
pub use identifiers::*;
pub use time_types::*;

#[cfg(feature = "std")]
extern crate std;
