//! Base types and traits for time management.
#![no_std]

mod time_types;
pub use time_types::*;

#[cfg(feature = "std")]
extern crate std;
