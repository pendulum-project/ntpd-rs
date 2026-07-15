//! General datastructures as defined by the ptp spec
#![no_std]

#[cfg(feature = "std")]
extern crate std;

use core::fmt::Debug;

mod common;
mod messages;

pub use common::*;
pub use messages::*;

/// An error that occured during processing in this crate.
#[derive(Clone, Debug)]
pub enum Error {
    /// The provided buffer was too short for the requested operation.
    BufferTooShort,
    /// The data provided is invalid for the requested operation.
    Invalid,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::BufferTooShort => f.write_str("a buffer is too short"),
            Error::Invalid => f.write_str("an invariant was violated"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}
