#![no_std]
#![feature(async_fn_in_trait)]
#![allow(incomplete_features)]

#[cfg(feature = "std")]
extern crate std;

pub mod bmc;
pub mod clock;
pub mod datastructures;
pub mod filters;
pub mod network;
pub mod port;
pub mod ptp_instance;
pub mod time;
mod utils;
