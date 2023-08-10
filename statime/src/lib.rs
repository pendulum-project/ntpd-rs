//! Statime is a library providing an implementation of PTP version 2.1
//! (IEEE1588-2019). It provides all the building blocks to setup PTP ordinary
//! and boundary clocks.
//!
//! Note: We are currently planning a major overhaul of the library. This will
//! also result in significant changes to the public API.
//!
//! # Device interfaces
//! `statime` is designed to be able to work with many different underlying
//! platforms, including embedded targets. This does mean that it cannot use the
//! standard library and platform specific libraries to interact with the system
//! clock and to access the network. That needs to be provided by the user of
//! the library.
//!
//! The `statime` crate defines a [`Clock`] interface that provide access to the
//! system clock. The [`NetworkRuntime`] and [`NetworkPort`]
//! abstractions provide the needed glue to access the network.
//!
//! On modern linux kernels, the `statime-linux` crate provides ready to use
//! implementations of these interfaces. For other platforms the user will need
//! to implement these themselves.
//!
//! # Clock identities
//!
//! All ptp clocks in a network need a unique clock identity. One way to achieve
//! this is to use (one of) the device's mac address to generate this
//! identifier. As this requires platform specific code to get the mac address,
//! this library does not implement this. Rather, direct access is given to the
//! clock identity type, and the user can create one from a mac address by
//! storing it in the first six bytes of the clock identifier, setting the
//! remaining bytes to 0. For more details on the exact specification of the
//! generation procedure, see IEEE1588-2019 section 7.5.2.2.2

#![no_std]

#[cfg(feature = "std")]
extern crate std;

mod bmc;
mod clock;
mod config;
mod datastructures;
mod filters;
mod port;
mod ptp_instance;
mod time;

pub use clock::Clock;
pub use config::{DelayMechanism, InstanceConfig, PortConfig};
#[cfg(feature = "fuzz")]
pub use datastructures::messages::FuzzMessage;
pub use datastructures::{
    common::{ClockAccuracy, ClockIdentity, ClockQuality, LeapIndicator, TimeSource},
    datasets::TimePropertiesDS,
    messages::{SdoId, MAX_DATA_LEN},
};
pub use filters::{basic::BasicFilter, Filter};
pub use port::{
    InBmca, Measurement, Port, PortAction, PortActionIterator, Running, TimestampContext,
};
pub use ptp_instance::PtpInstance;
pub use time::{Duration, Interval, Time};
