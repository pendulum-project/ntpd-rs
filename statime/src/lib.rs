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
//! For this purpose, `statime` defines two sets of interfaces. [`Clock`] and
//! [Timer] provide access to the system clock, and allow `statime` to wait for
//! various time intervals. The [`NetworkRuntime`] and [`NetworkPort`]
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
//!
//! # Ordinary clock example
//! Assuming we already have a network runtime and clock runtime, an ordinary
//! clock can be run by first creating all the datasets, then creating the port,
//! then finally setting up the instance and starting it:
//!
//! ```ignore
//! let default_ds = DefaultDS::new_ordinary_clock(
//!     clock_identity,
//!     128,
//!     128,
//!     0,
//!     false,
//!     SdoId::new(0).unwrap(),
//! );
//! let time_properties_ds =
//! TimePropertiesDS::new_arbitrary_time(false, false, TimeSource::InternalOscillator);
//! let port_ds = PortDS::new(
//!     PortIdentity {
//!         clock_identity,
//!         port_number: 1,
//!     },
//!     1,
//!     1,
//!     3,
//!     0,
//!     DelayMechanism::E2E,
//!     1,
//! );
//! let port = Port::new(port_ds, &mut network_runtime, interface_name).await;
//! let mut instance = PtpInstance::new_ordinary_clock(
//!     default_ds,
//!     time_properties_ds,
//!     port,
//!     local_clock,
//!     BasicFilter::new(0.25),
//! );
//!
//! instance.run(&TimerImpl).await;
//! ```
//!
//! # Boundary clock
//! Setting up a boundary clock is a similar process. However, instead of
//! creating a single port, multiple ports need to be created. For example:
//!
//! ```ignore
//! let default_ds = DefaultDS::new_ordinary_clock(
//!     clock_identity,
//!     128,
//!     128,
//!     0,
//!     false,
//!     SdoId::new(0).unwrap(),
//! );
//! let time_properties_ds =
//! TimePropertiesDS::new_arbitrary_time(false, false, TimeSource::InternalOscillator);
//! let port_1_ds = PortDS::new(
//!     PortIdentity {
//!         clock_identity,
//!         port_number: 1,
//!     },
//!     1,
//!     1,
//!     3,
//!     0,
//!     DelayMechanism::E2E,
//!     1,
//! );
//! let port_1 = Port::new(port_1_ds, &mut network_runtime, interface_name_1).await;
//! let port_2_ds = PortDS::new(
//!     PortIdentity {
//!         clock_identity,
//!         port_number: 2,
//!     },
//!     1,
//!     1,
//!     3,
//!     0,
//!     DelayMechanism::E2E,
//!     1,
//! );
//! let port_2 = Port::new(port_2_ds, &mut network_runtime, interface_name_2).await;
//! let mut instance = PtpInstance::new_boundary_clock(
//!     default_ds,
//!     time_properties_ds,
//!     [port_1, port_2],
//!     local_clock,
//!     BasicFilter::new(0.25),
//! );
//!
//! instance.run(&TimerImpl).await;
//! ```

#![no_std]
#![feature(async_fn_in_trait)]
#![allow(incomplete_features)]

#[cfg(feature = "std")]
extern crate std;

mod bmc;
mod clock;
mod config;
mod datastructures;
mod filters;
mod network;
mod port;
mod ptp_instance;
mod time;
mod utils;

pub use clock::{Clock, Timer};
pub use config::{DelayMechanism, PortConfig};
#[cfg(feature = "fuzz")]
pub use datastructures::messages::Message;
pub use datastructures::{
    common::{ClockAccuracy, ClockIdentity, ClockQuality, PortIdentity, TimeSource},
    datasets::{DefaultDS, TimePropertiesDS},
    messages::{SdoId, MAX_DATA_LEN},
};
pub use filters::{basic::BasicFilter, Filter};
pub use network::{NetworkPacket, NetworkPort, NetworkRuntime};
pub use port::{Measurement, Port};
pub use ptp_instance::PtpInstance;
pub use time::{Duration, Time};
