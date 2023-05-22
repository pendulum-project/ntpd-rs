#![no_std]
#![feature(async_fn_in_trait)]
#![allow(incomplete_features)]

#[cfg(feature = "std")]
extern crate std;

mod bmc;
mod clock;
mod datastructures;
mod filters;
mod network;
mod port;
mod ptp_instance;
mod time;
mod utils;

pub use clock::{Clock, Timer};
pub use datastructures::{
    common::{ClockAccuracy, ClockIdentity, ClockQuality, PortIdentity, TimeSource},
    datasets::{DefaultDS, DelayMechanism, PortDS, TimePropertiesDS},
    messages::{SdoId, MAX_DATA_LEN},
};
pub use filters::basic::BasicFilter;
pub use network::{NetworkPacket, NetworkPort, NetworkRuntime};
pub use port::Port;
pub use ptp_instance::PtpInstance;
pub use time::{Duration, Instant};
