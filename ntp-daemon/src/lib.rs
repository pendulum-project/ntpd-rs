#![forbid(unsafe_code)]

pub mod config;
mod peer;
pub mod sockets;
mod system;
pub mod tracing;

use serde::{Deserialize, Serialize};

pub use system::spawn;
pub use system::{ObservablePeerState, Peers};

#[derive(Serialize, Deserialize)]
pub enum Observe {
    Peers,
    System,
}
