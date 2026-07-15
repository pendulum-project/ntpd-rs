//! General datastructures as defined by the ptp spec
#![no_std]

use statime_wire::{ClockIdentity, ClockQuality};

#[cfg(feature = "std")]
extern crate std;

mod manager;
mod messages;
mod platform;
mod server;
mod source;

pub use manager::{CsptpConfig, CsptpManager};
pub use platform::{InternalState, StateMutex};
pub use server::{ServerRecvResult, ServerSocket, serve};
pub use source::{ClientRecvResult, ClientSocket, CsptpSource, CsptpSourceConfig};

/// Observable CSPTP state
#[derive(Debug, Copy, Clone)]
pub struct CsptpState {
    /// Clock identity of grandmaster currently in use. This will be the local
    /// clock identity if there is no upstream time source or the if the
    /// upstream time source does not use CSPTP
    pub grandmaster_identity: ClockIdentity,
    /// Priority 1 for the grandmaster currently in use. This will be the local
    /// value if there is no upstream time source or the if the upstream time
    /// source does not use CSPTP
    pub grandmaster_priority_1: u8,
    /// Priority 2 for the grandmaster currently in use. This will be the local
    /// value if there is no upstream time source or the if the upstream time
    /// source does not use CSPTP
    pub grandmaster_priority_2: u8,
    /// Clock quality for the grandmaster currently in use. This will be the
    /// local value if there is no upstream time source or the if the upstream
    /// time source does not use CSPTP
    pub grandmaster_clock_quality: ClockQuality,
    /// Steps removed from the current grandmaster. Will be 0 if there is no
    /// upstream time source or the upstream time source does not use CSPTP.
    pub steps_removed: u16,
    /// Whether the ptp timescale is in use.
    pub ptp_timescale: bool,
    /// Whether the current time is traceable.
    pub time_traceable: bool,
    /// Whether the current frequency is traceable.
    pub frequency_traceable: bool,
}
