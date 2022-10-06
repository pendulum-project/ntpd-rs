#![forbid(unsafe_code)]

mod clock;
mod clock_select;
mod config;
mod filter;
mod identifiers;
mod packet;
mod peer;
mod time_types;

pub use clock::{ClockController, ClockUpdateResult, NtpClock};
#[cfg(feature = "fuzz")]
pub use clock_select::fuzz_find_interval;
pub use clock_select::FilterAndCombine;
#[cfg(feature = "ext-test")]
pub use clock_select::{peer_snapshot, test_peer_snapshot};
pub use config::{StepThreshold, SystemConfig};
#[cfg(feature = "fuzz")]
pub use filter::fuzz_tuple_from_packet_default;
pub use identifiers::ReferenceId;

pub use packet::{NtpAssociationMode, NtpHeader, NtpLeapIndicator};
pub use peer::{
    AcceptSynchronizationError, IgnoreReason, Peer, PeerSnapshot, PeerStatistics, Reach,
    SystemSnapshot, Update,
};
#[cfg(feature = "fuzz")]
pub use time_types::fuzz_duration_from_seconds;
pub use time_types::{FrequencyTolerance, NtpDuration, NtpInstant, NtpTimestamp, PollInterval};
