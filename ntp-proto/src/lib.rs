#![forbid(unsafe_code)]

mod algorithm;
mod clock;
mod clock_select;
mod config;
mod filter;
mod identifiers;
mod packet;
mod peer;
mod time_types;

pub use algorithm::{DefaultTimeSyncController, TimeSyncController};
pub use clock::{ClockController, ClockUpdateResult, NtpClock};
#[cfg(feature = "fuzz")]
pub use clock_select::fuzz_find_interval;
pub use clock_select::FilterAndCombine;
#[cfg(feature = "ext-test")]
pub use clock_select::{peer_snapshot, test_peer_snapshot};
pub use config::{StepThreshold, SystemConfig};
pub use identifiers::ReferenceId;

pub use packet::{NtpAssociationMode, NtpLeapIndicator, NtpPacket};
#[cfg(feature = "fuzz")]
pub use peer::fuzz_measurement_from_packet;
pub use peer::{
    AcceptSynchronizationError, IgnoreReason, Peer, PeerSnapshot, PeerStatistics, PeerTimeSnapshot,
    Reach, SystemSnapshot, TimeSnapshot, Update,
};
#[cfg(feature = "fuzz")]
pub use time_types::fuzz_duration_from_seconds;
pub use time_types::{
    FrequencyTolerance, NtpDuration, NtpInstant, NtpTimestamp, PollInterval, PollIntervalLimits,
};
