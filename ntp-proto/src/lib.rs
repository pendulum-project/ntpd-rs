#![forbid(unsafe_code)]

mod algorithm;
mod clock;
mod clock_select;
mod config;
mod filter;
mod identifiers;
mod nts_record;
mod packet;
mod peer;
mod time_types;

pub use algorithm::{DefaultTimeSyncController, TimeSyncController};
pub use clock::{ClockController, ClockUpdateResult, NtpClock};
#[cfg(feature = "fuzz")]
pub use clock_select::fuzz_find_interval;
#[cfg(feature = "ext-test")]
pub use clock_select::peer_snapshot;
pub use clock_select::FilterAndCombine;
pub use config::{StepThreshold, SystemConfig};
pub use identifiers::ReferenceId;

pub use packet::{NtpAssociationMode, NtpLeapIndicator, NtpPacket};
#[cfg(feature = "fuzz")]
pub use peer::fuzz_measurement_from_packet;
pub use peer::{
    AcceptSynchronizationError, IgnoreReason, Measurement, Peer, PeerSnapshot, PeerStatistics,
    PeerTimeSnapshot, Reach, SystemSnapshot, TimeSnapshot, Update,
};
#[cfg(feature = "fuzz")]
pub use time_types::fuzz_duration_from_seconds;
pub use time_types::{
    FrequencyTolerance, NtpDuration, NtpInstant, NtpTimestamp, PollInterval, PollIntervalLimits,
};

pub use nts_record::{NtsRecord, WriteError};
