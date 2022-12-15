#![forbid(unsafe_code)]

mod algorithm;
mod clock;
mod config;
mod cookiestash;
mod identifiers;
mod nts_record;
mod packet;
mod peer;
mod system;
mod time_types;

#[cfg(feature = "fuzz")]
pub use algorithm::fuzz_find_interval;
pub use algorithm::{
    DefaultTimeSyncController, ObservablePeerTimedata, StandardClockController, StateUpdate,
    TimeSyncController,
};
pub use clock::NtpClock;
pub use config::{StepThreshold, SystemConfig};
pub use identifiers::ReferenceId;

pub use packet::{NtpAssociationMode, NtpLeapIndicator, NtpPacket};
#[cfg(feature = "fuzz")]
pub use peer::fuzz_measurement_from_packet;
#[cfg(feature = "ext-test")]
pub use peer::peer_snapshot;
pub use peer::{
    AcceptSynchronizationError, IgnoreReason, Measurement, Peer, PeerNtsData, PeerSnapshot, Reach,
    Update,
};
pub use system::{SystemSnapshot, TimeSnapshot};
#[cfg(feature = "fuzz")]
pub use time_types::fuzz_duration_from_seconds;
pub use time_types::{
    FrequencyTolerance, NtpDuration, NtpInstant, NtpTimestamp, PollInterval, PollIntervalLimits,
};

pub use nts_record::{
    KeyExchangeClient, KeyExchangeError, KeyExchangeResult, NtsRecord, NtsRecordDecoder, WriteError,
};
