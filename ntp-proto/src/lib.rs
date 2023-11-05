//! This crate contains packet parsing and algorithm code for ntpd-rs and is not
//! intended as a public interface at this time. It follows the same version as the
//! main ntpd-rs crate, but that version is not intended to give any stability
//! guarantee. Use at your own risk.
//!
//! Please visit the [ntpd-rs](https://github.com/pendulum-project/ntpd-rs) project
//! for more information.
#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "__internal-api"), allow(unused))]

mod algorithm;
mod clock;
mod config;
mod cookiestash;
mod identifiers;
mod keyset;
mod nts_record;
mod packet;
mod peer;
mod system;
mod time_types;

pub(crate) mod exitcode {
    /// An internal software error has been detected.  This
    /// should be limited to non-operating system related
    /// errors as possible.
    #[cfg(not(test))]
    pub const SOFTWARE: i32 = 70;
}

mod exports {
    pub use super::algorithm::{
        AlgorithmConfig, KalmanClockController, ObservablePeerTimedata, StateUpdate,
        TimeSyncController,
    };
    pub use super::clock::NtpClock;
    pub use super::config::{SourceDefaultsConfig, StepThreshold, SynchronizationConfig};
    pub use super::identifiers::ReferenceId;
    pub use super::keyset::{DecodedServerCookie, KeySet, KeySetProvider};

    #[cfg(feature = "__internal-fuzz")]
    pub use super::keyset::test_cookie;
    #[cfg(feature = "__internal-fuzz")]
    pub use super::packet::ExtensionField;
    pub use super::packet::{
        Cipher, CipherProvider, EncryptResult, ExtensionHeaderVersion, NoCipher,
        NtpAssociationMode, NtpLeapIndicator, NtpPacket, PacketParsingError,
    };
    #[cfg(feature = "__internal-fuzz")]
    pub use super::peer::fuzz_measurement_from_packet;
    #[cfg(feature = "__internal-test")]
    pub use super::peer::peer_snapshot;
    pub use super::peer::{
        AcceptSynchronizationError, IgnoreReason, Measurement, Peer, PeerNtsData, PeerSnapshot,
        PollError, ProtocolVersion, Reach, Update,
    };
    pub use super::system::{SystemSnapshot, TimeSnapshot};
    #[cfg(feature = "__internal-fuzz")]
    pub use super::time_types::fuzz_duration_from_seconds;
    pub use super::time_types::{
        FrequencyTolerance, NtpDuration, NtpInstant, NtpTimestamp, PollInterval, PollIntervalLimits,
    };

    #[cfg(feature = "__internal-fuzz")]
    pub use super::nts_record::fuzz_key_exchange_result_decoder;
    #[cfg(feature = "__internal-fuzz")]
    pub use super::nts_record::fuzz_key_exchange_server_decoder;
    pub use super::nts_record::{
        KeyExchangeClient, KeyExchangeError, KeyExchangeResult, KeyExchangeServer, NtsRecord,
        NtsRecordDecoder, WriteError,
    };

    #[cfg(feature = "ntpv5")]
    pub mod v5 {
        pub use crate::packet::v5::server_reference_id::{BloomFilter, ServerId};
    }
}

#[cfg(feature = "__internal-api")]
pub use exports::*;

#[cfg(not(feature = "__internal-api"))]
pub(crate) use exports::*;
