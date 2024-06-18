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
mod io;
mod ipfilter;
mod keyset;
mod nts_record;
mod packet;
mod server;
mod source;
mod system;
mod time_types;
pub mod gps_source;
pub use gps_source::GpsSource;
pub use gps_source::GpsSourceAction;
pub use gps_source::GpsSourceActionIterator;
pub use gps_source::GpsSourceUpdate;
pub mod pps_source;
pub use pps_source::PpsSource;
pub use pps_source::PpsSourceAction;
pub use pps_source::PpsSourceActionIterator;
pub use pps_source::PpsSourceUpdate;

#[cfg(feature = "nts-pool")]
mod nts_pool_ke;
#[cfg(feature = "nts-pool")]
pub mod tls_utils;

pub(crate) mod exitcode {
    /// An internal software error has been detected.  This
    /// should be limited to non-operating system related
    /// errors as possible.
    #[cfg(not(test))]
    pub const SOFTWARE: i32 = 70;
}

mod exports {
    pub use super::algorithm::{
        AlgorithmConfig, KalmanClockController, ObservableSourceTimedata, StateUpdate,
        TimeSyncController,
    };
    pub use super::clock::NtpClock;
    pub use super::config::{SourceDefaultsConfig, StepThreshold, SynchronizationConfig};
    pub use super::identifiers::ReferenceId;
    #[cfg(feature = "__internal-fuzz")]
    pub use super::ipfilter::fuzz::fuzz_ipfilter;
    pub use super::keyset::{DecodedServerCookie, KeySet, KeySetProvider};

    #[cfg(feature = "__internal-fuzz")]
    pub use super::keyset::test_cookie;
    #[cfg(feature = "__internal-fuzz")]
    pub use super::packet::ExtensionField;
    pub use super::packet::{
        Cipher, CipherProvider, EncryptResult, ExtensionHeaderVersion, NoCipher,
        NtpAssociationMode, NtpLeapIndicator, NtpPacket, PacketParsingError,
    };
    pub use super::server::{
        FilterAction, FilterList, IpSubnet, Server, ServerAction, ServerConfig, ServerReason,
        ServerResponse, ServerStatHandler, SubnetParseError,
    };
    #[cfg(feature = "__internal-fuzz")]
    pub use super::source::fuzz_measurement_from_packet;
    #[cfg(feature = "__internal-test")]
    pub use super::source::{source_snapshot, Measurement};
    pub use super::source::{
        AcceptSynchronizationError, NtpSource, NtpSourceAction, NtpSourceActionIterator,
        NtpSourceSnapshot, NtpSourceUpdate, ProtocolVersion, Reach, SourceNtsData,
    };
    pub use super::system::{System, SystemSnapshot, TimeSnapshot};
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

    #[cfg(feature = "nts-pool")]
    pub use super::nts_record::AeadAlgorithm;

    #[cfg(feature = "nts-pool")]
    pub use super::nts_pool_ke::{
        ClientToPoolData, ClientToPoolDecoder, PoolToServerData, PoolToServerDecoder,
        SupportedAlgorithmsDecoder,
    };
}

#[cfg(feature = "__internal-api")]
pub use exports::*;

#[cfg(not(feature = "__internal-api"))]
pub(crate) use exports::*;
