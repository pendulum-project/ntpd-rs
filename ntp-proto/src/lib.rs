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
mod nts;
mod packet;
mod server;
mod source;
mod system;
mod time_types;

pub mod tls_utils;

pub(crate) mod exitcode {
    /// An internal software error has been detected.  This
    /// should be limited to non-operating system related
    /// errors as possible.
    #[cfg(not(test))]
    pub const SOFTWARE: i32 = 70;
}

const NTP_DEFAULT_PORT: u16 = 123;

// This is a mod so we can control visibility for the moment, but these really are intended to be the top-level things.
mod generic {
    use std::fmt::Display;

    #[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
    pub enum NtpVersion {
        V3,
        V4,
        V5,
    }

    impl NtpVersion {
        pub fn as_u8(self) -> u8 {
            self.into()
        }
    }

    #[derive(Debug)]
    pub struct InvalidNtpVersion(u8);

    impl Display for InvalidNtpVersion {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "Invalid NTP version: {}", self.0)
        }
    }

    impl std::error::Error for InvalidNtpVersion {}

    impl TryFrom<u8> for NtpVersion {
        type Error = InvalidNtpVersion;

        fn try_from(value: u8) -> Result<Self, Self::Error> {
            match value {
                3 => Ok(NtpVersion::V3),
                4 => Ok(NtpVersion::V4),
                5 => Ok(NtpVersion::V5),
                e => Err(InvalidNtpVersion(e)),
            }
        }
    }

    impl From<NtpVersion> for u8 {
        fn from(value: NtpVersion) -> Self {
            match value {
                NtpVersion::V3 => 3,
                NtpVersion::V4 => 4,
                NtpVersion::V5 => 5,
            }
        }
    }
}

mod exports {
    pub use super::algorithm::{
        AlgorithmConfig, KalmanClockController, KalmanControllerMessage, KalmanSourceController,
        KalmanSourceMessage, ObservableSourceTimedata, SourceController, StateUpdate,
        TimeSyncController, TwoWayKalmanSourceController,
    };
    pub use super::clock::NtpClock;
    pub use super::config::{SourceConfig, StepThreshold, SynchronizationConfig};
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
    #[cfg(feature = "__internal-test")]
    pub use super::source::source_snapshot;
    pub use super::source::{
        AcceptSynchronizationError, Measurement, NtpSource, NtpSourceAction,
        NtpSourceActionIterator, NtpSourceSnapshot, NtpSourceUpdate, ObservableSourceState,
        OneWaySource, OneWaySourceSnapshot, OneWaySourceUpdate, ProtocolVersion, Reach,
        SourceNtsData,
    };
    pub use super::system::{
        System, SystemAction, SystemActionIterator, SystemSnapshot, SystemSourceUpdate,
        TimeSnapshot,
    };

    #[cfg(feature = "__internal-fuzz")]
    pub use super::time_types::fuzz_duration_from_seconds;
    pub use super::time_types::{
        FrequencyTolerance, NtpDuration, NtpInstant, NtpTimestamp, PollInterval, PollIntervalLimits,
    };

    #[cfg(feature = "__internal-fuzz")]
    pub use super::nts::Request as KeyExchangeRequest;
    pub use super::nts::{
        KeyExchangeClient, KeyExchangeResult, KeyExchangeServer, NtsClientConfig, NtsError,
        NtsServerConfig,
    };
    #[cfg(feature = "__internal-fuzz")]
    pub use super::nts::{KeyExchangeResponse, NtsRecord};

    pub use super::cookiestash::MAX_COOKIES;

    pub mod v5 {
        pub use crate::packet::v5::server_reference_id::{BloomFilter, ServerId};
    }

    pub use super::generic::NtpVersion;
}

#[cfg(feature = "__internal-api")]
pub use exports::*;

#[cfg(not(feature = "__internal-api"))]
pub(crate) use exports::*;
