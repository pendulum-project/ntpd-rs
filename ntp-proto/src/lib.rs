//! This crate contains packet parsing and algorithm code for ntpd-rs and is not
//! intended as a public interface at this time. It follows the same version as the
//! main ntpd-rs crate, but that version is not intended to give any stability
//! guarantee. Use at your own risk.
//!
//! Please visit the [ntpd-rs](https://github.com/pendulum-project/ntpd-rs) project
//! for more information.
#![forbid(unsafe_code)]
#![allow(missing_docs)]
#![cfg_attr(not(feature = "__internal-api"), allow(unused))]
// FIXME: the lints below should be reenabled. Please fix them with a per-lint
// PR fixing that one lint and enabling it accross all crates.
#![allow(clippy::cast_lossless)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::float_cmp)]
#![allow(clippy::if_not_else)]
#![allow(clippy::match_bool)]
#![allow(clippy::manual_midpoint)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_fields_in_debug)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::return_self_not_must_use)]
#![allow(clippy::should_panic_without_expect)]
#![allow(clippy::similar_names)]
#![allow(clippy::stable_sort_primitive)]
#![allow(clippy::struct_field_names)]
#![allow(clippy::trivially_copy_pass_by_ref)]
#![allow(clippy::unnecessary_wraps)]
#![allow(clippy::unreadable_literal)]

#[cfg(not(any(feature = "rustcrypto", feature = "openssl")))]
compile_error!("A crypto provider is needed, use '--features rustcrypto' or '--features openssl'");

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

/// Unique identifier for a source.
/// This source id makes sure that even if the network address is the same
/// that we always know which specific spawned source we are talking about.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash, Serialize, Deserialize)]
pub struct ClockId(u64);

impl ClockId {
    pub const SYSTEM: ClockId = ClockId(0);

    pub fn new() -> ClockId {
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        ClockId(COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
    }
}

impl Default for ClockId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for ClockId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

mod exports {
    pub use super::algorithm::{
        AlgorithmConfig, KalmanClockController, KalmanControllerMessage, KalmanSourceController,
        KalmanSourceMessage, Measurement, ObservableSourceTimedata, OneWaySourceControllerWrapper,
        SourceController, TimeSyncController, TimeSyncControllerWrapper,
        TwoWayKalmanSourceController, TwoWaySourceControllerWrapper,
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
    #[cfg(feature = "__internal-fuzz")]
    pub use super::server::HandleInnerData;
    pub use super::server::{
        FilterAction, FilterList, IpSubnet, Server, ServerAction, ServerConfig, ServerReason,
        ServerResponse, ServerStatHandler, SubnetParseError,
    };
    #[cfg(feature = "__internal-test")]
    pub use super::source::source_snapshot;
    pub use super::source::{
        AcceptSynchronizationError, NtpSource, NtpSourceAction, NtpSourceActionIterator,
        NtpSourceSnapshot, ObservableSourceState, OneWaySource, ProtocolVersion, Reach,
        SourceNtsData,
    };
    pub use super::system::{
        NtpManager, NtpServerInfo, NtpSnapshot, SourceType, SystemSnapshot, TimeSnapshot,
    };

    #[cfg(feature = "__internal-fuzz")]
    pub use super::time_types::fuzz_duration_from_seconds;
    pub use super::time_types::{
        FrequencyTolerance, NtpDuration, NtpTimestamp, PollInterval, PollIntervalLimits,
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

use std::sync::atomic::AtomicU64;

#[cfg(feature = "__internal-api")]
pub use exports::*;

#[cfg(not(feature = "__internal-api"))]
pub(crate) use exports::*;
use serde::{Deserialize, Serialize};
