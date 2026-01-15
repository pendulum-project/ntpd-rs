//! This crate contains packet parsing and algorithm code for ntpd-rs and is not
//! intended as a public interface at this time. It follows the same version as the
//! main ntpd-rs crate, but that version is not intended to give any stability
//! guarantee. Use at your own risk.
//!
//! Please visit the [ntpd-rs](https://github.com/pendulum-project/ntpd-rs) project
//! for more information.
#![forbid(unsafe_code)]
//FIXME: Remove once https://github.com/rust-lang/rust-clippy/issues/16394 is resolved
#![allow(renamed_and_removed_lints)]
#![warn(clippy::assigning_clones)]
#![warn(clippy::bool_to_int_with_if)]
#![warn(clippy::borrow_as_ptr)]
#![warn(clippy::case_sensitive_file_extension_comparisons)]
//FIXME: Enable #![warn(clippy::cast_lossless)]
//FIXME: Enable #![warn(clippy::cast_possible_truncation)]
//FIXME: Enable #![warn(clippy::cast_possible_wrap)]
//FIXME: Enable #![warn(clippy::cast_precision_loss)]
#![warn(clippy::cast_ptr_alignment)]
//FIXME: Enable #![warn(clippy::cast_sign_loss)]
//FIXME: Enable #![warn(clippy::checked_conversions)]
//FIXME: Enable #![warn(clippy::cloned_instead_of_copied)]
#![warn(clippy::comparison_chain)]
#![warn(clippy::copy_iterator)]
#![warn(clippy::default_trait_access)]
#![warn(clippy::doc_comment_double_space_linebreaks)]
#![warn(clippy::doc_link_with_quotes)]
//FIXME: Enable #![warn(clippy::doc_markdown)]
#![warn(clippy::elidable_lifetime_names)]
#![warn(clippy::empty_enum)]
//FIXME: Enable #![warn(clippy::enum_glob_use)]
#![warn(clippy::expl_impl_clone_on_copy)]
#![warn(clippy::explicit_deref_methods)]
//FIXME: Enable #![warn(clippy::explicit_into_iter_loop)]
//FIXME: Enable #![warn(clippy::explicit_iter_loop)]
//FIXME: Enable #![warn(clippy::filter_map_next)]
#![warn(clippy::flat_map_option)]
//FIXME: Enable #![warn(clippy::float_cmp)]
#![warn(clippy::fn_params_excessive_bools)]
#![warn(clippy::format_collect)]
#![warn(clippy::format_push_string)]
#![warn(clippy::from_iter_instead_of_collect)]
//FIXME: Enable #![warn(clippy::if_not_else)]
#![warn(clippy::ignore_without_reason)]
//FIXME: Enable #![warn(clippy::ignored_unit_patterns)]
//FIXME: Enable #![warn(clippy::implicit_clone)]
#![warn(clippy::implicit_hasher)]
#![warn(clippy::inconsistent_struct_constructor)]
#![warn(clippy::index_refutable_slice)]
#![warn(clippy::inefficient_to_string)]
#![warn(clippy::inline_always)]
#![warn(clippy::into_iter_without_iter)]
#![warn(clippy::invalid_upcast_comparisons)]
#![warn(clippy::ip_constant)]
//FIXME: Enable #![warn(clippy::items_after_statements)]
#![warn(clippy::iter_filter_is_ok)]
#![warn(clippy::iter_filter_is_some)]
#![warn(clippy::iter_not_returning_iterator)]
#![warn(clippy::iter_without_into_iter)]
#![warn(clippy::large_digit_groups)]
#![warn(clippy::large_futures)]
#![warn(clippy::large_stack_arrays)]
#![warn(clippy::large_types_passed_by_value)]
#![warn(clippy::linkedlist)]
#![warn(clippy::macro_use_imports)]
#![warn(clippy::manual_assert)]
#![warn(clippy::manual_instant_elapsed)]
#![warn(clippy::manual_is_power_of_two)]
#![warn(clippy::manual_is_variant_and)]
//FIXME: Enable #![warn(clippy::manual_let_else)]
//FIXME: Enable #![warn(clippy::manual_midpoint)]
#![warn(clippy::manual_string_new)]
#![warn(clippy::many_single_char_names)]
#![warn(clippy::map_unwrap_or)]
//FIXME: Enable #![warn(clippy::match_bool)]
#![warn(clippy::match_same_arms)]
#![warn(clippy::match_wild_err_arm)]
//FIXME: Enable #![warn(clippy::match_wildcard_for_single_variants)]
#![warn(clippy::maybe_infinite_iter)]
#![warn(clippy::mismatching_type_param_order)]
//FIXME: Enable #![warn(clippy::missing_errors_doc)]
//FIXME: Enable #![warn(clippy::missing_fields_in_debug)]
//FIXME: Enable #![warn(clippy::missing_panics_doc)]
//FIXME: Enable #![warn(clippy::must_use_candidate)]
#![warn(clippy::mut_mut)]
#![warn(clippy::naive_bytecount)]
#![warn(clippy::needless_bitwise_bool)]
#![warn(clippy::needless_continue)]
#![warn(clippy::needless_for_each)]
//FIXME: Enable #![warn(clippy::needless_pass_by_value)]
#![warn(clippy::needless_raw_string_hashes)]
#![warn(clippy::no_effect_underscore_binding)]
#![warn(clippy::no_mangle_with_rust_abi)]
#![warn(clippy::non_std_lazy_statics)]
#![warn(clippy::option_as_ref_cloned)]
#![warn(clippy::option_option)]
#![warn(clippy::ptr_as_ptr)]
#![warn(clippy::ptr_cast_constness)]
#![warn(clippy::pub_underscore_fields)]
#![warn(clippy::range_minus_one)]
#![warn(clippy::range_plus_one)]
#![warn(clippy::redundant_closure_for_method_calls)]
//FIXME: Enable #![warn(clippy::redundant_else)]
#![warn(clippy::ref_as_ptr)]
#![warn(clippy::ref_binding_to_reference)]
#![warn(clippy::ref_option)]
#![warn(clippy::ref_option_ref)]
//FIXME: Enable #![warn(clippy::return_self_not_must_use)]
#![warn(clippy::same_functions_in_if_condition)]
#![warn(clippy::semicolon_if_nothing_returned)]
//FIXME: Enable #![warn(clippy::should_panic_without_expect)]
//FIXME: Enable #![warn(clippy::similar_names)]
#![warn(clippy::single_char_pattern)]
//FIXME: Enable #![warn(clippy::single_match_else)]
//FIXME: Enable #![warn(clippy::stable_sort_primitive)]
#![warn(clippy::str_split_at_newline)]
#![warn(clippy::string_add_assign)]
#![warn(clippy::struct_excessive_bools)]
//FIXME: Enable #![warn(clippy::struct_field_names)]
#![warn(clippy::too_many_lines)]
#![warn(clippy::transmute_ptr_to_ptr)]
//FIXME: Enable #![warn(clippy::trivially_copy_pass_by_ref)]
#![warn(clippy::unchecked_duration_subtraction)]
#![warn(clippy::unicode_not_nfc)]
#![warn(clippy::unnecessary_box_returns)]
#![warn(clippy::unnecessary_debug_formatting)]
#![warn(clippy::unnecessary_join)]
#![warn(clippy::unnecessary_literal_bound)]
#![warn(clippy::unnecessary_semicolon)]
//FIXME: Enable #![warn(clippy::unnecessary_wraps)]
#![warn(clippy::unnested_or_patterns)]
//FIXME: Enable #![warn(clippy::unreadable_literal)]
#![warn(clippy::unsafe_derive_deserialize)]
#![warn(clippy::unused_async)]
#![warn(clippy::unused_self)]
#![warn(clippy::used_underscore_binding)]
#![warn(clippy::used_underscore_items)]
#![warn(clippy::verbose_bit_mask)]
#![warn(clippy::wildcard_imports)]
#![warn(clippy::zero_sized_map_values)]
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
