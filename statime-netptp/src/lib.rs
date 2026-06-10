//! Network handling for PTP/CSPTP in ntpd-rs/statime.
//!
//! This crate provides abstractions for dealing with the fact that both PTP
//! and CSPTP need sockets with local bindings on ports 319 and 320. The
//! operating system can only hand out 1 of those sockets per interface, plus a
//! fallback socket. This crate provides multiplexing for multiple uses of this
//! one socket, making implementing of simultaneous use of PTP and CSPTP, as
//! well as more than one CSPTP connection at the same time, easier.
//!
//! This is mostly intended as an internal crate for the ntpd-rs/statime
//! ecosystem, though we plan to keep the version numbering consistent with
//! semver. Be aware that we might be making breaking changes fairly often
//! though when using this crate, and that we might not be receptive to changes
//! making it work better for your particular use case if those changes have no
//! value for ntpd-rs/statime ecosystem.
#![cfg(target_os = "linux")]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![warn(rustdoc::unescaped_backticks)]
#![warn(clippy::assigning_clones)]
#![warn(clippy::bool_to_int_with_if)]
#![warn(clippy::borrow_as_ptr)]
#![warn(clippy::case_sensitive_file_extension_comparisons)]
#![warn(clippy::cast_lossless)]
#![warn(clippy::cast_possible_truncation)]
#![warn(clippy::cast_possible_wrap)]
#![warn(clippy::cast_precision_loss)]
#![warn(clippy::cast_ptr_alignment)]
#![warn(clippy::cast_sign_loss)]
#![warn(clippy::checked_conversions)]
#![warn(clippy::cloned_instead_of_copied)]
#![warn(clippy::comparison_chain)]
#![warn(clippy::copy_iterator)]
#![warn(clippy::default_trait_access)]
#![warn(clippy::doc_comment_double_space_linebreaks)]
#![warn(clippy::doc_link_with_quotes)]
#![warn(clippy::doc_markdown)]
#![warn(clippy::elidable_lifetime_names)]
#![warn(clippy::empty_enums)]
#![warn(clippy::enum_glob_use)]
#![warn(clippy::expl_impl_clone_on_copy)]
#![warn(clippy::explicit_deref_methods)]
#![warn(clippy::explicit_into_iter_loop)]
#![warn(clippy::explicit_iter_loop)]
#![warn(clippy::filter_map_next)]
#![warn(clippy::flat_map_option)]
#![warn(clippy::float_cmp)]
#![warn(clippy::fn_params_excessive_bools)]
#![warn(clippy::format_collect)]
#![warn(clippy::format_push_string)]
#![warn(clippy::from_iter_instead_of_collect)]
#![warn(clippy::if_not_else)]
#![warn(clippy::ignore_without_reason)]
#![warn(clippy::ignored_unit_patterns)]
#![warn(clippy::implicit_clone)]
#![warn(clippy::implicit_hasher)]
#![warn(clippy::inconsistent_struct_constructor)]
#![warn(clippy::index_refutable_slice)]
#![warn(clippy::inefficient_to_string)]
#![warn(clippy::inline_always)]
#![warn(clippy::into_iter_without_iter)]
#![warn(clippy::invalid_upcast_comparisons)]
#![warn(clippy::ip_constant)]
#![warn(clippy::items_after_statements)]
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
#![warn(clippy::manual_let_else)]
#![warn(clippy::manual_midpoint)]
#![warn(clippy::manual_string_new)]
#![warn(clippy::many_single_char_names)]
#![warn(clippy::map_unwrap_or)]
#![warn(clippy::match_bool)]
#![warn(clippy::match_same_arms)]
#![warn(clippy::match_wild_err_arm)]
#![warn(clippy::match_wildcard_for_single_variants)]
#![warn(clippy::maybe_infinite_iter)]
#![warn(clippy::mismatching_type_param_order)]
#![warn(clippy::missing_errors_doc)]
#![warn(clippy::missing_fields_in_debug)]
#![warn(clippy::missing_panics_doc)]
#![warn(clippy::must_use_candidate)]
#![warn(clippy::mut_mut)]
#![warn(clippy::naive_bytecount)]
#![warn(clippy::needless_bitwise_bool)]
#![warn(clippy::needless_continue)]
#![warn(clippy::needless_for_each)]
#![warn(clippy::needless_pass_by_value)]
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
#![warn(clippy::redundant_else)]
#![warn(clippy::ref_as_ptr)]
#![warn(clippy::ref_binding_to_reference)]
#![warn(clippy::ref_option)]
#![warn(clippy::ref_option_ref)]
#![warn(clippy::return_self_not_must_use)]
#![warn(clippy::same_functions_in_if_condition)]
#![warn(clippy::semicolon_if_nothing_returned)]
#![warn(clippy::should_panic_without_expect)]
#![warn(clippy::similar_names)]
#![warn(clippy::single_char_pattern)]
#![warn(clippy::single_match_else)]
#![warn(clippy::stable_sort_primitive)]
#![warn(clippy::str_split_at_newline)]
#![warn(clippy::string_add_assign)]
#![warn(clippy::struct_excessive_bools)]
#![warn(clippy::struct_field_names)]
#![warn(clippy::too_many_lines)]
#![warn(clippy::transmute_ptr_to_ptr)]
#![warn(clippy::trivially_copy_pass_by_ref)]
#![warn(clippy::unchecked_time_subtraction)]
#![warn(clippy::unicode_not_nfc)]
#![warn(clippy::unnecessary_box_returns)]
#![warn(clippy::unnecessary_debug_formatting)]
#![warn(clippy::unnecessary_join)]
#![warn(clippy::unnecessary_literal_bound)]
#![warn(clippy::unnecessary_semicolon)]
#![warn(clippy::unnecessary_wraps)]
#![warn(clippy::unnested_or_patterns)]
#![warn(clippy::unreadable_literal)]
#![warn(clippy::unsafe_derive_deserialize)]
#![warn(clippy::unused_async)]
#![warn(clippy::used_underscore_binding)]
#![warn(clippy::used_underscore_items)]
#![warn(clippy::verbose_bit_mask)]
#![warn(clippy::wildcard_imports)]
#![warn(clippy::zero_sized_map_values)]

use std::{
    collections::HashMap,
    sync::{Arc, RwLock, atomic::AtomicUsize},
    task::Wake,
    time::Duration,
};

use timestamped_socket::{
    interface::{InterfaceName, lookup_phc},
    socket::{SendTimestampToken, TimestampData},
};

use std::io::Result;

use crate::wake::ListWaker;

mod addresses;
mod interface;
mod socket;
mod wake;

use addresses::BoundInterface;
pub use addresses::PtpAddressFamily;
pub use interface::Interface;
pub use socket::{ConnectedSocket, OpenSocket, RecvResult};

/// The maximum size for incoming packets
pub const MAX_PACKET_SIZE: usize = 4096;
/// The number of incoming packets that are buffered for a socket.
pub const PACKET_BUFFER_SIZE: usize = 16;
/// The number of old send timestamps that are stored per interface.
pub const CACHED_TIMESTAMPS: usize = 32;
/// The amount of time we are willing to wait for a send timestamp.
pub const TIMESTAMP_FETCH_TIMEOUT: Duration = Duration::from_millis(1000);

/// Description of which clock to use for timestamping messages.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum TimestampingClock {
    /// Use the system clock.
    System,
    /// Use a hardware clock for the network card.
    Hardware {
        /// Which specific hardware clock to use.
        ///
        /// By default, we use the primary hardware clock associated with the
        /// interface. However, when using PTP virtual clocks in linux, this
        /// can be used to change the clock used to one of those.
        phc: Option<u32>,
    },
}

/// The primary management struct for the PTP/CSPTP network sockets.
///
/// Root of the hierarchy for opening sockets. Allows opening of specific
/// interfaces and configuring the clock sources used for those interface.
/// These interfaces can then be used to create sockets, which can be used
/// to handle the actual network traffic.
#[derive(Clone)]
pub struct NetworkManager<A: PtpAddressFamily>(Arc<NetworkManagerData<A>>);

struct InterfaceData<BoundInterface> {
    interface: BoundInterface,
    hardware_clock: Option<u32>,
    refcount: usize,
    send_wakers: Arc<ListWaker>,
    ts_wakers: Arc<ListWaker>,
    previous_timestamps: [RwLock<Option<(SendTimestampToken, TimestampData)>>; CACHED_TIMESTAMPS],
    timestamp_counter: RwLock<usize>,
}

struct SocketData<A: PtpAddressFamily> {
    remote_filter: Option<A>,
    local_filter: Option<A>,
    interface_filter: Option<InterfaceName>,
    timestamp_source: TimestampSource,
    message_channel: tokio::sync::mpsc::Sender<RecvResult<A>>,
}

struct NetworkManagerData<A: PtpAddressFamily> {
    interfaces: RwLock<HashMap<Option<InterfaceName>, InterfaceData<A::BoundInterface>>>,
    read_wakers: Arc<ListWaker>,
    sockets: RwLock<HashMap<usize, SocketData<A>>>,
    next_socket_id: AtomicUsize,
}

impl<A: PtpAddressFamily> NetworkManager<A> {
    /// Create a new network manager
    ///
    /// Immediately opens a general socket on port 319/320 not bound to a
    /// specific interface, as creating that socket later can be problematic.
    ///
    /// # Errors
    ///
    /// Returns any IO errors that occurred in setting up the general socket.
    pub fn new() -> Result<Self> {
        let mut interfaces = HashMap::new();

        interfaces.insert(
            None,
            InterfaceData {
                interface: A::BoundInterface::open(None, None)?,
                hardware_clock: None,
                // Ensure the general interface always stays open.
                refcount: 1,
                send_wakers: Arc::default(),
                ts_wakers: Arc::default(),
                previous_timestamps: Default::default(),
                timestamp_counter: RwLock::new(0),
            },
        );

        Ok(NetworkManager(Arc::new(NetworkManagerData {
            interfaces: RwLock::new(interfaces),
            read_wakers: Arc::default(),
            next_socket_id: AtomicUsize::new(0),
            sockets: RwLock::default(),
        })))
    }
}

impl<A: PtpAddressFamily> NetworkManager<A> {
    /// Get a reference to the general interface.
    ///
    /// This interface can be used to create sockets which don't care about
    /// which network interface their messages actually transit through.
    /// Timestamping of their messages will always be done with the system
    /// clock, as that is the only clock guaranteed to be available for
    /// timestamping on all network interfaces.
    #[must_use]
    #[expect(
        clippy::missing_panics_doc,
        reason = "Function will only panic if there is an implementation bug in this crate."
    )]
    pub fn open_general(&self) -> Interface<A> {
        // The mutex can only be poisoned from an earlier panic. It is ok for
        // us to propagate that to all the threads.
        let mut interfaces = self.0.interfaces.write().unwrap();
        // The general interface is always present. Should it somehow not be,
        // panic is the best solution.
        let entry = interfaces.get_mut(&None).unwrap();
        // An overflowing reference count is an error condition from which we
        // cannot reasonably recover. A panic here is the best solution.
        entry.refcount = entry.refcount.checked_add(1).unwrap();
        Interface {
            state: self.0.clone(),
            name: None,
            timestamp_source: TimestampSource::System,
        }
    }

    /// Open a specific network interface.
    ///
    /// This opens the specified network interface, configuring it such that
    /// the requested clock can be used for timestamping. If the interface was
    /// already previously opened, it will return a reference to it.
    ///
    /// # Errors
    ///
    /// Returns any IO errors that occured when trying to create a socket for
    /// the specified interface.
    ///
    /// Will also error when the interface is already open, but was created
    /// with a different clock for timestamping than currently requested,
    /// unless the currently requested clock is the system clock.
    #[expect(
        clippy::missing_panics_doc,
        reason = "Function will only panic if there is an implementation bug in this crate."
    )]
    pub fn open_interface(
        &self,
        interface: InterfaceName,
        clock: TimestampingClock,
    ) -> Result<Interface<A>> {
        let clock_idx = match clock {
            TimestampingClock::System => None,
            TimestampingClock::Hardware { phc: None } => {
                Some(lookup_phc(interface).ok_or(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "Hardware timestamping requested, but not available on interface.",
                ))?)
            }
            TimestampingClock::Hardware { phc: Some(phc) } => Some(phc),
        };

        // The mutex can only be poisoned from an earlier panic. It is ok for
        // us to propagate that to all the threads.
        let mut interfaces = self.0.interfaces.write().unwrap();
        // Ensure the interface exists and has its refcount increased for the new interface
        if let Some(entry) = interfaces.get_mut(&Some(interface)) {
            // Check the hardware clock matches expectations.
            // FIXME: Implement reopening of the interface when it doesn't yet have a hardware clock associated with it.
            if clock_idx.is_some() && entry.hardware_clock != clock_idx {
                return Err(std::io::Error::other(
                    "Interface already in use with different hardware clock.",
                ));
            }
            // An overflowing reference count is an error condition from which we
            // cannot reasonably recover. A panic here is the best solution.
            entry.refcount = entry.refcount.checked_add(1).unwrap();
        } else {
            interfaces.insert(
                Some(interface),
                InterfaceData {
                    interface: A::BoundInterface::open(Some(interface), clock_idx)?,
                    hardware_clock: clock_idx,
                    refcount: 1,
                    send_wakers: Arc::default(),
                    ts_wakers: Arc::default(),
                    previous_timestamps: Default::default(),
                    timestamp_counter: RwLock::new(0),
                },
            );
            // Packets may now arrive on the new interface, so everyone
            // should start listening there.
            self.0.read_wakers.wake_by_ref();
        }
        Ok(Interface {
            state: self.0.clone(),
            name: Some(interface),
            timestamp_source: match clock {
                TimestampingClock::System => TimestampSource::System,
                TimestampingClock::Hardware { .. } => TimestampSource::Hardware,
            },
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TimestampSource {
    System,
    Hardware,
}
