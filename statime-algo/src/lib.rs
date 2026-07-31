//! General datastructures as defined by the ptp spec
#![no_std]
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

// FIXME: Make crate no-std capable.
//#[cfg(feature = "std")]
extern crate std;

/// Unique identifier for a clock
// FIXME: Move to statime-base once that exists
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct ClockId(usize);

impl ClockId {
    /// Get a new identifier for a clock.
    #[expect(
        clippy::new_without_default,
        reason = "The new operation is non-trivial and has non-constant output"
    )]
    pub fn new() -> ClockId {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        ClockId(COUNTER.fetch_add(1, core::sync::atomic::Ordering::Relaxed))
    }
}

/// Unique identifier for a clock
// FIXME: Move to statime-base once that exists
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct LinkId(usize);

impl LinkId {
    /// Get a new identifier for a clock.
    #[expect(
        clippy::new_without_default,
        reason = "The new operation is non-trivial and has non-constant output"
    )]
    pub fn new() -> LinkId {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        LinkId(COUNTER.fetch_add(1, core::sync::atomic::Ordering::Relaxed))
    }
}

#[cfg(test)]
macro_rules! assert_almost_eq {
    ($left:expr, $right:expr) => {
        match (&$left, &$right) {
            (left_val, right_val) => {
                assert!(
                    (*left_val - *right_val).abs() <= 1e-6 * right_val.abs(),
                    "Floating point values not almost equal.\nLeft={left_val}\nRight={right_val}"
                )
            }
        }
    };
}

mod estimator;
mod filter;
mod link_noise;
mod matrix;
mod ringbuffer;

use core::sync::atomic::AtomicUsize;

pub use estimator::{EstimatorError, EstimatorState};
pub use filter::{LinkFilter, LinkFilterError};
pub use link_noise::{LinkNoiseError, LinkNoiseEstimator};
use statime_base::{Clock, Duration, Timestamp};

use crate::estimator::UncertainValue;

/// An error that occured in the kalman controller.
#[derive(Debug, Clone)]
pub enum KalmanControllerError<E> {
    /// Clock was not known to the controller
    UnknownClock,
    /// Tried to remove the system clock.
    CannotRemoveSystemClock,
    /// An error occurred in the link filter.
    LinkFilterError(LinkFilterError),
    /// An error occured in one of the clocks.
    ClockError(E),
}

impl<E> From<LinkFilterError> for KalmanControllerError<E> {
    fn from(value: LinkFilterError) -> Self {
        Self::LinkFilterError(value)
    }
}

struct ClockInfo<C> {
    id: ClockId,
    clock: C,
}

/// The main controller struct.
pub struct KalmanController<C> {
    clocks: std::vec::Vec<ClockInfo<C>>,
    filter: LinkFilter,
}

impl<C: Clock> KalmanController<C> {
    /// Create a new clock controller
    ///
    /// # Errors
    /// Fails if the provided system clock is not readable.
    pub fn new(
        system_clock: C,
        initial_wander: f64,
    ) -> Result<(Self, ClockId), KalmanControllerError<C::Error>> {
        let start_time = system_clock
            .now()
            .map_err(KalmanControllerError::ClockError)?;
        let (filter, id) = LinkFilter::empty((start_time - Timestamp::UNIX_EPOCH).as_seconds())
            .add_clock(
                UncertainValue {
                    value: 0.0,
                    uncertainty: 1e18,
                },
                UncertainValue {
                    value: 0.0,
                    uncertainty: system_clock
                        .max_frequency()
                        .map_err(KalmanControllerError::ClockError)?,
                },
                initial_wander,
            )?;
        Ok((
            Self {
                clocks: std::vec![ClockInfo {
                    id,
                    clock: system_clock
                }],
                filter,
            },
            id,
        ))
    }

    /// Add an external clock to the controller.
    ///
    /// # Errors
    /// Returns an error if the clock is already known to the filter.
    pub fn add_external_clock(&mut self) -> Result<ClockId, KalmanControllerError<C::Error>> {
        let (filter, id) = self.filter.clone().add_external_clock()?;
        self.filter = filter;
        Ok(id)
    }

    /// Remove an external clock from the controller.
    ///
    /// # Errors
    /// Returns an error if the clock is unknown, or not an external clock.
    pub fn remove_external_clock(
        &mut self,
        id: ClockId,
    ) -> Result<(), KalmanControllerError<C::Error>> {
        self.filter = self.filter.clone().remove_external_clock(id)?;
        Ok(())
    }

    /// Add an internal clock to the controller.
    ///
    /// # Errors
    /// Fails if there is insufficient storage available for the new clock.
    pub fn add_clock(
        &mut self,
        clock: C,
        initial_wander: f64,
    ) -> Result<ClockId, KalmanControllerError<C::Error>> {
        let (filter, id) = self.filter.clone().add_clock(
            UncertainValue {
                value: 0.0,
                uncertainty: 1e18,
            },
            UncertainValue {
                value: 0.0,
                uncertainty: clock
                    .max_frequency()
                    .map_err(KalmanControllerError::ClockError)?,
            },
            initial_wander,
        )?;
        self.filter = filter;
        self.clocks.push(ClockInfo { id, clock });
        Ok(id)
    }

    /// Remove a clock from the controller
    ///
    /// # Errors
    /// Fails if the clock is not known to the controller.
    pub fn remove_clock(
        &mut self,
        clock_id: ClockId,
    ) -> Result<(), KalmanControllerError<C::Error>> {
        if self.clocks[0].id == clock_id {
            return Err(KalmanControllerError::CannotRemoveSystemClock);
        }

        let Some(index) = self.clocks.iter().position(|info| info.id == clock_id) else {
            return Err(KalmanControllerError::UnknownClock);
        };
        self.clocks.remove(index);

        Ok(())
    }

    #[expect(unused)]
    fn steer_clocks(&mut self) -> Result<(), KalmanControllerError<C::Error>> {
        let mut filter = self.filter.clone().progress_time(
            (self.clocks[0]
                .clock
                .now()
                .map_err(KalmanControllerError::ClockError)?
                - Timestamp::UNIX_EPOCH)
                .as_seconds(),
        )?;
        for clock_info in &mut self.clocks {
            // FIXME: Make constants configurable.

            let offset = self.filter.clock_offset(clock_info.id)?.value;

            if offset < 10.0 {
                let frequency = self.filter.clock_frequency(clock_info.id)?.value;

                let cur_frequency_steer = clock_info
                    .clock
                    .get_frequency()
                    .map_err(KalmanControllerError::ClockError)?;
                let max_frequency_steer = clock_info
                    .clock
                    .max_frequency()
                    .map_err(KalmanControllerError::ClockError)?;

                let wanted_frequency_steer = cur_frequency_steer - frequency - offset / 8.0;

                let actual_frequency_steer =
                    wanted_frequency_steer.clamp(-max_frequency_steer, max_frequency_steer);
                // FIXME: Warn here on repeated clamping.

                clock_info
                    .clock
                    .set_frequency(actual_frequency_steer)
                    .map_err(KalmanControllerError::ClockError)?;
                filter = filter.absorb_frequency_steer(
                    clock_info.id,
                    actual_frequency_steer - cur_frequency_steer,
                )?;
            } else {
                clock_info
                    .clock
                    .step_clock(Duration::from_f64_seconds(-offset))
                    .map_err(KalmanControllerError::ClockError)?;
                filter = filter.absorb_offset_change(clock_info.id, -offset)?;
            }
        }

        self.filter = filter;

        Ok(())
    }
}
