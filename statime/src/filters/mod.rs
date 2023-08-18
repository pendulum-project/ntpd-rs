//! Definitions and implementations for the abstracted measurement filters

pub mod basic;

use crate::{port::Measurement, Clock, Duration};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FilterUpdate {
    pub next_update: Option<core::time::Duration>,
}

/// A filter for post-processing time measurements.
///
/// Filters are responsible for dealing with the network noise, and should
/// average out the input a bit so minor network variations are not immediately
/// reflected in the synchronization of the clock.
///
/// This crate provides a simple [`BasicFilter`](basic::BasicFilter) which is
/// suitable for most needs, but users can implement their own if desired.
pub trait Filter {
    type Config: Clone;

    /// Create a new instance of the filter.
    fn new(config: Self::Config) -> Self;

    /// Put a new measurement in the filter.
    /// The filter can then use this to adjust the clock
    fn measurement<C: Clock>(&mut self, m: Measurement, clock: &mut C) -> FilterUpdate;

    /// Handle a new measurement of the delay to the master.
    fn delay(&mut self, delay: Duration);

    /// Update initiated through [FilterUpdate::next_update] timeout.
    fn update<C: Clock>(&mut self, clock: &mut C) -> FilterUpdate;

    /// Handle ending of time synchronization from the source
    /// associated with this filter.
    fn demobilize<C: Clock>(&mut self, clock: &mut C);
}
