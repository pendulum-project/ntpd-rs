//! General datastructures as defined by the ptp spec
#![no_std]

// FIXME: Make crate no-std capable.
//#[cfg(feature = "std")]
extern crate std;

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

use core::marker::PhantomData;
use statime_base::{Clock, ClockError, ClockId, Duration, LinkId, TAI, Timestamp};

use crate::{
    estimator::UncertainValue,
    filter::{LinkFilter, LinkFilterConfig},
    matrix::MatrixError,
};

/// An error that occured in the kalman controller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AlgoError {
    /// Clock was not known to the controller
    UnknownClock(ClockId),
    /// Clock already exists in the estimator or filter state
    ClockAlreadyExists(ClockId),
    /// Link not found in the estimator or filter state
    UnknownLink(LinkId),
    /// Link already exists in the estimator or filter state
    LinkAlreadyExists(LinkId),
    /// Measurements or links cannot be between two external clocks
    BothClocksExternal(ClockId, ClockId),
    /// Measurements or links between a clock and itself are not allowed
    ClocksEqual(ClockId),
    /// Time moved backwards, which is not allowed
    NonMonotonicTimeProgression {
        /// The time as was currently known to the algorithm
        from: Timestamp<TAI>,
        /// The new time the algorithm was supposed to progress to
        to: Timestamp<TAI>,
    },
    /// Tried to remove the system clock.
    CannotRemoveSystemClock(ClockId),
    /// Error from the underlying matrix library
    MatrixError(MatrixError),
    /// Error from the underlying clock
    ClockError(ClockError),
    /// The provided clock is not known to this link.
    UnknownClockForLink(LinkId, ClockId),
    /// There are insufficient measurements to provide estimates.
    NotEnoughMeasurements(LinkId),
}

impl From<MatrixError> for AlgoError {
    fn from(err: MatrixError) -> Self {
        AlgoError::MatrixError(err)
    }
}

impl From<ClockError> for AlgoError {
    fn from(err: ClockError) -> Self {
        AlgoError::ClockError(err)
    }
}

struct ClockInfo<C> {
    id: ClockId,
    clock: C,
}

/// FIXME: Make this internal and part of the storage trait system.
/// Trait for state management
pub trait StateMutex {
    /// Type of clock for the storage.
    type Clock: Clock;

    /// Creates a new instance of the mutex
    fn new(state: KalmanControllerState<Self::Clock>) -> Self;

    /// Takes a shared reference to the contained state and calls `f` with it
    fn with_ref<R, F: FnOnce(&KalmanControllerState<Self::Clock>) -> R>(&self, f: F) -> R;

    /// Takes a mutable reference to the contained state and calls `f` with it
    fn with_mut<R, F: FnOnce(&mut KalmanControllerState<Self::Clock>) -> R>(&self, f: F) -> R;
}

impl<C: Clock> StateMutex for std::sync::RwLock<KalmanControllerState<C>> {
    type Clock = C;

    fn new(state: KalmanControllerState<Self::Clock>) -> Self {
        std::sync::RwLock::new(state)
    }

    fn with_ref<R, F: FnOnce(&KalmanControllerState<Self::Clock>) -> R>(&self, f: F) -> R {
        f(&self.read().unwrap())
    }

    fn with_mut<R, F: FnOnce(&mut KalmanControllerState<Self::Clock>) -> R>(&self, f: F) -> R {
        f(&mut self.write().unwrap())
    }
}

/// The main controller struct.
pub struct KalmanControllerState<C> {
    clocks: std::vec::Vec<ClockInfo<C>>,
    filter: LinkFilter,
    filter_config: LinkFilterConfig,
}

/// Controller for clocks using a kalman filter as its state estimation mechanism.
pub struct KalmanController<Mutex> {
    state: Mutex,
}

impl<Mutex: StateMutex> KalmanController<Mutex> {
    /// Create a new clock controller
    ///
    /// # Errors
    /// Fails if the provided system clock is not readable.
    pub fn new(
        system_clock: Mutex::Clock,
        initial_wander: f64,
        filter_config: LinkFilterConfig,
    ) -> Result<(Self, ClockId), AlgoError> {
        let start_time = system_clock.now()?;
        let (filter, id) = LinkFilter::empty(start_time).add_clock(
            UncertainValue {
                value: 0.0,
                uncertainty: 1e18,
            },
            UncertainValue {
                value: 0.0,
                uncertainty: system_clock.max_frequency()?,
            },
            initial_wander,
        )?;
        Ok((
            Self {
                state: Mutex::new(KalmanControllerState {
                    clocks: std::vec![ClockInfo {
                        id,
                        clock: system_clock
                    }],
                    filter,
                    filter_config,
                }),
            },
            id,
        ))
    }

    /// Add an external clock to the controller.
    ///
    /// # Errors
    /// Returns an error if the clock is already known to the filter.
    pub fn add_external_clock(&self) -> Result<ClockId, AlgoError> {
        self.state.with_mut(|state| {
            let (filter, id) = state.filter.clone().add_external_clock()?;
            state.filter = filter;
            Ok(id)
        })
    }

    /// Remove an external clock from the controller.
    ///
    /// # Errors
    /// Returns an error if the clock is unknown, or not an external clock.
    pub fn remove_external_clock(&self, id: ClockId) -> Result<(), AlgoError> {
        self.state.with_mut(|state| {
            state.filter = state.filter.clone().remove_external_clock(id)?;
            Ok(())
        })
    }

    /// Add an internal clock to the controller.
    ///
    /// # Errors
    /// Fails if there is insufficient storage available for the new clock.
    pub fn add_clock(
        &self,
        clock: Mutex::Clock,
        initial_wander: f64,
    ) -> Result<ClockId, AlgoError> {
        self.state.with_mut(|state| {
            let (filter, id) = state.filter.clone().add_clock(
                UncertainValue {
                    value: 0.0,
                    uncertainty: 1e18,
                },
                UncertainValue {
                    value: 0.0,
                    uncertainty: clock.max_frequency()?,
                },
                initial_wander,
            )?;
            state.filter = filter;
            state.clocks.push(ClockInfo { id, clock });
            Ok(id)
        })
    }

    /// Remove a clock from the controller
    ///
    /// # Errors
    /// Fails if the clock is not known to the controller.
    pub fn remove_clock(&self, clock_id: ClockId) -> Result<(), AlgoError> {
        self.state.with_mut(|state| {
            if state.clocks[0].id == clock_id {
                return Err(AlgoError::CannotRemoveSystemClock(clock_id));
            }

            let Some(index) = state.clocks.iter().position(|info| info.id == clock_id) else {
                return Err(AlgoError::UnknownClock(clock_id));
            };
            state.clocks.remove(index);

            state.filter = state.filter.clone().remove_clock(clock_id)?;

            Ok(())
        })
    }

    /// Create a measurement link between clocks where the delay and noise from
    /// the link itself are automatically determined.
    ///
    /// The resulting link will need measurements in both directions to succesfully
    /// work.
    ///
    /// This is an associated function instead of a method to allow links to store
    /// references to the controller in a manner most convenient for the user.
    ///
    /// # Errors
    /// Fails if the clocks are not known to the controller, both external, or
    /// when they are the same.
    pub fn create_tracked_link<ControllerRef: AsRef<KalmanController<Mutex>>>(
        // We can't have a normal self parameter here as we want a generic
        // reference-like thing for the link to store, and we can't use other
        // types as self. See the comments on KalmanLink for the motivation for
        // generic reference-like things.
        this: ControllerRef,
        clock_a: ClockId,
        clock_b: ClockId,
        decay_rate: f64,
    ) -> Result<KalmanLink<ControllerRef, Mutex>, AlgoError> {
        let link_id = this.as_ref().state.with_mut(|state| {
            let (filter, id) = state
                .filter
                .clone()
                .add_tracked_link(clock_a, clock_b, decay_rate)?;
            state.filter = filter;

            Ok::<_, AlgoError>(id)
        })?;

        Ok(KalmanLink {
            clock_a,
            clock_b,
            link_id,
            controller: this,
            phantomdata: PhantomData,
        })
    }

    /// Create a measurement link between clocks without delay estimation.
    ///
    /// This is an associated function instead of a method to allow links to store
    /// references to the controller in a manner most convenient for the user.
    ///
    /// # Errors
    /// Fails if the clocks are not known to the controller, both external, or
    /// when they are the same.
    pub fn create_untracked_link<ControllerRef: AsRef<KalmanController<Mutex>>>(
        // We can't have a normal self parameter here as we want a generic
        // reference-like thing for the link to store, and we can't use other
        // types as self. See the comments on KalmanLink for the motivation for
        // generic reference-like things.
        this: ControllerRef,
        clock_a: ClockId,
        clock_b: ClockId,
    ) -> Result<KalmanLink<ControllerRef, Mutex>, AlgoError> {
        let link_id = this.as_ref().state.with_mut(|state| {
            let (filter, id) = state.filter.clone().add_untracked_link(clock_a, clock_b)?;
            state.filter = filter;

            Ok::<_, AlgoError>(id)
        })?;

        Ok(KalmanLink {
            clock_a,
            clock_b,
            link_id,
            controller: this,
            phantomdata: PhantomData,
        })
    }

    /// Get the current offset of a clock.
    ///
    /// # Errors
    /// Fails when the clock is not known to the filter.
    pub fn clock_offset(&self, clock_id: ClockId) -> Result<UncertainValue, AlgoError> {
        self.state
            .with_ref(|state| state.filter.clock_offset(clock_id))
    }

    /// Get the current frequency offset of a clock.
    ///
    /// # Errors
    /// Fails when the clock is not known to the filter.
    pub fn clock_frequency(&self, clock_id: ClockId) -> Result<UncertainValue, AlgoError> {
        self.state
            .with_ref(|state| state.filter.clock_offset(clock_id))
    }
}

impl<C: Clock> KalmanControllerState<C> {
    fn steer_clocks(&mut self) -> Result<(), AlgoError> {
        let mut filter = self
            .filter
            .clone()
            .progress_time(self.clocks[0].clock.now()?)?;
        for (index, clock_info) in self.clocks.iter_mut().enumerate() {
            // FIXME: Make constants configurable.

            let offset = self.filter.clock_offset(clock_info.id)?.value;

            if offset < 10.0 {
                let frequency = self.filter.clock_frequency(clock_info.id)?.value;

                let cur_frequency_steer = clock_info.clock.get_frequency()?;
                let max_frequency_steer = clock_info.clock.max_frequency()?;

                let wanted_frequency_steer = cur_frequency_steer - frequency - offset / 8.0;

                let actual_frequency_steer =
                    wanted_frequency_steer.clamp(-max_frequency_steer, max_frequency_steer);
                // FIXME: Warn here on repeated clamping.

                clock_info.clock.set_frequency(actual_frequency_steer)?;
                filter = filter.absorb_frequency_steer(
                    clock_info.id,
                    actual_frequency_steer - cur_frequency_steer,
                )?;
            } else {
                clock_info
                    .clock
                    .step_clock(Duration::from_f64_seconds(-offset))?;
                if index == 0 {
                    filter = filter.absorb_system_clock_offset_change(
                        clock_info.id,
                        Duration::from_f64_seconds(-offset),
                    )?;
                } else {
                    filter = filter.absorb_offset_change(clock_info.id, -offset)?;
                }
            }
        }

        self.filter = filter;

        Ok(())
    }
}

/// A measurement link between two clocks, managed by a `KalmanController`.
pub struct KalmanLink<ControllerRef: AsRef<KalmanController<M>>, M: StateMutex> {
    clock_a: ClockId,
    clock_b: ClockId,
    link_id: LinkId,
    // We use a generic reference to the kalman controller here to avoid
    // forced inclusions of lifetimes in this type. This allows a link to
    // be based on for example an Arc<KalmanController<M>> when std is
    // available, whilst keeping &KalmanController<M> available as option
    // for embedded platforms where things like arc don't exist.
    controller: ControllerRef,
    phantomdata: PhantomData<KalmanController<M>>,
}

impl<ControllerRef: AsRef<KalmanController<M>>, M: StateMutex> Drop
    for KalmanLink<ControllerRef, M>
{
    fn drop(&mut self) {
        self.controller.as_ref().state.with_mut(|state| {
            match state.filter.clone().remove_link(self.link_id) {
                Ok(filter) => state.filter = filter,
                Err(_err) => {
                    // FIXME: log this here, as there is no other way to handle this.
                }
            }
        });
    }
}

impl<ControllerRef: AsRef<KalmanController<M>>, M: StateMutex> KalmanLink<ControllerRef, M> {
    /// Process a measurement on a connection.
    ///
    /// # Errors
    /// Fails if the provided measurement is not for the link.
    pub fn measurement(&self, measurement: Measurement) -> Result<(), AlgoError> {
        if measurement.send_clock != self.clock_a && measurement.send_clock != self.clock_b {
            return Err(AlgoError::UnknownClockForLink(
                self.link_id,
                measurement.send_clock,
            ));
        }

        if measurement.recv_clock != self.clock_a && measurement.recv_clock != self.clock_b {
            return Err(AlgoError::UnknownClockForLink(
                self.link_id,
                measurement.recv_clock,
            ));
        }

        self.controller.as_ref().state.with_mut(|state| {
            state.filter = state
                .filter
                .clone()
                .progress_time(state.clocks[0].clock.now()?)?;

            state.filter = state.filter.clone().measurement(
                &state.filter_config,
                measurement.send_clock,
                measurement.recv_clock,
                UncertainValue {
                    value: (measurement.recv_timestamp - measurement.send_timestamp).as_seconds(),
                    uncertainty: measurement.uncertainty.as_seconds(),
                },
                self.link_id,
            )?;
            state.steer_clocks()?;
            Ok(())
        })
    }
}

/// A measurement done on a link.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Measurement {
    /// The clock timestamping the initiation of the time measurement signal.
    pub send_clock: ClockId,
    /// The clock timestamping the reception of the time measurement signal.
    pub recv_clock: ClockId,
    /// The timestamp at which the synchronization signal was sent.
    pub send_timestamp: Timestamp<TAI>,
    /// The timestamp at which the synchronization signal was received.
    pub recv_timestamp: Timestamp<TAI>,
    /// The uncertainty of the timestamps.
    pub uncertainty: Duration,
    /// The delay to UTC of the external clock, if any. Use zero on internal measurements.
    pub root_delay: Duration,
}
