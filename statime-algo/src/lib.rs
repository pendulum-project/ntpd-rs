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

pub use estimator::{EstimatorError, EstimatorState};
pub use filter::{LinkFilter, LinkFilterError};
pub use link_noise::{LinkNoiseError, LinkNoiseEstimator};
use statime_base::{Clock, ClockId, Duration};

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
        let (filter, id) = LinkFilter::empty(start_time).add_clock(
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
            self.clocks[0]
                .clock
                .now()
                .map_err(KalmanControllerError::ClockError)?,
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
