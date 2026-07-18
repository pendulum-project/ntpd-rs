use std::{boxed::Box, vec::Vec};

use crate::matrix::Matrix;

use super::{ClockId, LinkId};

//FIXME: Replace with proper Timestamp type
type Timestamp = f64;

//FIXME: Make more permanent error enum
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum EstimatorError {
    ClockNotFound,
    ClockAlreadyExists,
    LinkNotFound,
    LinkAlreadyExists,
}

#[derive(Debug, Clone, Copy)]
struct ClockInfo {
    id: ClockId,
    base_index: usize,
    wander: f64,
}

impl ClockInfo {
    fn offset_index(self) -> usize {
        self.base_index
    }

    fn frequency_index(self) -> usize {
        self.base_index + 1
    }
}

#[derive(Debug, Clone, Copy)]
struct LinkInfo {
    id: LinkId,
    index: usize,
}

#[derive(Debug, Clone)]
struct EstimatorState {
    time: Timestamp,
    state: Matrix<Box<[f64]>>,
    uncertainty: Matrix<Box<[f64]>>,
    clock_info: Vec<ClockInfo>,
    link_info: Vec<LinkInfo>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct UncertainValue {
    /// Best estimate of the value
    value: f64,
    /// Square root of the variance of the value. Corresponds
    /// to 1 standard deviation.
    uncertainty: f64,
}

impl From<(f64, f64)> for UncertainValue {
    fn from(value: (f64, f64)) -> Self {
        UncertainValue {
            value: value.0,
            uncertainty: value.1,
        }
    }
}

impl EstimatorState {
    pub fn empty(time: Timestamp) -> EstimatorState {
        EstimatorState {
            time,
            state: Matrix::zero(0, 1),
            uncertainty: Matrix::zero(0, 0),
            clock_info: Vec::new(),
            link_info: Vec::new(),
        }
    }

    pub fn progress_time(&self, new_time: Timestamp) -> EstimatorState {
        let delta_t = new_time - self.time;

        let mut update = Matrix::identity(self.state.rows());
        let mut noise = Matrix::zero(self.state.rows(), self.state.rows());

        for clock_info in &self.clock_info {
            update[(clock_info.offset_index(), clock_info.frequency_index())] = delta_t;
            // We need to square wander as we store it in units of ppm per second,
            // which is a standard deviation (effectively).
            // The powers of time that contribute to clock process noise can be
            // derived from imposing the random-walk requirement on the frequency,
            // which gives linear relationship for the frequency variance increase,
            // and then requiring that two updates for shorter intervals give the same
            // result as one update for the sum of those intervals.
            noise[(clock_info.offset_index(), clock_info.offset_index())] =
                delta_t.powi(3) * clock_info.wander.powi(2) / 3.;
            noise[(clock_info.offset_index(), clock_info.frequency_index())] =
                delta_t.powi(2) * clock_info.wander.powi(2) / 2.;
            noise[(clock_info.frequency_index(), clock_info.offset_index())] =
                delta_t.powi(2) * clock_info.wander.powi(2) / 2.;
            noise[(clock_info.frequency_index(), clock_info.frequency_index())] =
                delta_t * clock_info.wander.powi(2);
        }

        EstimatorState {
            time: new_time,
            state: update.clone() * self.state.clone(),
            uncertainty: update.clone() * self.uncertainty.clone() * update.transpose() + noise,
            clock_info: self.clock_info.clone(),
            link_info: self.link_info.clone(),
        }
    }

    // Assumes it is happening NOW with respect to the time of the previous estimate
    pub fn measurement(
        &self,
        from: ClockId,
        to: ClockId,
        offset: UncertainValue,
        link_delay: Option<LinkId>,
    ) -> Result<EstimatorState, EstimatorError> {
        todo!()
    }

    pub fn add_clock(
        &self,
        id: ClockId,
        initial_offset: UncertainValue,
        initial_frequency: UncertainValue,
        initial_wander: f64,
    ) -> Result<EstimatorState, EstimatorError> {
        if self.clock_info.iter().any(|info| info.id == id) {
            return Err(EstimatorError::ClockAlreadyExists);
        }

        let new_clock_info = ClockInfo {
            id,
            base_index: self.state.rows(),
            wander: initial_wander,
        };

        let mut clock_info = self.clock_info.clone();
        clock_info.push(new_clock_info);

        Ok(EstimatorState {
            time: self.time,
            state: Matrix::new(self.state.rows() + 2, 1, |row, _| {
                if row == new_clock_info.offset_index() {
                    initial_offset.value
                } else if row == new_clock_info.frequency_index() {
                    initial_frequency.value
                } else {
                    self.state[(row, 0)]
                }
            }),
            uncertainty: Matrix::new(
                self.state.rows() + 2,
                self.state.rows() + 2,
                |row, column| {
                    if row < self.uncertainty.rows() && column < self.uncertainty.cols() {
                        // Existing uncertainty
                        self.uncertainty[(row, column)]
                    } else if row == column && row == new_clock_info.offset_index() {
                        // New clock has only uncertainty on the diagonal, for offset
                        initial_offset.uncertainty.powi(2)
                    } else if row == column && row == new_clock_info.frequency_index() {
                        // and frequency. No correlations between those yet.
                        initial_frequency.uncertainty.powi(2)
                    } else {
                        // No correlations between uncertainty of new clock and old state yet.
                        0.0
                    }
                },
            ),
            clock_info,
            link_info: self.link_info.clone(),
        })
    }

    pub fn remove_clock(&self, id: ClockId) -> Result<EstimatorState, EstimatorError> {
        let clock_info = self.get_clock_info(id)?;

        Ok(EstimatorState {
            time: self.time,
            state: Matrix::new(self.state.rows() - 2, 1, |row, _| {
                if row < clock_info.base_index {
                    self.state[(row, 0)]
                } else {
                    self.state[(row + 2, 0)]
                }
            }),
            uncertainty: Matrix::new(
                self.uncertainty.rows() - 2,
                self.uncertainty.cols() - 2,
                |row, col| {
                    let row = if row < clock_info.base_index {
                        row
                    } else {
                        row + 2
                    };
                    let col = if col < clock_info.base_index {
                        col
                    } else {
                        col + 2
                    };
                    self.uncertainty[(row, col)]
                },
            ),
            clock_info: self
                .clock_info
                .iter()
                .filter_map(|info| {
                    if info.id == id {
                        None
                    } else {
                        Some(ClockInfo {
                            id: info.id,
                            base_index: if info.base_index < clock_info.base_index {
                                info.base_index
                            } else {
                                info.base_index - 2
                            },
                            wander: info.wander,
                        })
                    }
                })
                .collect(),
            link_info: self
                .link_info
                .iter()
                .map(|link_info| LinkInfo {
                    id: link_info.id,
                    index: if link_info.index < clock_info.base_index {
                        link_info.index
                    } else {
                        link_info.index - 2
                    },
                })
                .collect(),
        })
    }

    pub fn add_link(
        &self,
        id: LinkId,
        initial_delay: f64,
        initial_delay_uncertainty: f64,
    ) -> Result<EstimatorState, EstimatorError> {
        todo!()
    }

    pub fn remove_link(&self, id: LinkId) -> Result<EstimatorState, EstimatorError> {
        todo!()
    }

    pub fn clock_offset(&self, id: ClockId) -> Result<UncertainValue, EstimatorError> {
        let clock_info = self.get_clock_info(id)?;
        Ok(UncertainValue {
            value: self.state[(clock_info.offset_index(), 0)],
            uncertainty: self.uncertainty[(clock_info.offset_index(), clock_info.offset_index())]
                .sqrt(),
        })
    }

    pub fn clock_frequency(&self, id: ClockId) -> Result<UncertainValue, EstimatorError> {
        let clock_info = self.get_clock_info(id)?;
        Ok(UncertainValue {
            value: self.state[(clock_info.frequency_index(), 0)],
            uncertainty: self.uncertainty
                [(clock_info.frequency_index(), clock_info.frequency_index())]
                .sqrt(),
        })
    }
}

impl EstimatorState {
    fn get_clock_info(&self, id: ClockId) -> Result<&ClockInfo, EstimatorError> {
        self.clock_info
            .iter()
            .find(|info| info.id == id)
            .ok_or(EstimatorError::ClockNotFound)
    }

    fn get_link_info(&self, id: LinkId) -> Result<&LinkInfo, EstimatorError> {
        self.link_info
            .iter()
            .find(|info| info.id == id)
            .ok_or(EstimatorError::LinkNotFound)
    }
}

#[cfg(test)]
mod tests {
    use crate::{ClockId, estimator::EstimatorState};

    macro_rules! assert_almost_eq {
        ($left:expr, $right:expr) => {
            match (&$left, &$right) {
                (left_val, right_val) => {
                    assert!((*left_val - *right_val).abs() <= 1e-6*right_val.abs(),
                        "Floating point values not almost equal.\nLeft={left_val}\nRight={right_val}")
                }
            }
        };
    }

    macro_rules! assert_uv_almost_eq {
        ($left:expr, $right:expr) => {
            match (&$left, &$right) {
                (left_val, right_val) => {
                    assert!((left_val.value - right_val.value).abs() <= 1e-6*right_val.value.abs(),
                        "Floating point values not almost equal.\nLeft={left_val:?}\nRight={right_val:?}");
                    assert!((left_val.uncertainty - right_val.uncertainty).abs() <= 1e-6*right_val.uncertainty.abs(),
                        "Floating point uncertainty not almost equal.\nLeft={left_val:?}\nRight={right_val:?}");
                }
            }
        };
    }

    #[test]
    fn test_add_clock() {
        let state = EstimatorState::empty(0.0);
        let state = state
            .add_clock(ClockId(1), (0.0, 1.0).into(), (2.0, 3.0).into(), 1e-8)
            .unwrap();
        assert_eq!(state.clock_offset(ClockId(1)).unwrap().value, 0.0);
        assert_eq!(state.clock_offset(ClockId(1)).unwrap().uncertainty, 1.0);
        assert_eq!(state.clock_frequency(ClockId(1)).unwrap().value, 2.0);
        assert_eq!(state.clock_frequency(ClockId(1)).unwrap().uncertainty, 3.0);
    }

    #[test]
    fn test_time_evolve() {
        let state = EstimatorState::empty(0.0);
        let state = state
            .add_clock(ClockId(1), (0.0, 0.0).into(), (1e-6, 0.0).into(), 1e-8)
            .unwrap();
        let state = state
            .add_clock(ClockId(2), (0.0, 1e-5).into(), (-1e-6, 1e-7).into(), 0.0)
            .unwrap();
        let state = state.progress_time(100.0);
        assert_eq!(state.clock_frequency(ClockId(1)).unwrap().value, 1e-6);
        // Random walk noise, so frequency deviation is sqrt(time_interval)*wander.
        assert_almost_eq!(state.clock_frequency(ClockId(1)).unwrap().uncertainty, 1e-7);
        // Pre-existing frequency offset should cause phase offset.
        assert_almost_eq!(state.clock_offset(ClockId(1)).unwrap().value, 1e-4);
        // Random walk noise in the derivative, so the integral gives an
        // additional factor of time compared to the frequency deviation.
        // The factor sqrt(3) follows from the structure of how updates work.
        assert_almost_eq!(
            state.clock_offset(ClockId(1)).unwrap().uncertainty,
            1e-5 / (3.0f64.sqrt())
        );

        let state = state.remove_clock(ClockId(1)).unwrap();

        assert_eq!(state.clock_frequency(ClockId(2)).unwrap().value, -1e-6);
        assert_eq!(state.clock_frequency(ClockId(2)).unwrap().uncertainty, 1e-7);
        assert_almost_eq!(state.clock_offset(ClockId(2)).unwrap().value, -1e-4);
        assert_almost_eq!(
            state.clock_offset(ClockId(2)).unwrap().uncertainty,
            1e-5 * (2.0f64.sqrt())
        );
    }

    #[test]
    fn test_progress_time_composes_well() {
        let state = EstimatorState::empty(0.0);
        let state = state
            .add_clock(ClockId(1), (0.0, 0.0).into(), (1e-6, 0.0).into(), 1e-8)
            .unwrap();

        let state_at_once = state.progress_time(100.0);

        let state_intermediate = state.progress_time(75.0);
        let state_via_intermediate = state_intermediate.progress_time(100.0);

        assert_uv_almost_eq!(
            state_at_once.clock_offset(ClockId(1)).unwrap(),
            state_via_intermediate.clock_offset(ClockId(1)).unwrap()
        );
        assert_uv_almost_eq!(
            state_at_once.clock_frequency(ClockId(1)).unwrap(),
            state_via_intermediate.clock_frequency(ClockId(1)).unwrap()
        );
    }
}
