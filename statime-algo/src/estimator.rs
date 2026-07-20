use std::{boxed::Box, vec::Vec};

use crate::matrix::{Matrix, MatrixError};

use super::{ClockId, LinkId};

//FIXME: Replace with proper Timestamp type
type Timestamp = f64;

//FIXME: Make more permanent error enum
/// Errors that can occur when using the estimator.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum EstimatorError {
    /// Clock was not found in the state
    ClockNotFound,
    /// Clock already exists in the state
    ClockAlreadyExists,
    /// Link not found in the state
    LinkNotFound,
    /// Link already exists in the state
    LinkAlreadyExists,
    /// Measurement between two external clocks is not allowed
    MeasurementBetweenExternalClocks,
    /// Error from the underlying matrix library
    MatrixError(MatrixError),
}

impl From<MatrixError> for EstimatorError {
    fn from(err: MatrixError) -> Self {
        EstimatorError::MatrixError(err)
    }
}

#[derive(Debug, Clone)]
struct ExternalClockList(Vec<ClockId>);

impl ExternalClockList {
    fn new() -> ExternalClockList {
        ExternalClockList(Vec::new())
    }

    /// Returns true if the given clock is is known as an external clock.
    fn contains(&self, id: ClockId) -> bool {
        self.0.contains(&id)
    }

    /// Add a new external clock to the list.
    fn add(&mut self, id: ClockId) -> Result<(), EstimatorError> {
        if self.contains(id) {
            Err(EstimatorError::ClockAlreadyExists)
        } else {
            self.0.push(id);
            Ok(())
        }
    }

    /// Remove an existing external clock from the list.
    fn remove(&mut self, id: ClockId) -> Result<(), EstimatorError> {
        if let Some(pos) = self.0.iter().position(|&x| x == id) {
            self.0.remove(pos);
            Ok(())
        } else {
            Err(EstimatorError::ClockNotFound)
        }
    }
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

#[derive(Debug, Clone)]
struct ClockInfoList(Vec<ClockInfo>);

impl ClockInfoList {
    fn new() -> ClockInfoList {
        ClockInfoList(Vec::new())
    }

    /// Checks if the given clock id exists in the current list.
    fn contains(&self, id: ClockId) -> bool {
        self.0.iter().any(|info| info.id == id)
    }

    /// Update the base indices of all clocks that have a base index greater
    /// than `from`, by subtracting `delta` from them.
    fn update_indices(&mut self, from: usize, delta: usize) {
        for info in self.0.iter_mut() {
            if info.base_index > from {
                info.base_index -= delta;
            }
        }
    }

    /// Remove the clock info for a given id, if it exists.
    /// This updates the base indices of clocks where needed.
    ///
    /// Returns the removed clock info.
    fn remove(&mut self, id: ClockId) -> Result<ClockInfo, EstimatorError> {
        let removed = if let Some(pos) = self.0.iter().position(|info| info.id == id) {
            Ok(self.0.remove(pos))
        } else {
            Err(EstimatorError::ClockNotFound)
        }?;

        self.update_indices(removed.base_index, 2);

        Ok(removed)
    }

    /// Add a new clock info to the list, if it doesn't already exist.
    fn add(&mut self, info: ClockInfo) -> Result<(), EstimatorError> {
        if self.0.iter().any(|existing| existing.id == info.id) {
            Err(EstimatorError::ClockAlreadyExists)
        } else {
            self.0.push(info);
            Ok(())
        }
    }

    /// Iterate over all clocks in the list.
    fn iter(&self) -> impl Iterator<Item = &ClockInfo> {
        self.0.iter()
    }
}

#[derive(Debug, Clone, Copy)]
struct LinkInfo {
    id: LinkId,
    index: usize,
    // Fraction of the link delay that we assume the error increases by every measurement
    decay_rate: f64,
}

#[derive(Debug, Clone)]
struct LinkInfoList(Vec<LinkInfo>);

impl LinkInfoList {
    fn new() -> LinkInfoList {
        LinkInfoList(Vec::new())
    }

    /// Update the indices of all links that have an index greater than `from`, by subtracting `delta` from them.
    fn update_indices(&mut self, from: usize, delta: usize) {
        for info in self.0.iter_mut() {
            if info.index > from {
                info.index -= delta;
            }
        }
    }

    /// Remove the link info for a given id, if it exists.
    /// This updates the indices for links where needed.
    ///
    /// Returns the removed clock info.
    fn remove(&mut self, id: LinkId) -> Result<LinkInfo, EstimatorError> {
        let removed = if let Some(pos) = self.0.iter().position(|info| info.id == id) {
            Ok(self.0.remove(pos))
        } else {
            Err(EstimatorError::LinkNotFound)
        }?;

        self.update_indices(removed.index, 1);

        Ok(removed)
    }

    /// Add a new link info to the list, if it doesn't already exist.
    fn add(&mut self, info: LinkInfo) -> Result<(), EstimatorError> {
        if self.0.iter().any(|existing| existing.id == info.id) {
            Err(EstimatorError::LinkAlreadyExists)
        } else {
            self.0.push(info);
            Ok(())
        }
    }

    /// Iterate over all links in the list.
    fn iter(&self) -> impl Iterator<Item = &LinkInfo> {
        self.0.iter()
    }
}

/// Represents the state of the estimator at a given point in time.
#[derive(Debug, Clone)]
pub struct EstimatorState {
    time: Timestamp,
    state: Matrix<Box<[f64]>>,
    uncertainty: Matrix<Box<[f64]>>,
    clock_info: ClockInfoList,
    external_clocks: ExternalClockList,
    link_info: LinkInfoList,
}

/// Represents an uncertain value, with a best estimate and an uncertainty (standard deviation).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct UncertainValue {
    /// Best estimate of the value
    value: f64,
    /// Square root of the variance of the value. Corresponds
    /// to 1 standard deviation.
    uncertainty: f64,
}

/// Convert from a tuple of (value, uncertainty) to an `UncertainValue`.
impl From<(f64, f64)> for UncertainValue {
    fn from(value: (f64, f64)) -> Self {
        UncertainValue {
            value: value.0,
            uncertainty: value.1,
        }
    }
}

impl EstimatorState {
    /// Create a new empty estimator state at the given timestamp.
    ///
    /// This state has no clocks or links contained in it.
    pub fn empty(time: Timestamp) -> EstimatorState {
        EstimatorState {
            time,
            state: Matrix::zero(0, 1),
            uncertainty: Matrix::zero(0, 0),
            clock_info: ClockInfoList::new(),
            external_clocks: ExternalClockList::new(),
            link_info: LinkInfoList::new(),
        }
    }

    /// Progress the estimator state to the new timestamp.
    pub fn progress_time(mut self, new_time: Timestamp) -> EstimatorState {
        let delta_t = new_time - self.time;

        let mut update = Matrix::identity(self.state.rows());
        let mut noise = Matrix::zero(self.state.rows(), self.state.rows());

        // For each clock, we need to determine a value for the update and noise matrices.
        for clock_info in self.clock_info.iter() {
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

        for link_info in self.link_info.iter() {
            noise[(link_info.index, link_info.index)] =
                delta_t * ((link_info.decay_rate * self.state[(link_info.index, 0)]).powi(2));
        }

        self.time = new_time;
        self.state = &update * &self.state;
        self.uncertainty = &update * &self.uncertainty * update.transpose() + noise;

        self
    }

    /// Add a new measurement to the estimator state.
    ///
    /// Assumes the measurements happens at the time the estimator state is
    /// currently set to.
    pub fn measurement(
        mut self,
        from: ClockId,
        to: ClockId,
        offset: UncertainValue,
        link_delay: Option<LinkId>,
    ) -> Result<EstimatorState, EstimatorError> {
        let mut measurement_projection = Matrix::zero(1, self.state.rows());

        let from_external = self.external_clocks.contains(from);
        let to_external = self.external_clocks.contains(to);

        if from_external && to_external {
            return Err(EstimatorError::MeasurementBetweenExternalClocks);
        }

        if !from_external {
            let from_clock_info = self.get_clock_info(from)?;
            measurement_projection[(0, from_clock_info.offset_index())] = -1.0;
        }

        if !to_external {
            let to_clock_info = self.get_clock_info(to)?;
            measurement_projection[(0, to_clock_info.offset_index())] = 1.0;
        }

        if let Some(link_delay) = link_delay {
            let link_delay_info = self.get_link_info(link_delay)?;
            measurement_projection[(0, link_delay_info.index)] = 1.0;
        }

        let expected = &measurement_projection * &self.state;
        let difference = Matrix::<Box<[f64]>>::from(offset.value) - expected;
        // The uncertainty of the difference between measurement and prediction is the sum of
        // the uncertainty of the measurement, and the uncertainty on the prediction. The
        // prediction uncertainty can be shown to follow from multiplying the state uncertainty
        // from both sides by the measurement projection. Intuitively this is because the
        // uncertainty is sort of a square of the state.
        let difference_covariance =
            &measurement_projection * &self.uncertainty * measurement_projection.transpose()
                + Matrix::from(offset.uncertainty.powi(2));

        // Intuitively, the multiplication with the measurement gives the contribution
        // for each part of the state to the uncertainty of the measurement prediction.
        // The division then normalizes that to weights on how large the change to each
        // part of the state needs to be. This makes sense because where our prediction
        // has more uncertainty from, the measurement should weigh more.
        let update_strength =
            &self.uncertainty * measurement_projection.transpose() / difference_covariance[(0, 0)];

        // This is simply using the strenght we calculated before to update the state
        self.state = &self.state + &update_strength * difference;

        // However I don't have a good intuition why this would be its uncertainty. It
        // is derived well on wikipedia, and when having questions I would suggest looking
        // at its page on kalman filters.
        let prev_step_proporitionality =
            Matrix::identity(self.state.rows()) - &update_strength * measurement_projection;
        self.uncertainty = (&prev_step_proporitionality
            * &self.uncertainty
            * prev_step_proporitionality.transpose()
            + &update_strength * offset.uncertainty.powi(2) * update_strength.transpose())
        .symmetrize();

        Ok(self)
    }

    /// Add an external clock to the estimator state.
    pub fn add_external_clock(mut self, id: ClockId) -> Result<EstimatorState, EstimatorError> {
        // check in clock info as well
        if self.clock_info.contains(id) {
            return Err(EstimatorError::ClockAlreadyExists);
        }

        self.external_clocks.add(id)?;

        Ok(self)
    }

    /// Remove an external clock from the estimator state.
    pub fn remove_external_clock(mut self, id: ClockId) -> Result<EstimatorState, EstimatorError> {
        self.external_clocks.remove(id)?;

        Ok(self)
    }

    /// Add a new clock to the estimator state.'
    ///
    /// To add a new clock you must provide the initial values for the offset,
    /// frequency and wander of the clock.
    pub fn add_clock(
        mut self,
        id: ClockId,
        initial_offset: UncertainValue,
        initial_frequency: UncertainValue,
        initial_wander: f64,
    ) -> Result<EstimatorState, EstimatorError> {
        // check in external clocks as well
        if self.external_clocks.contains(id) {
            return Err(EstimatorError::ClockAlreadyExists);
        }

        let new_clock_info = ClockInfo {
            id,
            base_index: self.state.rows(),
            wander: initial_wander,
        };

        self.clock_info.add(new_clock_info)?;
        self.state = self
            .state
            .extend_vec([initial_offset.value, initial_frequency.value])?;
        self.uncertainty = self.uncertainty.extend([
            [initial_offset.uncertainty.powi(2), 0.0],
            [0.0, initial_frequency.uncertainty.powi(2)],
        ]);

        Ok(self)
    }

    /// Remove a clock from the estimator state.
    pub fn remove_clock(mut self, id: ClockId) -> Result<EstimatorState, EstimatorError> {
        let clock_info = self.clock_info.remove(id)?;

        self.state = self.state.splice_vec(clock_info.base_index, 2)?;
        self.uncertainty = self.uncertainty.splice_square(clock_info.base_index, 2)?;
        self.link_info.update_indices(clock_info.base_index, 2);

        Ok(self)
    }

    /// Add a new link to the estimator state.
    ///
    /// The decay rate is the amount the uncertainty on the link delay increases every measurement on this link.
    pub fn add_link(
        mut self,
        id: LinkId,
        initial_delay: UncertainValue,
        decay_rate: f64,
    ) -> Result<EstimatorState, EstimatorError> {
        let new_link_info = LinkInfo {
            id,
            index: self.state.rows(),
            decay_rate,
        };

        self.link_info.add(new_link_info)?;
        self.state = self.state.extend_vec([initial_delay.value])?;
        self.uncertainty = self
            .uncertainty
            .extend([[initial_delay.uncertainty.powi(2)]]);

        Ok(self)
    }

    /// Remove a link from the estimator state.
    pub fn remove_link(mut self, id: LinkId) -> Result<EstimatorState, EstimatorError> {
        let removed_info = self.link_info.remove(id)?;
        self.state = self.state.splice_vec(removed_info.index, 1)?;
        self.uncertainty = self.uncertainty.splice_square(removed_info.index, 1)?;
        self.clock_info.update_indices(removed_info.index, 1);

        Ok(self)
    }

    /// Get the current offset of a clock in the state, along with the uncertainty of that offset.
    pub fn clock_offset(&self, id: ClockId) -> Result<UncertainValue, EstimatorError> {
        let clock_info = self.get_clock_info(id)?;
        Ok(UncertainValue {
            value: self.state[(clock_info.offset_index(), 0)],
            uncertainty: self.uncertainty[(clock_info.offset_index(), clock_info.offset_index())]
                .sqrt(),
        })
    }

    /// Get the current freqency of a clock in the state, along with the uncertainty of that frequency.
    pub fn clock_frequency(&self, id: ClockId) -> Result<UncertainValue, EstimatorError> {
        let clock_info = self.get_clock_info(id)?;
        Ok(UncertainValue {
            value: self.state[(clock_info.frequency_index(), 0)],
            uncertainty: self.uncertainty
                [(clock_info.frequency_index(), clock_info.frequency_index())]
                .sqrt(),
        })
    }

    /// Get the current delay of a link in the state, along with the uncertainty of that delay.
    pub fn link_delay(&self, id: LinkId) -> Result<UncertainValue, EstimatorError> {
        let link_info = self.get_link_info(id)?;
        Ok(UncertainValue {
            value: self.state[(link_info.index, 0)],
            uncertainty: self.uncertainty[(link_info.index, link_info.index)].sqrt(),
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
    use crate::{
        ClockId, LinkId,
        estimator::{EstimatorState, UncertainValue},
    };

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
        let state = EstimatorState::empty(0.0)
            .add_clock(ClockId(1), (0.0, 1.0).into(), (2.0, 3.0).into(), 1e-8)
            .unwrap();
        assert_eq!(state.clock_offset(ClockId(1)).unwrap().value, 0.0);
        assert_eq!(state.clock_offset(ClockId(1)).unwrap().uncertainty, 1.0);
        assert_eq!(state.clock_frequency(ClockId(1)).unwrap().value, 2.0);
        assert_eq!(state.clock_frequency(ClockId(1)).unwrap().uncertainty, 3.0);
    }

    #[test]
    fn test_time_evolve() {
        let state = EstimatorState::empty(0.0)
            .add_clock(ClockId(1), (0.0, 0.0).into(), (1e-6, 0.0).into(), 1e-8)
            .unwrap()
            .add_link(LinkId(1), (0.5, 0.2).into(), 0.0)
            .unwrap()
            .add_clock(ClockId(2), (0.0, 1e-5).into(), (-1e-6, 1e-7).into(), 0.0)
            .unwrap()
            .add_link(LinkId(2), (2.0, 0.0).into(), 0.1)
            .unwrap()
            .progress_time(100.0);
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

        assert_eq!(state.link_delay(LinkId(1)).unwrap().value, 0.5);
        assert_eq!(state.link_delay(LinkId(1)).unwrap().uncertainty, 0.2);

        let state = state.remove_link(LinkId(1)).unwrap();

        assert_eq!(state.clock_frequency(ClockId(2)).unwrap().value, -1e-6);
        assert_eq!(state.clock_frequency(ClockId(2)).unwrap().uncertainty, 1e-7);
        assert_almost_eq!(state.clock_offset(ClockId(2)).unwrap().value, -1e-4);
        assert_almost_eq!(
            state.clock_offset(ClockId(2)).unwrap().uncertainty,
            1e-5 * (2.0f64.sqrt())
        );

        assert_uv_almost_eq!(
            state.link_delay(LinkId(2)).unwrap(),
            UncertainValue::from((2.0, 2.0))
        );
    }

    #[test]
    fn test_progress_time_composes_well() {
        let state = EstimatorState::empty(0.0)
            .add_clock(ClockId(1), (0.0, 0.0).into(), (1e-6, 0.0).into(), 1e-8)
            .unwrap();

        let state_via_intermediate = state.clone().progress_time(75.0).progress_time(100.0);
        let state_at_once = state.progress_time(100.0);

        assert_uv_almost_eq!(
            state_at_once.clock_offset(ClockId(1)).unwrap(),
            state_via_intermediate.clock_offset(ClockId(1)).unwrap()
        );
        assert_uv_almost_eq!(
            state_at_once.clock_frequency(ClockId(1)).unwrap(),
            state_via_intermediate.clock_frequency(ClockId(1)).unwrap()
        );
    }

    #[test]
    fn test_add_link() {
        let state = EstimatorState::empty(0.0)
            .add_link(LinkId(1), (1.0, 2.0).into(), 0.0)
            .expect("Failed to add link");
        assert_eq!(state.link_delay(LinkId(1)).unwrap().value, 1.0);
        assert_eq!(state.link_delay(LinkId(1)).unwrap().uncertainty, 2.0);
    }

    #[test]
    fn test_measure_between_clocks_no_link() {
        let state = EstimatorState::empty(0.0)
            .add_clock(ClockId(1), (0.0, 0.1).into(), (0.0, 1e-8).into(), 1e-8)
            .unwrap()
            .add_clock(ClockId(2), (0.0, 0.1).into(), (0.0, 1e-8).into(), 1e-8)
            .unwrap()
            .measurement(
                ClockId(1),
                ClockId(2),
                (1.0, 2.0f64.sqrt() * 0.1).into(),
                None,
            )
            .unwrap();

        assert_uv_almost_eq!(
            state.clock_offset(ClockId(1)).unwrap(),
            UncertainValue::from((-0.25, 0.05 * (3.0f64.sqrt())))
        );
        assert_uv_almost_eq!(
            state.clock_offset(ClockId(2)).unwrap(),
            UncertainValue::from((0.25, 0.05 * (3.0f64.sqrt())))
        );
        assert_uv_almost_eq!(
            state.clock_frequency(ClockId(1)).unwrap(),
            UncertainValue::from((0.0, 1e-8))
        );
        assert_uv_almost_eq!(
            state.clock_frequency(ClockId(2)).unwrap(),
            UncertainValue::from((0.0, 1e-8))
        );

        let state = EstimatorState::empty(0.0)
            .add_clock(ClockId(1), (0.0, 0.0).into(), (0.0, 1e-3).into(), 0.0)
            .unwrap()
            .add_clock(ClockId(2), (0.0, 0.0).into(), (0.0, 1e-3).into(), 0.0)
            .unwrap()
            .progress_time(100.0)
            .measurement(
                ClockId(1),
                ClockId(2),
                (1.0, 2.0f64.sqrt() * 0.1).into(),
                None,
            )
            .unwrap();

        assert_uv_almost_eq!(
            state.clock_offset(ClockId(1)).unwrap(),
            UncertainValue::from((-0.25, 0.05 * (3.0f64.sqrt())))
        );
        assert_uv_almost_eq!(
            state.clock_offset(ClockId(2)).unwrap(),
            UncertainValue::from((0.25, 0.05 * (3.0f64.sqrt())))
        );
        assert_uv_almost_eq!(
            state.clock_frequency(ClockId(1)).unwrap(),
            UncertainValue::from((-0.0025, 0.0005 * (3.0f64.sqrt())))
        );
        assert_uv_almost_eq!(
            state.clock_frequency(ClockId(2)).unwrap(),
            UncertainValue::from((0.0025, 0.0005 * (3.0f64.sqrt())))
        );
    }

    #[test]
    fn test_measure_between_clocks_with_link() {
        let state = EstimatorState::empty(0.0)
            .add_clock(ClockId(1), (0.0, 0.1).into(), (0.0, 1e-8).into(), 1e-8)
            .unwrap()
            .add_clock(ClockId(2), (0.0, 0.1).into(), (0.0, 1e-8).into(), 1e-8)
            .unwrap()
            .add_link(LinkId(1), (1.0, 0.0).into(), 0.0)
            .unwrap()
            .measurement(
                ClockId(1),
                ClockId(2),
                (2.0, 2.0f64.sqrt() * 0.1).into(),
                Some(LinkId(1)),
            )
            .unwrap();

        assert_uv_almost_eq!(
            state.clock_offset(ClockId(1)).unwrap(),
            UncertainValue::from((-0.25, 0.05 * (3.0f64.sqrt())))
        );
        assert_uv_almost_eq!(
            state.clock_offset(ClockId(2)).unwrap(),
            UncertainValue::from((0.25, 0.05 * (3.0f64.sqrt())))
        );
        assert_uv_almost_eq!(
            state.clock_frequency(ClockId(1)).unwrap(),
            UncertainValue::from((0.0, 1e-8))
        );
        assert_uv_almost_eq!(
            state.clock_frequency(ClockId(2)).unwrap(),
            UncertainValue::from((0.0, 1e-8))
        );
        assert_uv_almost_eq!(
            state.link_delay(LinkId(1)).unwrap(),
            UncertainValue::from((1.0, 0.0))
        );

        let state = EstimatorState::empty(0.0)
            .add_clock(ClockId(1), (0.0, 0.0).into(), (0.0, 1e-8).into(), 1e-8)
            .unwrap()
            .add_clock(ClockId(2), (0.0, 0.0).into(), (0.0, 1e-8).into(), 1e-8)
            .unwrap()
            .add_link(LinkId(1), (0.0, 0.1).into(), 0.0)
            .unwrap()
            .measurement(ClockId(1), ClockId(2), (1.0, 0.1).into(), Some(LinkId(1)))
            .unwrap();

        assert_uv_almost_eq!(
            state.clock_offset(ClockId(1)).unwrap(),
            UncertainValue::from((0.0, 0.0))
        );
        assert_uv_almost_eq!(
            state.clock_offset(ClockId(2)).unwrap(),
            UncertainValue::from((0.0, 0.0))
        );
        assert_uv_almost_eq!(
            state.clock_frequency(ClockId(1)).unwrap(),
            UncertainValue::from((0.0, 1e-8))
        );
        assert_uv_almost_eq!(
            state.clock_frequency(ClockId(2)).unwrap(),
            UncertainValue::from((0.0, 1e-8))
        );
        assert_uv_almost_eq!(
            state.link_delay(LinkId(1)).unwrap(),
            UncertainValue::from((0.5, 0.1 / (2.0f64.sqrt())))
        );
    }

    #[test]
    fn test_measure_external_clock_no_link() {
        let state = EstimatorState::empty(0.0)
            .add_clock(ClockId(1), (0.0, 0.1).into(), (0.0, 1e-8).into(), 1e-8)
            .unwrap()
            .add_external_clock(ClockId(2))
            .unwrap()
            .measurement(ClockId(2), ClockId(1), (1.0, 0.1).into(), None)
            .unwrap();

        assert_uv_almost_eq!(
            state.clock_offset(ClockId(1)).unwrap(),
            UncertainValue::from((0.5, 0.1 / (2.0f64.sqrt())))
        );

        assert_uv_almost_eq!(
            state.clock_frequency(ClockId(1)).unwrap(),
            UncertainValue::from((0.0, 1e-8))
        );

        let state = EstimatorState::empty(0.0)
            .add_clock(ClockId(1), (0.0, 0.1).into(), (0.0, 1e-8).into(), 1e-8)
            .unwrap()
            .add_external_clock(ClockId(2))
            .unwrap()
            .measurement(ClockId(1), ClockId(2), (1.0, 0.1).into(), None)
            .unwrap();

        assert_uv_almost_eq!(
            state.clock_offset(ClockId(1)).unwrap(),
            UncertainValue::from((-0.5, 0.1 / (2.0f64.sqrt())))
        );

        assert_uv_almost_eq!(
            state.clock_frequency(ClockId(1)).unwrap(),
            UncertainValue::from((0.0, 1e-8))
        );

        assert!(state.remove_external_clock(ClockId(2)).is_ok());
    }
}
