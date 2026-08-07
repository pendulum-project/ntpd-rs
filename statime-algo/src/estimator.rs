use statime_base::{ClockId, DirectedLinkId, Duration, LinkId, TAI, Timestamp};

use crate::{
    AlgoError,
    matrix::Matrix,
    storage::{
        EstimatorLinkStorage, ExternalClockStorage, InternalClockStorage, KalmanStorageBase,
    },
};

#[cfg(not(feature = "std"))]
use crate::float_polyfill::FloatPolyfill;

#[derive(Debug, Clone)]
struct ExternalClockList<L>(L);

impl<L: ExternalClockStorage> ExternalClockList<L> {
    fn new() -> Self {
        ExternalClockList(L::new())
    }

    /// Returns true if the given clock is known as an external clock.
    fn contains(&self, id: ClockId) -> bool {
        self.0.contains(&id)
    }

    /// Add a new external clock to the list.
    fn add(&mut self, id: ClockId) -> Result<(), AlgoError> {
        if self.contains(id) {
            Err(AlgoError::ClockAlreadyExists(id))
        } else {
            self.0.push(id);
            Ok(())
        }
    }

    /// Remove an existing external clock from the list.
    fn remove(&mut self, id: ClockId) -> Result<(), AlgoError> {
        if let Some(pos) = self.0.iter().position(|&x| x == id) {
            self.0.remove(pos);
            Ok(())
        } else {
            Err(AlgoError::UnknownClock(id))
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ClockInfo {
    id: ClockId,
    base_index: usize,
    wander: f64,
}

impl ClockInfo {
    const SIZE: usize = 2;

    fn offset_index(self) -> usize {
        self.base_index
    }

    fn frequency_index(self) -> usize {
        self.base_index + 1
    }
}

#[derive(Debug, Clone)]
struct ClockInfoList<L>(L);

impl<L: InternalClockStorage> ClockInfoList<L> {
    fn new() -> Self {
        ClockInfoList(L::new())
    }

    /// Checks if the given clock id exists in the current list.
    fn contains(&self, id: ClockId) -> bool {
        self.0.iter().any(|info| info.id == id)
    }

    /// Update the base indices of all clocks that have a base index greater
    /// than `from`, by subtracting `delta` from them.
    fn update_indices(&mut self, from: usize, delta: usize) {
        for info in &mut *self.0 {
            if info.base_index > from {
                info.base_index -= delta;
            }
        }
    }

    /// Remove the clock info for a given id, if it exists.
    ///
    /// Updates the indices for clocks and links where needed.
    ///
    /// Returns the removed clock info.
    fn remove<LL: EstimatorLinkStorage>(
        &mut self,
        id: ClockId,
        link_info: &mut LinkInfoList<LL>,
    ) -> Result<ClockInfo, AlgoError> {
        let removed = if let Some(pos) = self.0.iter().position(|info| info.id == id) {
            Ok(self.0.remove(pos))
        } else {
            Err(AlgoError::UnknownClock(id))
        }?;

        self.update_indices(removed.base_index, ClockInfo::SIZE);
        link_info.update_indices(removed.base_index, ClockInfo::SIZE);

        Ok(removed)
    }

    /// Add a new clock info to the list, if it doesn't already exist.
    fn add(&mut self, info: ClockInfo) -> Result<(), AlgoError> {
        if self.0.iter().any(|existing| existing.id == info.id) {
            Err(AlgoError::ClockAlreadyExists(info.id))
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
pub struct LinkInfo {
    id: LinkId,
    index: usize,
    /// Fraction of the link delay that we assume the error increases by every second
    decay_rate: f64,
}

impl LinkInfo {
    const SIZE: usize = 1;
}

#[derive(Debug, Clone)]
struct LinkInfoList<L>(L);

impl<L: EstimatorLinkStorage> LinkInfoList<L> {
    fn new() -> Self {
        LinkInfoList(L::new())
    }

    /// Update the indices of all links that have an index greater than `from`, by subtracting `delta` from them.
    fn update_indices(&mut self, from: usize, delta: usize) {
        for info in &mut *self.0 {
            if info.index > from {
                info.index -= delta;
            }
        }
    }

    /// Remove the link info for a given id, if it exists.
    ///
    /// Updates the indices for links and clocks where needed.
    ///
    /// Returns the removed link info.
    fn remove<CL: InternalClockStorage>(
        &mut self,
        id: LinkId,
        clock_info: &mut ClockInfoList<CL>,
    ) -> Result<LinkInfo, AlgoError> {
        let removed = if let Some(pos) = self.0.iter().position(|info| info.id == id) {
            Ok(self.0.remove(pos))
        } else {
            Err(AlgoError::UnknownLink(id))
        }?;

        self.update_indices(removed.index, LinkInfo::SIZE);
        clock_info.update_indices(removed.index, LinkInfo::SIZE);

        Ok(removed)
    }

    /// Add a new link info to the list, if it doesn't already exist.
    fn add(&mut self, info: LinkInfo) -> Result<(), AlgoError> {
        if self.0.iter().any(|existing| existing.id == info.id) {
            Err(AlgoError::LinkAlreadyExists(info.id))
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
///
/// Note how mutating methods on this all consume self. This is on purpose,
/// as it makes it easier to reason about the state of the estimator. This
/// does however mean that errors result in the state being lost. In general
/// it is expected that most errors are unrecoverable. Typically one would
/// keep a list of some of the most recent states though, they could be used
/// for error recovery, but also for tracability and debugging.
#[derive(Debug, Clone)]
pub struct EstimatorState<Storage: KalmanStorageBase> {
    time: Timestamp<TAI>,
    state: Matrix<Storage::MatrixStorage>,
    uncertainty: Matrix<Storage::MatrixStorage>,
    clock_info: ClockInfoList<Storage::InternalClockStorage>,
    external_clocks: ExternalClockList<Storage::ExternalClockStorage>,
    link_info: LinkInfoList<Storage::EstimatorLinkStorage>,
}

/// Represents an uncertain value, with a best estimate and an uncertainty (standard deviation).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct UncertainValue {
    /// Best estimate of the value
    pub value: f64,
    /// Square root of the variance of the value. Corresponds
    /// to 1 standard deviation.
    pub uncertainty: f64,
}

impl UncertainValue {
    /// Add some additional uncertainty to the uncertain value.
    pub fn add_uncertainty(self, extra_uncertainty: f64) -> UncertainValue {
        UncertainValue {
            value: self.value,
            // Addition formula for uncertainty...
            uncertainty: (self.uncertainty.powi(2) + extra_uncertainty.powi(2)).sqrt(),
        }
    }
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

impl<Storage: KalmanStorageBase> EstimatorState<Storage> {
    /// Create a new empty estimator state at the given timestamp.
    ///
    /// This state has no clocks or links contained in it.
    #[must_use]
    pub fn empty(time: Timestamp<TAI>) -> Self {
        Self {
            time,
            state: Matrix::zero(0, 1),
            uncertainty: Matrix::zero(0, 0),
            clock_info: ClockInfoList::new(),
            external_clocks: ExternalClockList::new(),
            link_info: LinkInfoList::new(),
        }
    }

    /// Progress the estimator state to the new timestamp.
    ///
    /// # Errors
    /// Returns an error if the new time provided is before the current time of the estimator.
    pub fn progress_time(mut self, new_time: Timestamp<TAI>) -> Result<Self, AlgoError> {
        let delta_t = new_time - self.time;

        // time should not move backwards
        if delta_t < Duration::ZERO {
            return Err(AlgoError::NonMonotonicTimeProgression {
                from: self.time,
                to: new_time,
            });
        }

        // no time change, return state as is
        if new_time == self.time {
            return Ok(self);
        }

        let delta_t = delta_t.as_seconds();

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

        Ok(self)
    }

    /// Absorb a change in frequency of a clock.
    ///
    /// This function assumes steering happens at the current estimator time.
    ///
    /// # Errors
    /// Returns an error if the steered clock is unknown to the estimator.
    pub fn absorb_frequency_steer(
        mut self,
        steered_clock: ClockId,
        frequency_change: f64,
    ) -> Result<Self, AlgoError> {
        let clock_info = self.get_clock_info(steered_clock)?;
        let frequency_index = clock_info.frequency_index();
        self.state[(frequency_index, 0)] += frequency_change;
        Ok(self)
    }

    /// Absorb a step change in the phase of a clock.
    ///
    /// This function assumes steering happens at the current estimator time.
    ///
    /// # Errors
    /// Returns an error if the steered clock is unknown to the estimator.
    pub fn absorb_offset_change(
        mut self,
        steered_clock: ClockId,
        offset_change: f64,
    ) -> Result<Self, AlgoError> {
        let clock_info = self.get_clock_info(steered_clock)?;
        let offset_index = clock_info.offset_index();
        self.state[(offset_index, 0)] += offset_change;
        Ok(self)
    }

    /// Absorb a step change in the phase of a clock which is also used for the estimator time.
    ///
    /// This function assumes steering happens at the current estimator time.
    ///
    /// # Errors
    /// Returns an error if the steered clock is unknown to the estimator.
    pub fn absorb_system_clock_offset_change(
        mut self,
        steered_clock: ClockId,
        offset_change: Duration,
    ) -> Result<Self, AlgoError> {
        let clock_info = self.get_clock_info(steered_clock)?;
        let offset_index = clock_info.offset_index();
        self.state[(offset_index, 0)] += offset_change.as_seconds();
        self.time += offset_change;
        Ok(self)
    }

    /// Add a new measurement to the estimator state.
    ///
    /// Assumes the measurements happens at the time the estimator state is
    /// currently set to.
    ///
    /// # Errors
    /// Returns an error if either of the clock ids, or the link is unknown.
    /// Also returns an error if both referenced clocks are external.
    pub fn measurement(
        mut self,
        direction: DirectedLinkId,
        offset: UncertainValue,
        delay_link: bool,
    ) -> Result<Self, AlgoError> {
        let mut measurement_projection = Matrix::zero(1, self.state.rows());

        let from = direction.from_clock();
        let to = direction.to_clock();
        let from_external = self.external_clocks.contains(from);
        let to_external = self.external_clocks.contains(to);

        if from_external && to_external {
            return Err(AlgoError::BothClocksExternal(from, to));
        }

        if !from_external {
            let from_clock_info = self.get_clock_info(from)?;
            measurement_projection[(0, from_clock_info.offset_index())] = -1.0;
        }

        if !to_external {
            let to_clock_info = self.get_clock_info(to)?;
            measurement_projection[(0, to_clock_info.offset_index())] = 1.0;
        }

        if delay_link {
            let link_delay_info = self.get_link_info(direction.link_id())?;
            measurement_projection[(0, link_delay_info.index)] = 1.0;
        }

        let expected = &measurement_projection * &self.state;
        let difference = Matrix::<Storage::MatrixStorage>::from(offset.value) - expected;
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

        // This is simply using the strength we calculated before to update the state
        self.state = &self.state + &update_strength * difference;

        // However I don't have a good intuition why this would be its uncertainty. It
        // is derived well on wikipedia, and when having questions I would suggest looking
        // at its page on kalman filters.
        let prev_step_proportionality =
            Matrix::identity(self.state.rows()) - &update_strength * measurement_projection;
        self.uncertainty = (&prev_step_proportionality
            * &self.uncertainty
            * prev_step_proportionality.transpose()
            + &update_strength * offset.uncertainty.powi(2) * update_strength.transpose())
        .symmetrize()?;

        Ok(self)
    }

    /// Add an external clock to the estimator state.
    ///
    /// # Errors
    /// Returns an error if the clock is already known to the estimator.
    pub fn add_external_clock(mut self, id: ClockId) -> Result<Self, AlgoError> {
        // check in clock info as well
        if self.clock_info.contains(id) {
            return Err(AlgoError::ClockAlreadyExists(id));
        }

        self.external_clocks.add(id)?;

        Ok(self)
    }

    /// Remove an external clock from the estimator state.
    ///
    /// # Errors
    /// Returns an error if the clock in question is not an external clock known to the estimator.
    pub fn remove_external_clock(mut self, id: ClockId) -> Result<Self, AlgoError> {
        self.external_clocks.remove(id)?;

        Ok(self)
    }

    /// Add a new clock to the estimator state.'
    ///
    /// To add a new clock you must provide the initial values for the offset,
    /// frequency and wander of the clock.
    ///
    /// # Errors
    /// Returns an erorr if the clock in question is already known to the estimator.
    pub fn add_clock(
        mut self,
        id: ClockId,
        initial_offset: UncertainValue,
        initial_frequency: UncertainValue,
        initial_wander: f64,
    ) -> Result<Self, AlgoError> {
        // check in external clocks as well
        if self.external_clocks.contains(id) {
            return Err(AlgoError::ClockAlreadyExists(id));
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
    ///
    /// # Errors
    /// Returns an error if the clock in question is not known to the estimator.
    pub fn remove_clock(mut self, id: ClockId) -> Result<Self, AlgoError> {
        let clock_info = self.clock_info.remove(id, &mut self.link_info)?;

        self.state = self
            .state
            .splice_vec(clock_info.base_index, ClockInfo::SIZE)?;
        self.uncertainty = self
            .uncertainty
            .splice_square(clock_info.base_index, ClockInfo::SIZE)?;

        Ok(self)
    }

    /// Add a new link to the estimator state.
    ///
    /// The decay rate is the amount the uncertainty on the link delay increases every second on this link.
    ///
    /// # Errors
    /// Returns an error if the link in question is already known or if any of
    /// the clocks in the link are unknown to the estimator.
    pub fn add_link(
        mut self,
        id: LinkId,
        initial_delay: UncertainValue,
        decay_rate: f64,
    ) -> Result<Self, AlgoError> {
        if !self.is_known_clock(id.first_clock()) {
            return Err(AlgoError::UnknownClock(id.first_clock()));
        }

        if !self.is_known_clock(id.second_clock()) {
            return Err(AlgoError::UnknownClock(id.second_clock()));
        }

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
    ///
    /// # Errors
    /// Returns an error if the link in question is unknown.
    pub fn remove_link(mut self, id: LinkId) -> Result<Self, AlgoError> {
        let removed_info = self.link_info.remove(id, &mut self.clock_info)?;
        self.state = self.state.splice_vec(removed_info.index, LinkInfo::SIZE)?;
        self.uncertainty = self
            .uncertainty
            .splice_square(removed_info.index, LinkInfo::SIZE)?;

        Ok(self)
    }

    /// Get the current offset of a clock in the state, along with the uncertainty of that offset.
    ///
    /// # Errors
    /// Returns an error if the clock in question is unknown.
    pub fn clock_offset(&self, id: ClockId) -> Result<UncertainValue, AlgoError> {
        let clock_info = self.get_clock_info(id)?;
        Ok(UncertainValue {
            value: self.state[(clock_info.offset_index(), 0)],
            uncertainty: self.uncertainty[(clock_info.offset_index(), clock_info.offset_index())]
                .sqrt(),
        })
    }

    /// Get the current frequency of a clock in the state, along with the uncertainty of that frequency.
    ///
    /// # Errors
    /// Returns an error if the clock in question is unknown.
    pub fn clock_frequency(&self, id: ClockId) -> Result<UncertainValue, AlgoError> {
        let clock_info = self.get_clock_info(id)?;
        Ok(UncertainValue {
            value: self.state[(clock_info.frequency_index(), 0)],
            uncertainty: self.uncertainty
                [(clock_info.frequency_index(), clock_info.frequency_index())]
                .sqrt(),
        })
    }

    /// Get an estimated duration until the error on this clock hits a given bound
    pub fn time_to_error_bound_exceedance(
        &self,
        id: ClockId,
        bound: Duration,
    ) -> Result<Duration, AlgoError> {
        // 2^20 seconds
        const ABSOLUTE_MAX_EXCEEDANCE_TIME: f64 = 1_048_576.0;
        // How precise we want to calculate the duration.
        const PRECISION: f64 = 1e-3;

        let clock_info = self.get_clock_info(id)?;
        let target = bound.as_seconds().powi(2);
        // We do a binary search on an approximation of the error of the clock after progressing time.
        // For this we use the expansion of the progress time function, which combines the wander, frequency,
        // and offset uncertainties, together with their correlations.
        let c1 = self.uncertainty[(clock_info.offset_index(), clock_info.offset_index())];
        // We force this component up to ensure all components are positive, and therefore the
        // estimate is always increasing. This will allow us to do binary searching later.
        let c2 =
            self.uncertainty[(clock_info.offset_index(), clock_info.frequency_index())].max(0.0);
        let c3 = self.uncertainty[(clock_info.frequency_index(), clock_info.frequency_index())];
        let c4 = clock_info.wander.powi(2);
        let eval = |t: f64| c1 + c2 * t + c3 * t.powi(2) + c4 * t.powi(3);
        let mut low = 0.0;
        let mut high = 1.0;
        // Find a sufficiently high upper bound
        while eval(high) < target {
            if high >= ABSOLUTE_MAX_EXCEEDANCE_TIME {
                return Ok(Duration::from_f64_seconds(ABSOLUTE_MAX_EXCEEDANCE_TIME));
            }

            low = high;
            high *= 2.0;
        }

        while high - low > PRECISION * low {
            let mid = high.midpoint(low);
            if eval(mid) < target {
                low = mid;
            } else {
                high = mid;
            }
        }

        Ok(Duration::from_f64_seconds(low))
    }

    /// Get the current delay of a link in the state, along with the uncertainty of that delay.
    ///
    /// # Errors
    /// Returns an error if the link in question is unknown.
    #[cfg(test)]
    pub fn link_delay(&self, id: LinkId) -> Result<UncertainValue, AlgoError> {
        let link_info = self.get_link_info(id)?;
        Ok(UncertainValue {
            value: self.state[(link_info.index, 0)],
            uncertainty: self.uncertainty[(link_info.index, link_info.index)].sqrt(),
        })
    }

    /// Is a given clock internal
    #[must_use]
    pub fn is_internal_clock(&self, id: ClockId) -> bool {
        self.clock_info.iter().any(|info| info.id == id)
    }

    /// Is a given clock external
    #[must_use]
    pub fn is_external_clock(&self, id: ClockId) -> bool {
        self.external_clocks.contains(id)
    }

    /// Is a given clock known to the estimator
    #[must_use]
    pub fn is_known_clock(&self, id: ClockId) -> bool {
        self.is_internal_clock(id) || self.is_external_clock(id)
    }

    pub(crate) fn current_time(&self) -> Timestamp<TAI> {
        self.time
    }

    fn get_clock_info(&self, id: ClockId) -> Result<&ClockInfo, AlgoError> {
        self.clock_info
            .iter()
            .find(|info| info.id == id)
            .ok_or(AlgoError::UnknownClock(id))
    }

    fn get_link_info(&self, id: LinkId) -> Result<&LinkInfo, AlgoError> {
        self.link_info
            .iter()
            .find(|info| info.id == id)
            .ok_or(AlgoError::UnknownLink(id))
    }
}

#[cfg(all(test, feature = "std"))]
#[allow(clippy::float_cmp, reason = "Test code")]
mod tests {
    use crate::storage::StdKalmanStorage;

    use super::*;

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
        let clock_1 = ClockId::new();
        let clock_2 = ClockId::new();

        let state = EstimatorState::<StdKalmanStorage<()>>::empty(Timestamp::UNIX_EPOCH)
            .add_clock(clock_1, (0.0, 1.0).into(), (2.0, 3.0).into(), 1e-8)
            .unwrap();
        assert_eq!(state.clock_offset(clock_1).unwrap().value, 0.0);
        assert_eq!(state.clock_offset(clock_1).unwrap().uncertainty, 1.0);
        assert_eq!(state.clock_frequency(clock_1).unwrap().value, 2.0);
        assert_eq!(state.clock_frequency(clock_1).unwrap().uncertainty, 3.0);

        assert_eq!(
            state.clone().add_external_clock(clock_1).unwrap_err(),
            AlgoError::ClockAlreadyExists(clock_1)
        );
        let state = state.add_external_clock(clock_2).unwrap();

        assert_eq!(
            state
                .add_clock(clock_2, (0.0, 1.0).into(), (2.0, 3.0).into(), 1e-8)
                .unwrap_err(),
            AlgoError::ClockAlreadyExists(clock_2)
        );
    }

    #[test]
    fn test_clock_removal() {
        let clock_1 = ClockId::new();
        let clock_2 = ClockId::new();
        let clock_3 = ClockId::new();

        let state = EstimatorState::<StdKalmanStorage<()>>::empty(Timestamp::UNIX_EPOCH)
            .add_clock(clock_1, (0.0, 1.0).into(), (0.0, 1.0).into(), 1e-8)
            .unwrap()
            .add_external_clock(clock_2)
            .unwrap();

        // remove non-existing clock should fail
        assert_eq!(
            state.clone().remove_clock(clock_3).unwrap_err(),
            AlgoError::UnknownClock(clock_3)
        );

        // remove existing clock via external clock removal should fail
        assert_eq!(
            state.clone().remove_external_clock(clock_1).unwrap_err(),
            AlgoError::UnknownClock(clock_1)
        );

        // remove existing external clock via internal clock removal should fail
        assert_eq!(
            state.clone().remove_clock(clock_2).unwrap_err(),
            AlgoError::UnknownClock(clock_2)
        );

        // removing the existing clocks should succeed
        state
            .remove_clock(clock_1)
            .unwrap()
            .remove_external_clock(clock_2)
            .unwrap();
    }

    #[test]
    fn test_time_evolve() {
        let clock_1 = ClockId::new();
        let clock_2 = ClockId::new();

        let link_1 = LinkId::new(clock_1, clock_2).unwrap();
        let link_2 = LinkId::new(clock_1, clock_2).unwrap();

        let state = EstimatorState::<StdKalmanStorage<()>>::empty(Timestamp::UNIX_EPOCH)
            .add_clock(clock_1, (0.0, 0.0).into(), (1e-6, 0.0).into(), 1e-8)
            .unwrap()
            .add_clock(clock_2, (0.0, 1e-5).into(), (-1e-6, 1e-7).into(), 0.0)
            .unwrap()
            .add_link(link_1, (0.5, 0.2).into(), 0.0)
            .unwrap()
            .add_link(link_2, (2.0, 0.0).into(), 0.1)
            .unwrap()
            .progress_time(Timestamp::UNIX_EPOCH + Duration::from_seconds_nanos(100, 0))
            .unwrap();
        assert_eq!(state.clock_frequency(clock_1).unwrap().value, 1e-6);
        // Random walk noise, so frequency deviation is sqrt(time_interval)*wander.
        assert_almost_eq!(state.clock_frequency(clock_1).unwrap().uncertainty, 1e-7);
        // Pre-existing frequency offset should cause phase offset.
        assert_almost_eq!(state.clock_offset(clock_1).unwrap().value, 1e-4);
        // Random walk noise in the derivative, so the integral gives an
        // additional factor of time compared to the frequency deviation.
        // The factor sqrt(3) follows from the structure of how updates work.
        assert_almost_eq!(
            state.clock_offset(clock_1).unwrap().uncertainty,
            1e-5 / (3.0f64.sqrt())
        );

        let state = state.remove_clock(clock_1).unwrap();

        assert_eq!(state.link_delay(link_1).unwrap().value, 0.5);
        assert_eq!(state.link_delay(link_1).unwrap().uncertainty, 0.2);

        let state = state.remove_link(link_1).unwrap();

        assert_eq!(state.clock_frequency(clock_2).unwrap().value, -1e-6);
        assert_eq!(state.clock_frequency(clock_2).unwrap().uncertainty, 1e-7);
        assert_almost_eq!(state.clock_offset(clock_2).unwrap().value, -1e-4);
        assert_almost_eq!(
            state.clock_offset(clock_2).unwrap().uncertainty,
            1e-5 * (2.0f64.sqrt())
        );

        assert_uv_almost_eq!(
            state.link_delay(link_2).unwrap(),
            UncertainValue::from((2.0, 2.0))
        );
    }

    #[test]
    fn test_frequency_steering() {
        let clock_1 = ClockId::new();

        let state = EstimatorState::<StdKalmanStorage<()>>::empty(Timestamp::UNIX_EPOCH)
            .add_clock(clock_1, (0.0, 0.0).into(), (1e-6, 0.0).into(), 1e-8)
            .unwrap()
            .absorb_frequency_steer(clock_1, -1e-6)
            .unwrap();

        assert_uv_almost_eq!(
            state.clock_frequency(clock_1).unwrap(),
            UncertainValue::from((0.0, 0.0))
        );
    }

    #[test]
    fn test_clock_offset_steering() {
        let clock_1 = ClockId::new();
        let clock_2 = ClockId::new();

        let state = EstimatorState::<StdKalmanStorage<()>>::empty(
            Timestamp::UNIX_EPOCH + Duration::from_seconds_nanos(10, 0),
        )
        .add_clock(clock_1, (0.0, 0.0).into(), (1e-6, 0.0).into(), 1e-8)
        .unwrap()
        .add_clock(clock_2, (0.0, 0.0).into(), (1e-6, 0.0).into(), 1e-8)
        .unwrap()
        .absorb_offset_change(clock_2, 1.0)
        .unwrap();

        assert_eq!(
            state.time,
            Timestamp::UNIX_EPOCH + Duration::from_seconds_nanos(10, 0)
        );
        assert_uv_almost_eq!(
            state.clock_offset(clock_2).unwrap(),
            UncertainValue::from((1.0, 0.0))
        );

        let state = state
            .absorb_system_clock_offset_change(clock_1, Duration::from_seconds_nanos(-1, 0))
            .unwrap();
        assert_eq!(
            state.time,
            Timestamp::UNIX_EPOCH + Duration::from_seconds_nanos(9, 0)
        );
        assert_uv_almost_eq!(
            state.clock_offset(clock_1).unwrap(),
            UncertainValue::from((-1.0, 0.0))
        );
    }

    #[test]
    fn test_progress_time_composes_well() {
        let clock_1 = ClockId::new();

        let state = EstimatorState::<StdKalmanStorage<()>>::empty(Timestamp::UNIX_EPOCH)
            .add_clock(clock_1, (0.0, 0.0).into(), (1e-6, 0.0).into(), 1e-8)
            .unwrap();

        let state_via_intermediate = state
            .clone()
            .progress_time(Timestamp::UNIX_EPOCH + Duration::from_seconds_nanos(75, 0))
            .unwrap()
            .progress_time(Timestamp::UNIX_EPOCH + Duration::from_seconds_nanos(100, 0))
            .unwrap();
        let state_at_once = state
            .progress_time(Timestamp::UNIX_EPOCH + Duration::from_seconds_nanos(100, 0))
            .unwrap();

        assert_uv_almost_eq!(
            state_at_once.clock_offset(clock_1).unwrap(),
            state_via_intermediate.clock_offset(clock_1).unwrap()
        );
        assert_uv_almost_eq!(
            state_at_once.clock_frequency(clock_1).unwrap(),
            state_via_intermediate.clock_frequency(clock_1).unwrap()
        );
    }

    #[test]
    fn test_add_link() {
        let clock_1 = ClockId::new();
        let clock_2 = ClockId::new();
        let link_1 = LinkId::new(clock_1, clock_2).unwrap();

        let state = EstimatorState::<StdKalmanStorage<()>>::empty(Timestamp::UNIX_EPOCH)
            .add_clock(clock_1, (0.0, 0.0).into(), (1e-6, 0.0).into(), 1e-8)
            .unwrap()
            .add_clock(clock_2, (0.0, 1e-5).into(), (-1e-6, 1e-7).into(), 0.0)
            .unwrap()
            .add_link(link_1, (1.0, 2.0).into(), 0.0)
            .expect("Failed to add link");
        assert_eq!(state.link_delay(link_1).unwrap().value, 1.0);
        assert_eq!(state.link_delay(link_1).unwrap().uncertainty, 2.0);
    }

    #[test]
    fn test_measure_between_clocks_no_link() {
        let clock_1 = ClockId::new();
        let clock_2 = ClockId::new();

        let state = EstimatorState::<StdKalmanStorage<()>>::empty(Timestamp::UNIX_EPOCH)
            .add_clock(clock_1, (0.0, 0.1).into(), (0.0, 1e-8).into(), 1e-8)
            .unwrap()
            .add_clock(clock_2, (0.0, 0.1).into(), (0.0, 1e-8).into(), 1e-8)
            .unwrap()
            .measurement(
                LinkId::new(clock_1, clock_2).unwrap().forward(),
                (1.0, 2.0f64.sqrt() * 0.1).into(),
                false,
            )
            .unwrap();

        assert_uv_almost_eq!(
            state.clock_offset(clock_1).unwrap(),
            UncertainValue::from((-0.25, 0.05 * (3.0f64.sqrt())))
        );
        assert_uv_almost_eq!(
            state.clock_offset(clock_2).unwrap(),
            UncertainValue::from((0.25, 0.05 * (3.0f64.sqrt())))
        );
        assert_uv_almost_eq!(
            state.clock_frequency(clock_1).unwrap(),
            UncertainValue::from((0.0, 1e-8))
        );
        assert_uv_almost_eq!(
            state.clock_frequency(clock_2).unwrap(),
            UncertainValue::from((0.0, 1e-8))
        );

        let state = EstimatorState::<StdKalmanStorage<()>>::empty(Timestamp::UNIX_EPOCH)
            .add_clock(clock_1, (0.0, 0.0).into(), (0.0, 1e-3).into(), 0.0)
            .unwrap()
            .add_clock(clock_2, (0.0, 0.0).into(), (0.0, 1e-3).into(), 0.0)
            .unwrap()
            .progress_time(Timestamp::UNIX_EPOCH + Duration::from_seconds_nanos(100, 0))
            .unwrap()
            .measurement(
                LinkId::new(clock_1, clock_2).unwrap().forward(),
                (1.0, 2.0f64.sqrt() * 0.1).into(),
                false,
            )
            .unwrap();

        assert_uv_almost_eq!(
            state.clock_offset(clock_1).unwrap(),
            UncertainValue::from((-0.25, 0.05 * (3.0f64.sqrt())))
        );
        assert_uv_almost_eq!(
            state.clock_offset(clock_2).unwrap(),
            UncertainValue::from((0.25, 0.05 * (3.0f64.sqrt())))
        );
        assert_uv_almost_eq!(
            state.clock_frequency(clock_1).unwrap(),
            UncertainValue::from((-0.0025, 0.0005 * (3.0f64.sqrt())))
        );
        assert_uv_almost_eq!(
            state.clock_frequency(clock_2).unwrap(),
            UncertainValue::from((0.0025, 0.0005 * (3.0f64.sqrt())))
        );
    }

    #[test]
    fn test_measure_between_clocks_with_link() {
        let clock_1 = ClockId::new();
        let clock_2 = ClockId::new();
        let link_1 = LinkId::new(clock_1, clock_2).unwrap();

        let state = EstimatorState::<StdKalmanStorage<()>>::empty(Timestamp::UNIX_EPOCH)
            .add_clock(clock_1, (0.0, 0.1).into(), (0.0, 1e-8).into(), 1e-8)
            .unwrap()
            .add_clock(clock_2, (0.0, 0.1).into(), (0.0, 1e-8).into(), 1e-8)
            .unwrap()
            .add_link(link_1, (1.0, 0.0).into(), 0.0)
            .unwrap()
            .measurement(link_1.forward(), (2.0, 2.0f64.sqrt() * 0.1).into(), true)
            .unwrap();

        assert_uv_almost_eq!(
            state.clock_offset(clock_1).unwrap(),
            UncertainValue::from((-0.25, 0.05 * (3.0f64.sqrt())))
        );
        assert_uv_almost_eq!(
            state.clock_offset(clock_2).unwrap(),
            UncertainValue::from((0.25, 0.05 * (3.0f64.sqrt())))
        );
        assert_uv_almost_eq!(
            state.clock_frequency(clock_1).unwrap(),
            UncertainValue::from((0.0, 1e-8))
        );
        assert_uv_almost_eq!(
            state.clock_frequency(clock_2).unwrap(),
            UncertainValue::from((0.0, 1e-8))
        );
        assert_uv_almost_eq!(
            state.link_delay(link_1).unwrap(),
            UncertainValue::from((1.0, 0.0))
        );

        let state = EstimatorState::<StdKalmanStorage<()>>::empty(Timestamp::UNIX_EPOCH)
            .add_clock(clock_1, (0.0, 0.0).into(), (0.0, 1e-8).into(), 1e-8)
            .unwrap()
            .add_clock(clock_2, (0.0, 0.0).into(), (0.0, 1e-8).into(), 1e-8)
            .unwrap()
            .add_link(link_1, (0.0, 0.1).into(), 0.0)
            .unwrap()
            .measurement(link_1.forward(), (1.0, 0.1).into(), true)
            .unwrap();

        assert_uv_almost_eq!(
            state.clock_offset(clock_1).unwrap(),
            UncertainValue::from((0.0, 0.0))
        );
        assert_uv_almost_eq!(
            state.clock_offset(clock_2).unwrap(),
            UncertainValue::from((0.0, 0.0))
        );
        assert_uv_almost_eq!(
            state.clock_frequency(clock_1).unwrap(),
            UncertainValue::from((0.0, 1e-8))
        );
        assert_uv_almost_eq!(
            state.clock_frequency(clock_2).unwrap(),
            UncertainValue::from((0.0, 1e-8))
        );
        assert_uv_almost_eq!(
            state.link_delay(link_1).unwrap(),
            UncertainValue::from((0.5, 0.1 / (2.0f64.sqrt())))
        );
    }

    #[test]
    fn test_measure_external_clock_no_link() {
        let clock_1 = ClockId::new();
        let clock_2 = ClockId::new();

        let state = EstimatorState::<StdKalmanStorage<()>>::empty(Timestamp::UNIX_EPOCH)
            .add_clock(clock_1, (0.0, 0.1).into(), (0.0, 1e-8).into(), 1e-8)
            .unwrap()
            .add_external_clock(clock_2)
            .unwrap()
            .measurement(
                LinkId::new(clock_2, clock_1).unwrap().forward(),
                (1.0, 0.1).into(),
                false,
            )
            .unwrap();

        assert_uv_almost_eq!(
            state.clock_offset(clock_1).unwrap(),
            UncertainValue::from((0.5, 0.1 / (2.0f64.sqrt())))
        );

        assert_uv_almost_eq!(
            state.clock_frequency(clock_1).unwrap(),
            UncertainValue::from((0.0, 1e-8))
        );

        let state = EstimatorState::<StdKalmanStorage<()>>::empty(Timestamp::UNIX_EPOCH)
            .add_clock(clock_1, (0.0, 0.1).into(), (0.0, 1e-8).into(), 1e-8)
            .unwrap()
            .add_external_clock(clock_2)
            .unwrap()
            .measurement(
                LinkId::new(clock_1, clock_2).unwrap().forward(),
                (1.0, 0.1).into(),
                false,
            )
            .unwrap();

        assert_uv_almost_eq!(
            state.clock_offset(clock_1).unwrap(),
            UncertainValue::from((-0.5, 0.1 / (2.0f64.sqrt())))
        );

        assert_uv_almost_eq!(
            state.clock_frequency(clock_1).unwrap(),
            UncertainValue::from((0.0, 1e-8))
        );

        assert!(state.remove_external_clock(clock_2).is_ok());
    }

    #[test]
    fn test_negative_time_step() {
        let state = EstimatorState::<StdKalmanStorage<()>>::empty(
            Timestamp::UNIX_EPOCH + Duration::from_seconds_nanos(1, 0),
        );
        assert_eq!(
            state
                .clone()
                .progress_time(Timestamp::UNIX_EPOCH)
                .unwrap_err(),
            AlgoError::NonMonotonicTimeProgression {
                from: Timestamp::UNIX_EPOCH + Duration::from_seconds_nanos(1, 0),
                to: Timestamp::UNIX_EPOCH
            }
        );
    }

    #[test]
    fn test_invalid_measurements() {
        let clock_1 = ClockId::new();
        let clock_2 = ClockId::new();
        let clock_3 = ClockId::new();
        let clock_4 = ClockId::new();
        let clock_5 = ClockId::new();
        let link_1 = LinkId::new(clock_3, clock_1).unwrap();

        let state = EstimatorState::<StdKalmanStorage<()>>::empty(Timestamp::UNIX_EPOCH)
            .add_external_clock(clock_1)
            .unwrap()
            .add_external_clock(clock_2)
            .unwrap()
            .add_clock(clock_3, (0.0, 0.1).into(), (0.0, 1e-8).into(), 1e-8)
            .unwrap()
            .add_clock(clock_4, (0.0, 0.1).into(), (0.0, 1e-8).into(), 1e-8)
            .unwrap();

        assert_eq!(
            state
                .clone()
                .measurement(
                    LinkId::new(clock_1, clock_2).unwrap().forward(),
                    (0.0, 0.1).into(),
                    false
                )
                .unwrap_err(),
            AlgoError::BothClocksExternal(clock_1, clock_2)
        );

        assert_eq!(
            state
                .clone()
                .measurement(
                    LinkId::new(clock_3, clock_5).unwrap().forward(),
                    (0.0, 0.1).into(),
                    false
                )
                .unwrap_err(),
            AlgoError::UnknownClock(clock_5)
        );

        assert_eq!(
            state
                .clone()
                .measurement(
                    LinkId::new(clock_5, clock_3).unwrap().forward(),
                    (0.0, 0.1).into(),
                    false
                )
                .unwrap_err(),
            AlgoError::UnknownClock(clock_5)
        );

        assert_eq!(
            state
                .clone()
                .measurement(link_1.forward(), (0.0, 0.1).into(), true)
                .unwrap_err(),
            AlgoError::UnknownLink(link_1)
        );
    }

    #[test]
    fn test_exceedance_bound() {
        let clock_1 = ClockId::new();
        let clock_2 = ClockId::new();

        let state = EstimatorState::<StdKalmanStorage<()>>::empty(Timestamp::UNIX_EPOCH)
            .add_clock(clock_1, (0.0, 5e-4).into(), (0.0, 1e-6).into(), 0.0)
            .unwrap()
            .add_clock(clock_2, (0.0, 0.0).into(), (0.0, 0.0).into(), 1e-9)
            .unwrap();
        // Approximately sqrt(750000) to within precision choice
        assert_almost_eq!(
            state
                .time_to_error_bound_exceedance(clock_1, Duration::from_seconds_nanos(0, 1_000_000))
                .unwrap()
                .as_seconds(),
            866.0
        );
        // Approximately 10000 to within precision choice
        assert_almost_eq!(
            state
                .time_to_error_bound_exceedance(clock_2, Duration::from_seconds_nanos(0, 1_000_000))
                .unwrap()
                .as_seconds(),
            9992.0
        );
        let state = state
            .progress_time(Timestamp::UNIX_EPOCH + Duration::from_seconds_nanos(433, 0))
            .unwrap();
        // at least the remainder
        assert!(
            state
                .time_to_error_bound_exceedance(clock_1, Duration::from_seconds_nanos(0, 1_000_000))
                .unwrap()
                .as_seconds()
                > 433.0
        );
        assert!(
            state
                .time_to_error_bound_exceedance(clock_2, Duration::from_seconds_nanos(0, 1_000_000))
                .unwrap()
                .as_seconds()
                > 9992.0 - 433.0
        );
    }
}
