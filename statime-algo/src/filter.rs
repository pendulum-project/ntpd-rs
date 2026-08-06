use statime_base::{
    ClockId, DirectedLinkId, Direction, Duration, LeapStatus, LinkId, TAI, Timestamp,
};

use crate::{
    AlgoError,
    estimator::{EstimatorState, UncertainValue},
    link_noise::{LinkDelayNoiseEstimate, LinkNoiseEstimator},
    ringbuffer::UnorderedRingBuffer,
    storage::{FilterLinkStorage, KalmanStorageBase},
};

#[derive(Debug, Clone)]
enum LinkState {
    Tracked {
        link_noise_estimator: LinkNoiseEstimator,
        decay_rate: f64,
    },
    Untracked,
}

impl LinkState {
    /// Get the current delay and noise estimate for the link.
    ///
    /// # Errors
    /// Returns an error if the link is tracked but the delay and noise estimate is not yet available.
    fn delay_and_noise_estimate(&self) -> Result<LinkDelayNoiseEstimate, AlgoError> {
        match self {
            LinkState::Tracked {
                link_noise_estimator,
                ..
            } => Ok(link_noise_estimator.delay_and_noise_estimate()?),
            LinkState::Untracked => Ok(LinkDelayNoiseEstimate {
                delay: 0.0,
                noise: 0.0,
            }),
        }
    }

    /// Get the decay rate for the link.
    fn decay_rate(&self) -> f64 {
        match self {
            LinkState::Tracked { decay_rate, .. } => *decay_rate,
            LinkState::Untracked => 0.0,
        }
    }

    /// Update estimates based on a new measurement.
    fn measurement(&mut self, direction: Direction, offset: UncertainValue, time: Timestamp<TAI>) {
        if let LinkState::Tracked {
            link_noise_estimator,
            ..
        } = self
        {
            *link_noise_estimator =
                link_noise_estimator
                    .clone()
                    .measurement(direction, offset.value, time);
        }
    }

    /// Returns true if this is a tracked link, false if it is untracked.
    fn is_tracked(&self) -> bool {
        matches!(self, LinkState::Tracked { .. })
    }
}

#[derive(Debug, Clone)]
struct ExternalLinkState {
    last_offsets: UnorderedRingBuffer,
    last_offset_uncertainty: f64,
    root_delay: f64,
    leap_status: Option<LeapStatus>,
    usable: bool,
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct OffsetWindow {
    low: f64,
    high: f64,
}

impl OffsetWindow {
    /// Returns true if this window overlaps the other window
    pub fn overlaps(self, other: OffsetWindow) -> bool {
        self.low <= other.high && self.high >= other.low
    }
}

#[derive(Debug, Clone)]
pub struct LinkInfo {
    id: LinkId,
    active: bool,
    link_state: LinkState,
    external_link_state: Option<ExternalLinkState>,
}

impl LinkInfo {
    /// Get an offset window for the link.
    ///
    /// Returns None if the link is not with an external clock, or if the link is not usable.
    fn offset_window<Storage: KalmanStorageBase>(
        &self,
        config: &LinkFilterConfig,
        state: &EstimatorState<Storage>,
    ) -> Option<OffsetWindow> {
        let external_link_state = self.external_link_state.as_ref()?;

        if external_link_state.last_offsets.as_ref().is_empty() || !external_link_state.usable {
            return None;
        }

        let internal_clock = if state.is_internal_clock(self.id.first_clock()) {
            self.id.first_clock()
        } else {
            self.id.second_clock()
        };

        let internal_offset = state.clock_offset(internal_clock).ok()?.value;

        #[expect(
            clippy::cast_precision_loss,
            reason = "self.last_offsets length is always exactly representable as f64"
        )]
        let avg_offset = external_link_state
            .last_offsets
            .as_ref()
            .iter()
            .sum::<f64>()
            / (external_link_state.last_offsets.as_ref().len() as f64);

        let LinkDelayNoiseEstimate { delay, noise } =
            self.link_state.delay_and_noise_estimate().ok()?;
        let half_window_size = noise * config.select_link_uncertainty_window
            + external_link_state.last_offset_uncertainty * config.select_offset_uncertainty_window
            + (delay + external_link_state.root_delay) * config.select_delay_uncertainty_window;

        if half_window_size < config.select_max_window_size {
            Some(OffsetWindow {
                low: avg_offset - internal_offset - half_window_size,
                high: avg_offset - internal_offset + half_window_size,
            })
        } else {
            None
        }
    }

    fn update_link_offsets_from_steer(&mut self, steered_clock: ClockId, offset_change: f64) {
        if let Some(external_state) = &mut self.external_link_state
            && self.id.contains_clock(steered_clock)
        {
            for offset in external_state.last_offsets.as_mut() {
                *offset += offset_change;
            }
        }
    }
}

/// A list of links, with some utility functions for finding and iterating over
/// them.
#[derive(Debug, Clone)]
struct LinkInfoList<L>(L);

impl<L: FilterLinkStorage> LinkInfoList<L> {
    /// Create a new, empty `LinkInfoList`.
    fn new() -> Self {
        LinkInfoList(L::new())
    }

    /// Find a link by its id, returning a reference to it.
    ///
    /// # Errors
    /// Returns an error if the link is not found.
    fn find_by_id(&self, id: LinkId) -> Result<&LinkInfo, AlgoError> {
        self.0
            .iter()
            .find(|info| info.id == id)
            .ok_or(AlgoError::UnknownLink(id))
    }

    /// Find a link by its id, returning a mutable reference to it.
    ///
    /// # Errors
    /// Returns an error if the link is not found.
    fn find_by_id_mut(&mut self, id: LinkId) -> Result<&mut LinkInfo, AlgoError> {
        self.0
            .iter_mut()
            .find(|info| info.id == id)
            .ok_or(AlgoError::UnknownLink(id))
    }

    /// Add a new link to the list.
    fn add_link(&mut self, link: LinkInfo) {
        self.0.push(link);
    }

    /// Remove a link from the list.
    fn remove_link(&mut self, id: LinkId) -> Result<LinkInfo, AlgoError> {
        let index = self
            .0
            .iter()
            .position(|info| info.id == id)
            .ok_or(AlgoError::UnknownLink(id))?;
        Ok(self.0.remove(index))
    }

    /// Iterate over the links in the list.
    fn iter(&self) -> impl Iterator<Item = &LinkInfo> {
        self.into_iter()
    }
}

impl<'a, L: FilterLinkStorage> IntoIterator for &'a LinkInfoList<L> {
    type Item = &'a LinkInfo;
    type IntoIter = core::slice::Iter<'a, LinkInfo>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<'a, L: FilterLinkStorage> IntoIterator for &'a mut LinkInfoList<L> {
    type Item = &'a mut LinkInfo;
    type IntoIter = core::slice::IterMut<'a, LinkInfo>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter_mut()
    }
}

/// A state estimation filter with full support for handling selection an dprocessing of links.
#[derive(Debug, Clone)]
pub struct LinkFilter<Storage: KalmanStorageBase> {
    links: LinkInfoList<Storage::FilterLinkStorage>,
    estimation_state: EstimatorState<Storage>,
}

#[derive(Debug, Clone)]
pub struct LinkFilterConfig {
    /// Size of the window of uncertainty to assume around source offset for
    /// judging whether it is a truechimer, based on the observed noise in the
    /// offset.
    pub select_offset_uncertainty_window: f64,
    /// Size of the window of uncertainty to assume around source offset for
    /// judging whether it is a truechimer, based on the observed link delay
    /// noise.
    pub select_link_uncertainty_window: f64,
    /// Size of the window of uncertainty to assume around source offset for
    /// judging whether it is a truechimer, from potential asymmetry due to
    /// delay and root delay.
    pub select_delay_uncertainty_window: f64,
    /// Maximum size of the window of uncertainty before we judge a source to
    /// be unsuitable for synchronization.
    pub select_max_window_size: f64,
    /// Minimum number of sources that need to agree on the current time before
    /// we enable synchronization.
    pub minimum_agreeing_sources: usize,
}

impl<Storage: KalmanStorageBase> LinkFilter<Storage> {
    /// Create a new, empty `LinkFilter`.
    #[must_use]
    pub fn empty(time: Timestamp<TAI>) -> Self {
        LinkFilter {
            links: LinkInfoList::new(),
            estimation_state: EstimatorState::empty(time),
        }
    }

    /// Progress the time of the filter.
    ///
    /// # Errors
    /// Returns an error if the new time is before the current time of the filter.
    pub fn progress_time(mut self, new_time: Timestamp<TAI>) -> Result<Self, AlgoError> {
        self.estimation_state = self.estimation_state.progress_time(new_time)?;
        Ok(self)
    }

    /// Absorb a frequency change of one of the clocks.
    ///
    /// # Errors
    /// Returns an error if the steered clock is not known to the filter.
    pub fn absorb_frequency_steer(
        mut self,
        steered_clock: ClockId,
        frequency_change: f64,
    ) -> Result<Self, AlgoError> {
        self.estimation_state = self
            .estimation_state
            .absorb_frequency_steer(steered_clock, frequency_change)?;
        Ok(self)
    }

    /// Absorb a step change in the phase of a clock.
    ///
    /// This function assumes steering happens at the current filter time.
    ///
    /// # Errors
    /// Returns an error if the steered clock is unknown to the filter.
    pub fn absorb_offset_change(
        mut self,
        steered_clock: ClockId,
        offset_change: f64,
    ) -> Result<Self, AlgoError> {
        self.estimation_state = self
            .estimation_state
            .absorb_offset_change(steered_clock, offset_change)?;
        for link in &mut self.links {
            if let LinkState::Tracked {
                link_noise_estimator,
                ..
            } = &mut link.link_state
            {
                *link_noise_estimator = link_noise_estimator
                    .clone()
                    .absorb_offset_change(steered_clock);
            }

            link.update_link_offsets_from_steer(steered_clock, offset_change);
        }
        Ok(self)
    }

    /// Absorb a step change in the phase of a clock which is also used for the filter time.
    ///
    /// This function assumes steering happens at the current filter time.
    ///
    /// # Errors
    /// Returns an error if the steered clock is unknown to the filter.
    pub fn absorb_system_clock_offset_change(
        mut self,
        steered_clock: ClockId,
        offset_change: Duration,
    ) -> Result<Self, AlgoError> {
        self.estimation_state = self
            .estimation_state
            .absorb_system_clock_offset_change(steered_clock, offset_change)?;
        for link in &mut self.links {
            if let LinkState::Tracked {
                link_noise_estimator,
                ..
            } = &mut link.link_state
            {
                *link_noise_estimator = link_noise_estimator
                    .clone()
                    .absorb_system_clock_offset_change(steered_clock, offset_change);
            }

            link.update_link_offsets_from_steer(steered_clock, offset_change.as_seconds());
        }

        Ok(self)
    }

    /// Process a measurement from one of the links.
    ///
    /// # Errors
    /// Returns an error if the provided link is unknown.
    pub fn measurement(
        mut self,
        config: &LinkFilterConfig,
        direction: DirectedLinkId,
        offset: UncertainValue,
    ) -> Result<Self, AlgoError> {
        let link = self.links.find_by_id_mut(direction.link_id())?;

        link.link_state.measurement(
            direction.direction(),
            offset,
            self.estimation_state.current_time(),
        );
        let Ok(estimates) = link.link_state.delay_and_noise_estimate() else {
            // Delay and noise not known yet, so link not yet usable, not even for basic offset estimation.
            return Ok(self);
        };
        let decay_rate = link.link_state.decay_rate();
        let is_tracked_link = link.link_state.is_tracked();

        if let Some(external_link_state) = &mut link.external_link_state {
            // Ensure offset is calculated relative to the external clock, flipping signs
            // if the measurement direction was different.
            let offset_to_external = if self
                .estimation_state
                .is_external_clock(direction.from_clock())
            {
                offset.value - estimates.delay
            } else {
                -(offset.value - estimates.delay)
            };

            external_link_state.last_offsets.insert(offset_to_external);
            external_link_state.last_offset_uncertainty = offset.uncertainty;

            let our_window = link.offset_window(config, &self.estimation_state);

            let Some(consensus_window) = self.find_external_consensus_window(config) else {
                // If there is no consensus currently, wait until there is before we start
                // discarding links. This ensures that short-term disagreement doesn't
                // immediately reset synchronization, but that we still don't steer without
                // consensus.
                return Ok(self);
            };

            let link = self.links.find_by_id_mut(direction.link_id())?;

            // We are active if and only if our window overlaps with the consensus window.
            if let Some(our_window) = our_window
                && our_window.overlaps(consensus_window)
            {
                if !link.active {
                    link.active = true;
                    if is_tracked_link {
                        self.estimation_state = self.estimation_state.add_link(
                            direction.link_id(),
                            (estimates.delay, estimates.noise).into(),
                            decay_rate,
                        )?;
                    }
                }
            } else {
                if link.active {
                    link.active = false;
                    if is_tracked_link {
                        self.estimation_state =
                            self.estimation_state.remove_link(direction.link_id())?;
                    }
                }
                return Ok(self);
            }
        } else if !link.active {
            link.active = true;
            if is_tracked_link {
                self.estimation_state = self.estimation_state.add_link(
                    direction.link_id(),
                    (estimates.delay, estimates.noise).into(),
                    decay_rate,
                )?;
            }
        }

        self.estimation_state = self.estimation_state.measurement(
            direction,
            offset.add_uncertainty(estimates.noise),
            is_tracked_link,
        )?;

        Ok(self)
    }

    pub fn external_data_update(
        mut self,
        link_id: LinkId,
        root_delay: f64,
        leap_status: Option<LeapStatus>,
        usable: bool,
    ) -> Result<Self, AlgoError> {
        let link = self.links.find_by_id_mut(link_id)?;
        if let Some(external_state) = &mut link.external_link_state {
            external_state.root_delay = root_delay;
            external_state.leap_status = leap_status;
            external_state.usable = usable;
            Ok(self)
        } else {
            Err(AlgoError::LinkNotExternal(link_id))
        }
    }

    #[must_use]
    pub fn leap_vote(&self, config: &LinkFilterConfig) -> Option<LeapStatus> {
        let consensus_window = self.find_external_consensus_window(config)?;

        let mut count_none = 0;
        let mut count_59 = 0;
        let mut count_61 = 0;

        for link in self.links.iter() {
            if let Some(window) = link.offset_window(config, &self.estimation_state)
                && window.overlaps(consensus_window)
                && let Some(state) = &link.external_link_state
            {
                match state.leap_status {
                    Some(LeapStatus::None) => count_none += 1,
                    Some(LeapStatus::Leap59) => count_59 += 1,
                    Some(LeapStatus::Leap61) => count_61 += 1,
                    None => { /* no vote */ }
                }
            }
        }

        let total = count_none + count_59 + count_61;

        if count_none * 2 > total {
            Some(LeapStatus::None)
        } else if count_59 * 2 > total {
            Some(LeapStatus::Leap59)
        } else if count_61 * 2 > total {
            Some(LeapStatus::Leap61)
        } else {
            None
        }
    }

    #[must_use]
    pub fn local_root_delay(&self, config: &LinkFilterConfig) -> Option<f64> {
        let consensus_window = self.find_external_consensus_window(config)?;

        let mut best_delay = f64::MAX;
        for link in self.links.iter() {
            if let Some(window) = link.offset_window(config, &self.estimation_state)
                && window.overlaps(consensus_window)
                && let Some(state) = &link.external_link_state
                && let Ok(estimate) = link.link_state.delay_and_noise_estimate()
            {
                best_delay = best_delay.min(state.root_delay + estimate.delay);
            }
        }

        Some(best_delay)
    }

    /// Add an external clock to the filter.
    ///
    /// # Errors
    /// Returns an error if the clock cannot be added due to capacity constraints.
    pub fn add_external_clock(mut self) -> Result<(Self, ClockId), AlgoError> {
        let id = ClockId::new();
        self.estimation_state = self.estimation_state.add_external_clock(id)?;
        Ok((self, id))
    }

    /// Remove an external clock from the filter.
    ///
    /// # Errors
    /// Returns an error if the clock is unknown, or not an external clock.
    pub fn remove_external_clock(mut self, id: ClockId) -> Result<Self, AlgoError> {
        // FIXME: check for existence of links with this clock
        self.estimation_state = self.estimation_state.remove_external_clock(id)?;
        Ok(self)
    }

    /// Add an internal clock to the filter.
    ///
    /// # Errors
    /// Returns an error if the clock cannot be added due to capacity constraints.
    pub fn add_clock(
        mut self,
        initial_offset: UncertainValue,
        initial_frequency: UncertainValue,
        initial_wander: f64,
    ) -> Result<(Self, ClockId), AlgoError> {
        let id = ClockId::new();
        self.estimation_state = self.estimation_state.add_clock(
            id,
            initial_offset,
            initial_frequency,
            initial_wander,
        )?;
        Ok((self, id))
    }

    /// Remove an internal clock from the filter.
    ///
    /// # Errors
    /// Returns an error if the clock is not known to the filter or if the
    /// clock is still in use by any links.
    pub fn remove_clock(mut self, id: ClockId) -> Result<Self, AlgoError> {
        if let Some(link) = self.links.iter().find(|l| l.id.contains_clock(id)) {
            return Err(AlgoError::ClockInUse(id, link.id));
        }

        self.estimation_state = self.estimation_state.remove_clock(id)?;
        Ok(self)
    }

    /// Add a link whos delay, and the link noise, is actively measured.
    ///
    /// Note that such links are required to have measurements in both directions to be useful.
    ///
    /// # Errors
    /// Returns an error if the provided clocks are invalid, or an invalid combination for the link.
    pub fn add_tracked_link(
        mut self,
        first_clock: ClockId,
        second_clock: ClockId,
        decay_rate: f64,
    ) -> Result<(Self, LinkId), AlgoError> {
        let first_internal = self.estimation_state.is_internal_clock(first_clock);
        let first_external = self.estimation_state.is_external_clock(first_clock);
        let second_internal = self.estimation_state.is_internal_clock(second_clock);
        let second_external = self.estimation_state.is_external_clock(second_clock);

        if !first_internal && !first_external {
            return Err(AlgoError::UnknownClock(first_clock));
        }

        if !second_internal && !second_external {
            return Err(AlgoError::UnknownClock(second_clock));
        }

        if first_external && second_external {
            return Err(AlgoError::BothClocksExternal(first_clock, second_clock));
        }

        let id =
            LinkId::new(first_clock, second_clock).ok_or(AlgoError::ClocksEqual(first_clock))?;
        let is_internal = first_internal && second_internal;
        self.links.add_link(LinkInfo {
            id,
            active: false,
            link_state: LinkState::Tracked {
                link_noise_estimator: LinkNoiseEstimator::new(id),
                decay_rate,
            },
            external_link_state: if is_internal {
                None
            } else {
                Some(ExternalLinkState {
                    last_offsets: UnorderedRingBuffer::default(),
                    last_offset_uncertainty: 0.0,
                    root_delay: 0.0,
                    leap_status: None,
                    usable: false,
                })
            },
        });

        Ok((self, id))
    }

    /// Add a link where delay and link noise are non-tracked.
    ///
    /// # Errors
    /// Returns an error if the provided clocks are invalid, or an invalid combination for the link.
    pub fn add_untracked_link(
        mut self,
        first_clock: ClockId,
        second_clock: ClockId,
    ) -> Result<(Self, LinkId), AlgoError> {
        let first_internal = self.estimation_state.is_internal_clock(first_clock);
        let first_external = self.estimation_state.is_external_clock(first_clock);
        let second_internal = self.estimation_state.is_internal_clock(second_clock);
        let second_external = self.estimation_state.is_external_clock(second_clock);

        if !first_internal && !first_external {
            return Err(AlgoError::UnknownClock(first_clock));
        }

        if !second_internal && !second_external {
            return Err(AlgoError::UnknownClock(second_clock));
        }

        if first_external && second_external {
            return Err(AlgoError::BothClocksExternal(first_clock, second_clock));
        }

        let id =
            LinkId::new(first_clock, second_clock).ok_or(AlgoError::ClocksEqual(first_clock))?;
        let is_internal = first_internal && second_internal;
        self.links.add_link(LinkInfo {
            id,
            active: is_internal,
            link_state: LinkState::Untracked,
            external_link_state: if is_internal {
                None
            } else {
                Some(ExternalLinkState {
                    last_offsets: UnorderedRingBuffer::default(),
                    last_offset_uncertainty: 0.0,
                    root_delay: 0.0,
                    leap_status: None,
                    usable: false,
                })
            },
        });

        Ok((self, id))
    }

    /// Remove a link from the filter.
    ///
    /// # Errors
    /// Returns an error if the link does not exist.
    pub fn remove_link(mut self, id: LinkId) -> Result<Self, AlgoError> {
        let link = self.links.remove_link(id)?;
        if link.active && matches!(link.link_state, LinkState::Tracked { .. }) {
            self.estimation_state = self.estimation_state.remove_link(id)?;
        }

        Ok(self)
    }

    /// Check whether a given link is currently active. Note that this reflects
    /// only whether the last measurement was used, not whether the link would be
    /// chosen now when a new measurement matching the old ones arrives.
    ///
    /// # Errors
    /// Returns an error if the link does not exist.
    pub fn link_active(&self, id: LinkId) -> Result<bool, AlgoError> {
        let link = self.links.find_by_id(id)?;
        Ok(link.active)
    }

    fn find_external_consensus_window(&self, config: &LinkFilterConfig) -> Option<OffsetWindow> {
        let mut bounds: Storage::BoundStorage = self
            .links
            .iter()
            .filter_map(|info| {
                info.offset_window(config, &self.estimation_state)
                    .map(|window| {
                        [
                            (window.low, BoundType::Start),
                            (window.high, BoundType::End),
                        ]
                    })
            })
            .flatten()
            .collect();

        bounds.sort_unstable_by(|a, b| a.0.total_cmp(&b.0).then_with(|| a.1.cmp(&b.1)));

        // Find the intersection of the confidence intervals of the maximum
        // overlapping set. We need this entire interval to properly integrate
        // periodic sources
        let mut maxlow: usize = 0;
        let mut maxhigh: usize = 0;
        let mut max_offset_low: f64 = 0.0;
        let mut max_offset_high: f64 = 0.0;
        let mut cur: usize = 0;

        for (offset, boundtype) in &*bounds {
            match boundtype {
                BoundType::Start => {
                    cur += 1;
                    if cur > maxlow {
                        maxlow = cur;
                        max_offset_low = *offset;
                    }
                }
                BoundType::End => {
                    if cur > maxhigh {
                        maxhigh = cur;
                        max_offset_high = *offset;
                    }
                    cur -= 1;
                }
            }
        }

        // Check that the lower and upper bound of the intersection agree on how many
        // sources are part of the maximum set. If not, something has seriously gone
        // wrong and we shouldn't steer the clock.
        assert_eq!(maxlow, maxhigh);
        let max = maxlow;

        if max >= config.minimum_agreeing_sources && max * 4 > bounds.len() {
            Some(OffsetWindow {
                low: max_offset_low,
                high: max_offset_high,
            })
        } else {
            None
        }
    }

    /// Get the current offset of a clock.
    ///
    /// # Errors
    /// Fails when the clock is not known to the filter.
    pub fn clock_offset(&self, clock_id: ClockId) -> Result<UncertainValue, AlgoError> {
        self.estimation_state.clock_offset(clock_id)
    }

    /// Get the current frequency offset of a clock.
    ///
    /// # Errors
    /// Fails when the clock is not known to the filter.
    pub fn clock_frequency(&self, clock_id: ClockId) -> Result<UncertainValue, AlgoError> {
        self.estimation_state.clock_frequency(clock_id)
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum BoundType {
    Start,
    End,
}

#[cfg(all(test, feature = "std"))]
#[allow(clippy::too_many_lines, reason = "Test code")]
mod tests {
    use statime_base::{ClockId, Duration, LeapStatus, Timestamp};

    use crate::{
        AlgoError, StdKalmanStorage,
        filter::{LinkFilter, LinkFilterConfig},
    };

    #[test]
    fn untracked_internal_link_is_always_active() {
        let filter = LinkFilter::<StdKalmanStorage<()>>::empty(Timestamp::UNIX_EPOCH);
        let (filter, clock_a) = filter
            .add_clock((0.0, 0.0).into(), (0.0, 0.0).into(), 1e-8)
            .unwrap();
        let (filter, clock_b) = filter
            .add_clock((0.0, 0.0).into(), (0.0, 0.0).into(), 1e-8)
            .unwrap();
        let (filter, link_id) = filter.add_untracked_link(clock_a, clock_b).unwrap();
        assert!(filter.link_active(link_id).unwrap());
    }

    #[test]
    fn tracked_internal_link_becomes_active() {
        let config = LinkFilterConfig {
            select_offset_uncertainty_window: 2.0,
            select_link_uncertainty_window: 2.0,
            select_delay_uncertainty_window: 0.7,
            select_max_window_size: 1.0,
            minimum_agreeing_sources: 3,
        };

        let filter = LinkFilter::<StdKalmanStorage<()>>::empty(Timestamp::UNIX_EPOCH);
        let (filter, clock_a) = filter
            .add_clock((0.0, 0.0).into(), (0.0, 0.0).into(), 1e-8)
            .unwrap();
        let (filter, clock_b) = filter
            .add_clock((0.0, 0.0).into(), (0.0, 0.0).into(), 1e-8)
            .unwrap();
        let (filter, link_id) = filter.add_tracked_link(clock_a, clock_b, 0.01).unwrap();

        assert!(!filter.link_active(link_id).unwrap());

        let filter = filter
            .measurement(&config, link_id.forward(), (0.0, 0.0).into())
            .unwrap()
            .measurement(&config, link_id.reverse(), (0.0, 0.0).into())
            .unwrap()
            .measurement(&config, link_id.forward(), (0.0, 0.0).into())
            .unwrap()
            .measurement(&config, link_id.reverse(), (0.0, 0.0).into())
            .unwrap()
            .measurement(&config, link_id.forward(), (0.0, 0.0).into())
            .unwrap()
            .measurement(&config, link_id.reverse(), (0.0, 0.0).into())
            .unwrap()
            .measurement(&config, link_id.forward(), (0.0, 0.0).into())
            .unwrap()
            .measurement(&config, link_id.reverse(), (0.0, 0.0).into())
            .unwrap();

        assert!(filter.link_active(link_id).unwrap());
    }

    #[test]
    fn external_links_need_consensus() {
        let config = LinkFilterConfig {
            select_offset_uncertainty_window: 2.0,
            select_link_uncertainty_window: 2.0,
            select_delay_uncertainty_window: 0.7,
            select_max_window_size: 1.0,
            minimum_agreeing_sources: 1,
        };

        let filter = LinkFilter::<StdKalmanStorage<()>>::empty(Timestamp::UNIX_EPOCH);
        let (filter, clock_int) = filter
            .add_clock((0.0, 0.0).into(), (0.0, 0.0).into(), 1e-8)
            .unwrap();
        let (filter, clock_ext_1) = filter.add_external_clock().unwrap();
        let (filter, clock_ext_2) = filter.add_external_clock().unwrap();
        let (filter, clock_ext_3) = filter.add_external_clock().unwrap();
        let (filter, link_1) = filter
            .add_tracked_link(clock_int, clock_ext_1, 0.01)
            .unwrap();
        let (filter, link_2) = filter
            .add_tracked_link(clock_int, clock_ext_2, 0.01)
            .unwrap();
        let (filter, link_3) = filter
            .add_tracked_link(clock_int, clock_ext_3, 0.01)
            .unwrap();

        let filter = filter
            // link 1
            .external_data_update(link_1, 0.1, None, true)
            .unwrap()
            .measurement(&config, link_1.forward(), (0.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_1.reverse(), (0.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_1.forward(), (0.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_1.reverse(), (0.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_1.forward(), (0.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_1.reverse(), (0.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_1.forward(), (0.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_1.reverse(), (0.0, 0.001).into())
            .unwrap()
            // link 2
            .external_data_update(link_2, 0.1, None, true)
            .unwrap()
            .measurement(&config, link_2.forward(), (0.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_2.reverse(), (0.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_2.forward(), (0.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_2.reverse(), (0.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_2.forward(), (0.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_2.reverse(), (0.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_2.forward(), (0.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_2.reverse(), (0.0, 0.001).into())
            .unwrap()
            // link 3
            .external_data_update(link_3, 0.1, None, true)
            .unwrap()
            .measurement(&config, link_3.forward(), (0.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_3.reverse(), (0.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_3.forward(), (0.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_3.reverse(), (0.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_3.forward(), (0.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_3.reverse(), (0.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_3.forward(), (0.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_3.reverse(), (0.0, 0.001).into())
            .unwrap();

        assert!(filter.link_active(link_1).unwrap());
        assert!(filter.link_active(link_2).unwrap());
        assert!(filter.link_active(link_3).unwrap());

        let filter = LinkFilter::<StdKalmanStorage<()>>::empty(Timestamp::UNIX_EPOCH);
        let (filter, clock_int) = filter
            .add_clock((0.0, 0.0).into(), (0.0, 0.0).into(), 1e-8)
            .unwrap();
        let (filter, clock_ext_1) = filter.add_external_clock().unwrap();
        let (filter, clock_ext_2) = filter.add_external_clock().unwrap();
        let (filter, clock_ext_3) = filter.add_external_clock().unwrap();
        let (filter, link_1) = filter
            .add_tracked_link(clock_int, clock_ext_1, 0.01)
            .unwrap();
        let (filter, link_2) = filter
            .add_tracked_link(clock_int, clock_ext_2, 0.01)
            .unwrap();
        let (filter, link_3) = filter
            .add_tracked_link(clock_int, clock_ext_3, 0.01)
            .unwrap();

        let filter = filter
            // link 1
            .external_data_update(link_1, 0.1, None, true)
            .unwrap()
            .measurement(&config, link_1.forward(), (0.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_1.reverse(), (0.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_1.forward(), (0.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_1.reverse(), (0.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_1.forward(), (0.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_1.reverse(), (0.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_1.forward(), (0.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_1.reverse(), (0.0, 0.001).into())
            .unwrap()
            // link 2
            .external_data_update(link_2, 0.1, None, true)
            .unwrap()
            .measurement(&config, link_2.forward(), (0.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_2.reverse(), (0.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_2.forward(), (0.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_2.reverse(), (0.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_2.forward(), (0.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_2.reverse(), (0.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_2.forward(), (0.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_2.reverse(), (0.0, 0.001).into())
            .unwrap()
            // link 3
            .external_data_update(link_3, 0.1, None, true)
            .unwrap()
            .measurement(&config, link_3.forward(), (1.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_3.reverse(), (-1.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_3.forward(), (1.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_3.reverse(), (-1.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_3.forward(), (1.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_3.reverse(), (-1.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_3.forward(), (1.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_3.reverse(), (-1.0, 0.001).into())
            .unwrap();

        assert!(filter.link_active(link_1).unwrap());
        assert!(filter.link_active(link_2).unwrap());
        assert!(!filter.link_active(link_3).unwrap());

        let filter = LinkFilter::<StdKalmanStorage<()>>::empty(Timestamp::UNIX_EPOCH);
        let (filter, clock_int) = filter
            .add_clock((0.0, 0.0).into(), (0.0, 0.0).into(), 1e-8)
            .unwrap();
        let (filter, clock_ext_1) = filter.add_external_clock().unwrap();
        let (filter, clock_ext_2) = filter.add_external_clock().unwrap();
        let (filter, clock_ext_3) = filter.add_external_clock().unwrap();
        let (filter, link_1) = filter
            .add_tracked_link(clock_int, clock_ext_1, 0.01)
            .unwrap();
        let (filter, link_2) = filter
            .add_tracked_link(clock_int, clock_ext_2, 0.01)
            .unwrap();
        let (filter, link_3) = filter
            .add_tracked_link(clock_int, clock_ext_3, 0.01)
            .unwrap();

        let filter = filter
            // link 1
            .external_data_update(link_1, 0.1, None, true)
            .unwrap()
            .measurement(&config, link_1.forward(), (0.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_1.reverse(), (0.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_1.forward(), (0.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_1.reverse(), (0.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_1.forward(), (0.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_1.reverse(), (0.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_1.forward(), (0.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_1.reverse(), (0.0, 0.001).into())
            .unwrap()
            // link 2
            .external_data_update(link_2, 0.1, None, true)
            .unwrap()
            .measurement(&config, link_2.forward(), (1.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_2.reverse(), (-1.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_2.forward(), (1.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_2.reverse(), (-1.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_2.forward(), (1.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_2.reverse(), (-1.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_2.forward(), (1.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_2.reverse(), (-1.0, 0.001).into())
            .unwrap()
            // link 3
            .external_data_update(link_3, 0.1, None, true)
            .unwrap()
            .measurement(&config, link_3.forward(), (1.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_3.reverse(), (-1.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_3.forward(), (1.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_3.reverse(), (-1.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_3.forward(), (1.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_3.reverse(), (-1.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_3.forward(), (1.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_3.reverse(), (-1.0, 0.001).into())
            .unwrap();

        // Link 1 is still active since it came online first.
        assert!(filter.link_active(link_1).unwrap());
        // Link 2 is still inactive since, although it is part of the selected set,
        // it hasn't yet contributed.
        assert!(!filter.link_active(link_2).unwrap());
        // Link 3 caused the change so reflects the activity status.
        assert!(filter.link_active(link_3).unwrap());

        let filter = filter
            .measurement(&config, link_1.forward(), (0.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_2.forward(), (1.0, 0.001).into())
            .unwrap();
        //
        assert!(!filter.link_active(link_1).unwrap());
        assert!(filter.link_active(link_2).unwrap());
    }

    #[test]
    fn external_links_inactive_when_unusable() {
        let config = LinkFilterConfig {
            select_offset_uncertainty_window: 2.0,
            select_link_uncertainty_window: 2.0,
            select_delay_uncertainty_window: 0.7,
            select_max_window_size: 1.0,
            minimum_agreeing_sources: 1,
        };

        let filter = LinkFilter::<StdKalmanStorage<()>>::empty(Timestamp::UNIX_EPOCH);
        let (filter, clock_int) = filter
            .add_clock((0.0, 0.0).into(), (0.0, 0.0).into(), 1e-8)
            .unwrap();
        let (filter, clock_ext_1) = filter.add_external_clock().unwrap();
        let (filter, link_1) = filter.add_untracked_link(clock_int, clock_ext_1).unwrap();
        let filter = filter
            .external_data_update(link_1, 0.1, None, true)
            .unwrap()
            .measurement(&config, link_1.forward(), (0.0, 0.0).into())
            .unwrap();

        assert!(filter.link_active(link_1).unwrap());

        let filter = LinkFilter::<StdKalmanStorage<()>>::empty(Timestamp::UNIX_EPOCH);
        let (filter, clock_int) = filter
            .add_clock((0.0, 0.0).into(), (0.0, 0.0).into(), 1e-8)
            .unwrap();
        let (filter, clock_ext_1) = filter.add_external_clock().unwrap();
        let (filter, link_1) = filter.add_untracked_link(clock_int, clock_ext_1).unwrap();
        let filter = filter
            .external_data_update(link_1, 0.1, None, false)
            .unwrap()
            .measurement(&config, link_1.forward(), (0.0, 0.0).into())
            .unwrap();

        assert!(!filter.link_active(link_1).unwrap());
    }

    #[test]
    fn internal_link_inactive_on_unusable_measurements() {
        let config = LinkFilterConfig {
            select_offset_uncertainty_window: 2.0,
            select_link_uncertainty_window: 2.0,
            select_delay_uncertainty_window: 0.7,
            select_max_window_size: 1.0,
            minimum_agreeing_sources: 3,
        };

        let filter = LinkFilter::<StdKalmanStorage<()>>::empty(Timestamp::UNIX_EPOCH);
        let (filter, clock_a) = filter
            .add_clock((0.0, 0.0).into(), (0.0, 0.0).into(), 1e-8)
            .unwrap();
        let (filter, clock_b) = filter
            .add_clock((0.0, 0.0).into(), (0.0, 0.0).into(), 1e-8)
            .unwrap();
        let (filter, link_id) = filter.add_tracked_link(clock_a, clock_b, 0.01).unwrap();

        assert!(!filter.link_active(link_id).unwrap());

        let filter = filter
            .measurement(&config, link_id.forward(), (0.0, 0.0).into())
            .unwrap()
            .progress_time(Timestamp::UNIX_EPOCH + Duration::from_seconds_nanos(0, 600_000_000))
            .unwrap()
            .measurement(&config, link_id.reverse(), (0.0, 0.0).into())
            .unwrap()
            .progress_time(Timestamp::UNIX_EPOCH + Duration::from_seconds_nanos(10, 0))
            .unwrap()
            .measurement(&config, link_id.forward(), (0.0, 0.0).into())
            .unwrap()
            .progress_time(Timestamp::UNIX_EPOCH + Duration::from_seconds_nanos(10, 600_000_000))
            .unwrap()
            .measurement(&config, link_id.reverse(), (0.0, 0.0).into())
            .unwrap()
            .progress_time(Timestamp::UNIX_EPOCH + Duration::from_seconds_nanos(20, 0))
            .unwrap()
            .measurement(&config, link_id.forward(), (0.0, 0.0).into())
            .unwrap()
            .progress_time(Timestamp::UNIX_EPOCH + Duration::from_seconds_nanos(20, 600_000_000))
            .unwrap()
            .measurement(&config, link_id.reverse(), (0.0, 0.0).into())
            .unwrap()
            .progress_time(Timestamp::UNIX_EPOCH + Duration::from_seconds_nanos(30, 0))
            .unwrap()
            .measurement(&config, link_id.forward(), (0.0, 0.0).into())
            .unwrap()
            .progress_time(Timestamp::UNIX_EPOCH + Duration::from_seconds_nanos(30, 600_000_000))
            .unwrap()
            .measurement(&config, link_id.reverse(), (0.0, 0.0).into())
            .unwrap();

        assert!(!filter.link_active(link_id).unwrap());
    }

    #[test]
    fn external_links_activity_and_steering_works() {
        let config = LinkFilterConfig {
            select_offset_uncertainty_window: 2.0,
            select_link_uncertainty_window: 2.0,
            select_delay_uncertainty_window: 0.7,
            select_max_window_size: 1.0,
            minimum_agreeing_sources: 1,
        };

        let filter = LinkFilter::<StdKalmanStorage<()>>::empty(Timestamp::UNIX_EPOCH);
        let (filter, clock_int_1) = filter
            .add_clock((0.0, 0.0).into(), (0.0, 0.0).into(), 1e-8)
            .unwrap();
        let (filter, clock_int_2) = filter
            .add_clock((10.0, 0.0).into(), (0.0, 0.0).into(), 1e-8)
            .unwrap();
        let (filter, clock_ext_1) = filter.add_external_clock().unwrap();
        let (filter, clock_ext_2) = filter.add_external_clock().unwrap();
        let (filter, clock_ext_3) = filter.add_external_clock().unwrap();
        let (filter, link_1) = filter.add_untracked_link(clock_int_1, clock_ext_1).unwrap();
        let (filter, link_2) = filter.add_untracked_link(clock_int_1, clock_ext_2).unwrap();
        let (filter, link_3) = filter.add_untracked_link(clock_int_2, clock_ext_3).unwrap();

        let filter = filter
            .external_data_update(link_1, 0.1, None, true)
            .unwrap()
            .measurement(&config, link_1.forward(), (0.0, 0.001).into())
            .unwrap()
            .external_data_update(link_2, 0.1, None, true)
            .unwrap()
            .measurement(&config, link_2.forward(), (0.0, 0.001).into())
            .unwrap()
            .external_data_update(link_3, 0.1, None, true)
            .unwrap()
            .measurement(&config, link_3.forward(), (-10.0, 0.001).into())
            .unwrap();

        assert!(filter.link_active(link_1).unwrap());
        assert!(filter.link_active(link_2).unwrap());
        assert!(filter.link_active(link_3).unwrap());

        let filter = filter
            .absorb_offset_change(clock_int_2, -10.0)
            .unwrap()
            .measurement(&config, link_3.forward(), (0.0, 0.001).into())
            .unwrap();

        assert!(filter.link_active(link_3).unwrap());

        let filter = LinkFilter::<StdKalmanStorage<()>>::empty(
            Timestamp::UNIX_EPOCH + Duration::from_seconds_nanos(10, 0),
        );
        let (filter, clock_int_1) = filter
            .add_clock((0.0, 0.0).into(), (0.0, 0.0).into(), 1e-8)
            .unwrap();
        let (filter, clock_int_2) = filter
            .add_clock((-10.0, 0.0).into(), (0.0, 0.0).into(), 1e-8)
            .unwrap();
        let (filter, clock_ext_1) = filter.add_external_clock().unwrap();
        let (filter, clock_ext_2) = filter.add_external_clock().unwrap();
        let (filter, clock_ext_3) = filter.add_external_clock().unwrap();
        let (filter, link_1) = filter.add_untracked_link(clock_int_1, clock_ext_1).unwrap();
        let (filter, link_2) = filter.add_untracked_link(clock_int_1, clock_ext_2).unwrap();
        let (filter, link_3) = filter.add_untracked_link(clock_ext_3, clock_int_2).unwrap();

        let filter = filter
            .external_data_update(link_1, 0.1, None, true)
            .unwrap()
            .measurement(&config, link_1.forward(), (0.0, 0.001).into())
            .unwrap()
            .external_data_update(link_2, 0.1, None, true)
            .unwrap()
            .measurement(&config, link_2.forward(), (0.0, 0.001).into())
            .unwrap()
            .external_data_update(link_3, 0.1, None, true)
            .unwrap()
            .measurement(&config, link_3.forward(), (-10.0, 0.001).into())
            .unwrap();

        assert!(filter.link_active(link_1).unwrap());
        assert!(filter.link_active(link_2).unwrap());
        assert!(filter.link_active(link_3).unwrap());

        let filter = filter
            .absorb_system_clock_offset_change(clock_int_2, Duration::from_seconds_nanos(10, 0))
            .unwrap()
            .measurement(&config, link_3.forward(), (0.0, 0.001).into())
            .unwrap();

        assert!(filter.link_active(link_3).unwrap());
    }

    #[test]
    fn too_uncertain_external_links_inactive() {
        let config = LinkFilterConfig {
            select_offset_uncertainty_window: 2.0,
            select_link_uncertainty_window: 2.0,
            select_delay_uncertainty_window: 0.7,
            select_max_window_size: 1.0,
            minimum_agreeing_sources: 1,
        };

        let filter = LinkFilter::<StdKalmanStorage<()>>::empty(Timestamp::UNIX_EPOCH);
        let (filter, clock_int) = filter
            .add_clock((0.0, 0.0).into(), (0.0, 0.0).into(), 1e-8)
            .unwrap();
        let (filter, clock_ext_1) = filter.add_external_clock().unwrap();
        let (filter, link_1) = filter.add_untracked_link(clock_int, clock_ext_1).unwrap();
        let filter = filter
            .external_data_update(link_1, 10.0, None, true)
            .unwrap()
            .measurement(&config, link_1.forward(), (0.0, 0.0).into())
            .unwrap();

        assert!(!filter.link_active(link_1).unwrap());

        let filter = LinkFilter::<StdKalmanStorage<()>>::empty(Timestamp::UNIX_EPOCH);
        let (filter, clock_int) = filter
            .add_clock((0.0, 0.0).into(), (0.0, 0.0).into(), 1e-8)
            .unwrap();
        let (filter, clock_ext_1) = filter.add_external_clock().unwrap();
        let (filter, link_1) = filter.add_untracked_link(clock_int, clock_ext_1).unwrap();
        let filter = filter
            .external_data_update(link_1, 0.0, None, true)
            .unwrap()
            .measurement(&config, link_1.forward(), (0.0, 1.0).into())
            .unwrap();

        assert!(!filter.link_active(link_1).unwrap());

        let filter = LinkFilter::<StdKalmanStorage<()>>::empty(Timestamp::UNIX_EPOCH);
        let (filter, clock_int) = filter
            .add_clock((0.0, 0.0).into(), (0.0, 0.0).into(), 1e-8)
            .unwrap();
        let (filter, clock_ext_1) = filter.add_external_clock().unwrap();
        let (filter, link_1) = filter
            .add_tracked_link(clock_int, clock_ext_1, 0.0)
            .unwrap();
        let filter = filter
            .external_data_update(link_1, 10.0, None, true)
            .unwrap()
            .measurement(&config, link_1.forward(), (0.0, 0.0).into())
            .unwrap()
            .measurement(&config, link_1.reverse(), (0.0, 0.0).into())
            .unwrap()
            .measurement(&config, link_1.forward(), (1.0, 0.0).into())
            .unwrap()
            .measurement(&config, link_1.reverse(), (1.0, 0.0).into())
            .unwrap()
            .measurement(&config, link_1.forward(), (1.0, 0.0).into())
            .unwrap()
            .measurement(&config, link_1.reverse(), (1.0, 0.0).into())
            .unwrap()
            .measurement(&config, link_1.forward(), (-1.0, 0.0).into())
            .unwrap()
            .measurement(&config, link_1.reverse(), (-1.0, 0.0).into())
            .unwrap()
            .measurement(&config, link_1.forward(), (-1.0, 0.0).into())
            .unwrap()
            .measurement(&config, link_1.reverse(), (-1.0, 0.0).into())
            .unwrap();

        assert!(!filter.link_active(link_1).unwrap());
    }

    #[test]
    fn leap_vote() {
        let config = LinkFilterConfig {
            select_offset_uncertainty_window: 2.0,
            select_link_uncertainty_window: 2.0,
            select_delay_uncertainty_window: 0.7,
            select_max_window_size: 1.0,
            minimum_agreeing_sources: 1,
        };

        let filter = LinkFilter::<StdKalmanStorage<()>>::empty(Timestamp::UNIX_EPOCH);
        let (filter, clock_int) = filter
            .add_clock((0.0, 0.0).into(), (0.0, 0.0).into(), 1e-8)
            .unwrap();
        let (filter, clock_ext_1) = filter.add_external_clock().unwrap();
        let (filter, clock_ext_2) = filter.add_external_clock().unwrap();
        let (filter, clock_ext_3) = filter.add_external_clock().unwrap();
        let (filter, link_1) = filter
            .add_tracked_link(clock_int, clock_ext_1, 0.01)
            .unwrap();
        let (filter, link_2) = filter
            .add_tracked_link(clock_int, clock_ext_2, 0.01)
            .unwrap();
        let (filter, link_3) = filter
            .add_tracked_link(clock_int, clock_ext_3, 0.01)
            .unwrap();

        let base_filter = filter
            // link 1
            .external_data_update(link_1, 0.1, None, true)
            .unwrap()
            .measurement(&config, link_1.forward(), (0.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_1.reverse(), (0.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_1.forward(), (0.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_1.reverse(), (0.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_1.forward(), (0.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_1.reverse(), (0.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_1.forward(), (0.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_1.reverse(), (0.0, 0.001).into())
            .unwrap()
            // link 2
            .external_data_update(link_2, 0.1, None, true)
            .unwrap()
            .measurement(&config, link_2.forward(), (0.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_2.reverse(), (0.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_2.forward(), (0.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_2.reverse(), (0.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_2.forward(), (0.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_2.reverse(), (0.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_2.forward(), (0.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_2.reverse(), (0.0, 0.001).into())
            .unwrap()
            // link 3
            .external_data_update(link_3, 0.1, None, true)
            .unwrap()
            .measurement(&config, link_3.forward(), (0.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_3.reverse(), (0.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_3.forward(), (0.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_3.reverse(), (0.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_3.forward(), (0.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_3.reverse(), (0.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_3.forward(), (0.0, 0.001).into())
            .unwrap()
            .measurement(&config, link_3.reverse(), (0.0, 0.001).into())
            .unwrap();

        let filter = base_filter
            .clone()
            .external_data_update(link_1, 0.1, Some(LeapStatus::None), true)
            .unwrap()
            .external_data_update(link_2, 0.1, Some(LeapStatus::None), true)
            .unwrap()
            .external_data_update(link_3, 0.1, Some(LeapStatus::None), true)
            .unwrap();
        assert_eq!(filter.leap_vote(&config), Some(LeapStatus::None));

        let filter = base_filter
            .clone()
            .external_data_update(link_1, 0.1, Some(LeapStatus::Leap59), true)
            .unwrap()
            .external_data_update(link_2, 0.1, Some(LeapStatus::Leap59), true)
            .unwrap()
            .external_data_update(link_3, 0.1, Some(LeapStatus::Leap59), true)
            .unwrap();
        assert_eq!(filter.leap_vote(&config), Some(LeapStatus::Leap59));

        let filter = base_filter
            .clone()
            .external_data_update(link_1, 0.1, Some(LeapStatus::Leap61), true)
            .unwrap()
            .external_data_update(link_2, 0.1, Some(LeapStatus::Leap61), true)
            .unwrap()
            .external_data_update(link_3, 0.1, Some(LeapStatus::Leap61), true)
            .unwrap();
        assert_eq!(filter.leap_vote(&config), Some(LeapStatus::Leap61));

        let filter = base_filter
            .clone()
            .external_data_update(link_1, 0.1, Some(LeapStatus::None), true)
            .unwrap()
            .external_data_update(link_2, 0.1, Some(LeapStatus::Leap59), true)
            .unwrap()
            .external_data_update(link_3, 0.1, Some(LeapStatus::Leap59), true)
            .unwrap();
        assert_eq!(filter.leap_vote(&config), Some(LeapStatus::Leap59));

        let filter = base_filter
            .clone()
            .external_data_update(link_1, 0.1, Some(LeapStatus::None), true)
            .unwrap()
            .external_data_update(link_2, 0.1, None, true)
            .unwrap()
            .external_data_update(link_3, 0.1, None, true)
            .unwrap();
        assert_eq!(filter.leap_vote(&config), Some(LeapStatus::None));

        let filter = base_filter
            .clone()
            .external_data_update(link_1, 0.1, Some(LeapStatus::None), true)
            .unwrap()
            .external_data_update(link_2, 0.1, Some(LeapStatus::Leap59), true)
            .unwrap()
            .external_data_update(link_3, 0.1, Some(LeapStatus::Leap61), true)
            .unwrap();
        assert_eq!(filter.leap_vote(&config), None);
    }

    #[test]
    fn local_root_delay() {
        let config = LinkFilterConfig {
            select_offset_uncertainty_window: 2.0,
            select_link_uncertainty_window: 2.0,
            select_delay_uncertainty_window: 0.7,
            select_max_window_size: 1.0,
            minimum_agreeing_sources: 1,
        };

        let filter = LinkFilter::<StdKalmanStorage<()>>::empty(Timestamp::UNIX_EPOCH);
        let (filter, clock_int_1) = filter
            .add_clock((0.0, 0.0).into(), (0.0, 0.0).into(), 1e-8)
            .unwrap();
        let (filter, clock_int_2) = filter
            .add_clock((0.0, 0.0).into(), (0.0, 0.0).into(), 1e-8)
            .unwrap();
        let (filter, clock_ext_1) = filter.add_external_clock().unwrap();
        let (filter, clock_ext_2) = filter.add_external_clock().unwrap();
        let (filter, clock_ext_3) = filter.add_external_clock().unwrap();
        let (filter, link_1) = filter.add_untracked_link(clock_int_1, clock_ext_1).unwrap();
        let (filter, link_2) = filter.add_untracked_link(clock_int_1, clock_ext_2).unwrap();
        let (filter, link_3) = filter.add_untracked_link(clock_int_2, clock_ext_3).unwrap();

        let filter = filter
            .external_data_update(link_1, 0.3, None, true)
            .unwrap()
            .measurement(&config, link_1.forward(), (0.0, 0.001).into())
            .unwrap()
            .external_data_update(link_2, 0.2, None, true)
            .unwrap()
            .measurement(&config, link_2.forward(), (0.0, 0.001).into())
            .unwrap()
            .external_data_update(link_3, 0.1, None, true)
            .unwrap()
            .measurement(&config, link_3.forward(), (10.0, 0.001).into())
            .unwrap();

        assert_eq!(filter.local_root_delay(&config), Some(0.2));

        let filter = filter.remove_link(link_2).unwrap();

        assert_eq!(filter.local_root_delay(&config), None);
    }

    #[test]
    fn test_new_link_validation() {
        let filter = LinkFilter::<StdKalmanStorage<()>>::empty(Timestamp::UNIX_EPOCH);
        let (filter, clock_1) = filter
            .add_clock((0.0, 0.0).into(), (0.0, 0.0).into(), 1e-8)
            .unwrap();
        let (filter, clock_2) = filter.add_external_clock().unwrap();
        let (filter, clock_3) = filter.add_external_clock().unwrap();
        let clock_4 = ClockId::new();

        assert_eq!(
            filter
                .clone()
                .add_untracked_link(clock_4, clock_1)
                .unwrap_err(),
            AlgoError::UnknownClock(clock_4)
        );
        assert_eq!(
            filter
                .clone()
                .add_untracked_link(clock_2, clock_4)
                .unwrap_err(),
            AlgoError::UnknownClock(clock_4)
        );
        assert_eq!(
            filter
                .clone()
                .add_untracked_link(clock_2, clock_3)
                .unwrap_err(),
            AlgoError::BothClocksExternal(clock_2, clock_3)
        );

        assert_eq!(
            filter
                .clone()
                .add_tracked_link(clock_4, clock_1, 0.01)
                .unwrap_err(),
            AlgoError::UnknownClock(clock_4)
        );
        assert_eq!(
            filter
                .clone()
                .add_tracked_link(clock_2, clock_4, 0.01)
                .unwrap_err(),
            AlgoError::UnknownClock(clock_4)
        );
        assert_eq!(
            filter
                .clone()
                .add_tracked_link(clock_2, clock_3, 0.01)
                .unwrap_err(),
            AlgoError::BothClocksExternal(clock_2, clock_3)
        );
    }
}
