use statime_base::{ClockId, DirectedLinkId, Direction, Duration, LinkId, TAI, Timestamp};

use crate::{
    AlgoError,
    estimator::{EstimatorState, UncertainValue},
    link_noise::{LinkDelayNoiseEstimate, LinkNoiseEstimator},
    ringbuffer::UnorderedRingBuffer,
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

    /// Get the current noise estimate for the link.
    ///
    /// # Errors
    /// Returns an error if the link is tracked but the noise estimate is not yet available.
    fn noise_estimate(&self) -> Result<f64, AlgoError> {
        match self {
            LinkState::Tracked {
                link_noise_estimator,
                ..
            } => Ok(link_noise_estimator.noise_estimate()?),
            LinkState::Untracked => Ok(0.0),
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
struct LinkInfo {
    id: LinkId,
    active: bool,
    link_state: LinkState,
    external_link_state: Option<ExternalLinkState>,
}

impl LinkInfo {
    /// Get an offset window for the link.
    ///
    /// Returns None if the link is not with an external clock.
    fn offset_window(&self, config: &LinkFilterConfig) -> Option<OffsetWindow> {
        let external_link_state = self.external_link_state.as_ref()?;

        if external_link_state.last_offsets.as_ref().is_empty() {
            return None;
        }

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

        let noise_estimate = self.link_state.noise_estimate().ok()?;
        let half_window_size = noise_estimate * config.select_link_uncertainty_window
            + external_link_state.last_offset_uncertainty * config.select_offset_uncertainty_window;

        Some(OffsetWindow {
            low: avg_offset - half_window_size,
            high: avg_offset + half_window_size,
        })
    }
}

/// A list of links, with some utility functions for finding and iterating over
/// them.
#[derive(Debug, Clone)]
struct LinkInfoList(std::vec::Vec<LinkInfo>);

impl LinkInfoList {
    /// Create a new, empty `LinkInfoList`.
    fn new() -> LinkInfoList {
        LinkInfoList(std::vec::Vec::new())
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

impl<'a> IntoIterator for &'a LinkInfoList {
    type Item = &'a LinkInfo;
    type IntoIter = core::slice::Iter<'a, LinkInfo>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<'a> IntoIterator for &'a mut LinkInfoList {
    type Item = &'a mut LinkInfo;
    type IntoIter = core::slice::IterMut<'a, LinkInfo>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter_mut()
    }
}

/// A state estimation filter with full support for handling selection an dprocessing of links.
#[derive(Debug, Clone)]
pub struct LinkFilter {
    links: LinkInfoList,
    estimation_state: EstimatorState,
}

#[derive(Debug, Clone)]
pub struct LinkFilterConfig {
    /// Size of the window of uncertainty to assume around source offset for
    /// judging whether it is a truechimer, based on the observed noise in the
    /// offset.
    pub select_offset_uncertainty_window: f64,
    /// Size of the window of uncertainty to assume around source offset for
    /// judging whether it is a truechimer, based on the observerd link delay
    /// noise.
    pub select_link_uncertainty_window: f64,
    /// Maximum size of the window of uncertainty before we judge a source to
    /// be unsuitable for synchronization.
    pub select_max_window_size: f64,
    /// Minimum number of sources that need to agree on the current time before
    /// we enable synchronization.
    pub minimum_agreeing_sources: usize,
}

impl LinkFilter {
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
    ) -> Result<LinkFilter, AlgoError> {
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
    ) -> Result<LinkFilter, AlgoError> {
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

            let our_window = link.offset_window(config);

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

    fn find_external_consensus_window(&self, config: &LinkFilterConfig) -> Option<OffsetWindow> {
        #[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
        enum BoundType {
            Start,
            End,
        }
        let mut bounds: std::vec::Vec<_> = self
            .links
            .iter()
            .filter_map(|info| {
                info.offset_window(config).map(|window| {
                    [
                        (window.low, BoundType::Start),
                        (window.high, BoundType::End),
                    ]
                })
            })
            .flatten()
            .collect();

        bounds.sort_by(|a, b| a.0.total_cmp(&b.0).then_with(|| a.1.cmp(&b.1)));

        // Find the intersection of the confidence intervals of the maximum
        // overlapping set. We need this entire interval to properly integrate
        // periodic sources
        let mut maxlow: usize = 0;
        let mut maxhigh: usize = 0;
        let mut max_offset_low: f64 = 0.0;
        let mut max_offset_high: f64 = 0.0;
        let mut cur: usize = 0;

        for (offset, boundtype) in &bounds {
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

        if max > config.minimum_agreeing_sources && max * 4 > bounds.len() {
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
