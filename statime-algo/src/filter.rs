use crate::{
    ClockId, EstimatorError, EstimatorState, LinkId, LinkNoiseError, LinkNoiseEstimator,
    estimator::UncertainValue, ringbuffer::UnorderedRingBuffer,
};

type Timestamp = f64;

/// An error that occured in the link filter.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum LinkFilterError {
    /// One of the provided clocks was not known to the filter.
    UnknownClock,
    /// The provided link was not known to the filter.
    UnknownLink,
    /// Both clocks on a link are external.
    BothClocksExternal,
    /// Provided clocks for a link are identical.
    ClocksEqual,
    /// Provided clocks are not valid for the link
    InvalidClocks,
    /// An error occured in the underlying estimator.
    EstimatorError(EstimatorError),
    /// An error occured in a link noise estimator.
    LinkNoiseError(LinkNoiseError),
}

impl From<EstimatorError> for LinkFilterError {
    fn from(value: EstimatorError) -> Self {
        LinkFilterError::EstimatorError(value)
    }
}

impl From<LinkNoiseError> for LinkFilterError {
    fn from(value: LinkNoiseError) -> Self {
        LinkFilterError::LinkNoiseError(value)
    }
}

enum LinkState {
    Tracked {
        link_noise_estimator: LinkNoiseEstimator,
        decay_rate: f64,
    },
    Untracked(ClockId, ClockId),
}

struct ExternalLinkState {
    last_offsets: UnorderedRingBuffer,
    last_offset_uncertainty: f64,
}

struct LinkInfo {
    id: LinkId,
    active: bool,
    link_state: LinkState,
    external_link_state: Option<ExternalLinkState>,
}

struct OffsetWindow {
    low: f64,
    high: f64,
}

impl LinkInfo {
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

        let half_window_size = match &self.link_state {
            LinkState::Tracked {
                link_noise_estimator,
                ..
            } => {
                link_noise_estimator.noise_estimate().ok()? * config.select_link_uncertainty_window
            }
            LinkState::Untracked(_, _) => 0.0,
        } + external_link_state.last_offset_uncertainty
            * config.select_offset_uncertainty_window;

        Some(OffsetWindow {
            low: avg_offset - half_window_size,
            high: avg_offset + half_window_size,
        })
    }
}

/// A state estimation filter with full support for handling selection an dprocessing of links.
pub struct LinkFilter {
    links: std::vec::Vec<LinkInfo>,
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
    pub fn empty(time: Timestamp) -> Self {
        LinkFilter {
            links: std::vec::Vec::new(),
            estimation_state: EstimatorState::empty(time),
        }
    }

    /// Progress the time of the filter.
    ///
    /// # Errors
    /// Returns an error if the new time is before the current time of the filter.
    pub fn progress_time(mut self, new_time: Timestamp) -> Result<Self, LinkFilterError> {
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
    ) -> Result<Self, LinkFilterError> {
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
    ) -> Result<LinkFilter, EstimatorError> {
        self.estimation_state = self
            .estimation_state
            .absorb_offset_change(steered_clock, offset_change)?;
        for link in &mut self.links {
            match &mut link.link_state {
                LinkState::Tracked {
                    link_noise_estimator,
                    ..
                } => {
                    *link_noise_estimator = link_noise_estimator
                        .clone()
                        .absorb_offset_change(steered_clock);
                }
                LinkState::Untracked(_, _) => {}
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
        offset_change: f64,
    ) -> Result<LinkFilter, EstimatorError> {
        self.estimation_state = self
            .estimation_state
            .absorb_offset_change(steered_clock, offset_change)?;
        for link in &mut self.links {
            match &mut link.link_state {
                LinkState::Tracked {
                    link_noise_estimator,
                    ..
                } => {
                    *link_noise_estimator = link_noise_estimator
                        .clone()
                        .absorb_system_clock_offset_change(steered_clock, offset_change);
                }
                LinkState::Untracked(_, _) => {}
            }
        }

        Ok(self)
    }

    /// Process a measurement from one of the links.
    ///
    /// # Errors
    /// Returns an error if the provided clocks are not valid for the provided link, or if the provided link is uknown.
    pub fn measurement(
        mut self,
        config: &LinkFilterConfig,
        from: ClockId,
        to: ClockId,
        offset: UncertainValue,
        link_id: LinkId,
    ) -> Result<Self, LinkFilterError> {
        let link = self
            .links
            .iter_mut()
            .find(|info| info.id == link_id)
            .ok_or(LinkFilterError::UnknownLink)?;

        let (delay, delay_noise, decay_rate, delay_link) = match &mut link.link_state {
            LinkState::Tracked {
                link_noise_estimator,
                decay_rate,
            } => {
                *link_noise_estimator = link_noise_estimator.clone().measurement(
                    from,
                    to,
                    offset.value,
                    self.estimation_state.current_time(),
                )?;
                match (
                    link_noise_estimator.delay_estimate().ok(),
                    link_noise_estimator.noise_estimate().ok(),
                ) {
                    (Some(delay), Some(noise)) => (delay, noise, *decay_rate, Some(link_id)),
                    // Delay and noise not known yet, so link not yet usable, not even for basic offset estimation.
                    _ => return Ok(self),
                }
            }
            LinkState::Untracked(a, b) => {
                if !((*a == from && *b == to) || (*a == to && *b == from)) {
                    return Err(LinkFilterError::InvalidClocks);
                }
                (0.0, 0.0, 0.0, None)
            }
        };

        if let Some(external_link_state) = &mut link.external_link_state {
            // Ensure offset is calculated relative to the external clock, flipping signs
            // if the measurement direction was different.
            let offset_to_external = if self.estimation_state.is_external_clock(from) {
                offset.value - delay
            } else {
                -(offset.value - delay)
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

            let link = self
                .links
                .iter_mut()
                .find(|info| info.id == link_id)
                .ok_or(LinkFilterError::UnknownLink)?;

            // We are active if and only if our window overlaps with the consensus window.
            if let Some(our_window) = our_window
                && our_window.low <= consensus_window.high
                && our_window.high >= consensus_window.low
            {
                if !link.active {
                    link.active = true;
                    if delay_link.is_some() {
                        self.estimation_state = self.estimation_state.add_link(
                            link_id,
                            UncertainValue {
                                value: delay,
                                uncertainty: delay_noise,
                            },
                            decay_rate,
                        )?;
                    }
                }
            } else {
                if link.active {
                    link.active = false;
                    if delay_link.is_some() {
                        self.estimation_state = self.estimation_state.remove_link(link_id)?;
                    }
                }
                return Ok(self);
            }
        }

        self.estimation_state = self.estimation_state.measurement(
            from,
            to,
            UncertainValue {
                value: offset.value,
                // Addition formula for uncertainty...
                uncertainty: (offset.uncertainty.powi(2) + delay_noise.powi(2)).sqrt(),
            },
            delay_link,
        )?;

        Ok(self)
    }

    /// Add an external clock to the filter.
    ///
    /// # Errors
    /// Returns an error if the clock is already known to the filter.
    pub fn add_external_clock(mut self) -> Result<(Self, ClockId), LinkFilterError> {
        let id = ClockId::new();
        self.estimation_state = self.estimation_state.add_external_clock(id)?;
        Ok((self, id))
    }

    /// Remove an external clock from the filter.
    ///
    /// # Errors
    /// Returns an error if the clock is unknown, or not an external clock.
    pub fn remove_external_clock(mut self, id: ClockId) -> Result<Self, LinkFilterError> {
        // FIXME: check for existence of links with this clock
        self.estimation_state = self.estimation_state.remove_external_clock(id)?;
        Ok(self)
    }

    /// Add an internal clock to the filter.
    ///
    /// # Errors
    /// Returns an error if the clock is already a part of the filter.
    pub fn add_clock(
        mut self,
        initial_offset: UncertainValue,
        initial_frequency: UncertainValue,
        initial_wander: f64,
    ) -> Result<(Self, ClockId), LinkFilterError> {
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
    /// Returns an error if the clock is not known to the filter.
    pub fn remove_clock(mut self, id: ClockId) -> Result<Self, LinkFilterError> {
        // FIXME: check for existence of links with this clock
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
    ) -> Result<(Self, LinkId), LinkFilterError> {
        if first_clock == second_clock {
            return Err(LinkFilterError::ClocksEqual);
        }

        let first_internal = self.estimation_state.is_internal_clock(first_clock);
        let first_external = self.estimation_state.is_external_clock(first_clock);
        let second_internal = self.estimation_state.is_internal_clock(second_clock);
        let second_external = self.estimation_state.is_external_clock(second_clock);

        if !(first_internal || first_external) || !(second_internal || second_external) {
            return Err(LinkFilterError::UnknownClock);
        }

        if first_external && second_external {
            return Err(LinkFilterError::BothClocksExternal);
        }

        let id = LinkId::new();
        let is_internal = first_internal && second_internal;
        self.links.push(LinkInfo {
            id,
            active: false,
            link_state: LinkState::Tracked {
                link_noise_estimator: LinkNoiseEstimator::new(first_clock, second_clock)?,
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
    ) -> Result<(Self, LinkId), LinkFilterError> {
        if first_clock == second_clock {
            return Err(LinkFilterError::ClocksEqual);
        }

        let first_internal = self.estimation_state.is_internal_clock(first_clock);
        let first_external = self.estimation_state.is_external_clock(first_clock);
        let second_internal = self.estimation_state.is_internal_clock(second_clock);
        let second_external = self.estimation_state.is_external_clock(second_clock);

        if !(first_internal || first_external) || !(second_internal || second_external) {
            return Err(LinkFilterError::UnknownClock);
        }

        if first_external && second_external {
            return Err(LinkFilterError::BothClocksExternal);
        }

        let id = LinkId::new();
        let is_internal = first_internal && second_internal;
        self.links.push(LinkInfo {
            id,
            active: is_internal,
            link_state: LinkState::Untracked(first_clock, second_clock),
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
    pub fn remove_link(mut self, id: LinkId) -> Result<Self, LinkFilterError> {
        let Some(info_index) = self.links.iter().position(|info| info.id == id) else {
            return Err(LinkFilterError::UnknownLink);
        };

        let link = self.links.remove(info_index);
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
}
