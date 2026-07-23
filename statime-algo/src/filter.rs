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
    Tracked(LinkNoiseEstimator),
    Untracked(ClockId, ClockId),
}

struct LinkInfo {
    id: LinkId,
    active: bool,
    internal: bool,
    link_state: LinkState,
    last_offsets: UnorderedRingBuffer,
}

/// A state estimation filter with full support for handling selection an dprocessing of links.
pub struct LinkFilter {
    links: std::vec::Vec<LinkInfo>,
    estimation_state: EstimatorState,
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

    /// Process a measurement from one of the links.
    ///
    /// # Errors
    /// Returns an error if the provided clocks are not valid for the provided link, or if the provided link is uknown.
    pub fn measurement(
        self,
        from: ClockId,
        to: ClockId,
        offset: UncertainValue,
        link: LinkId,
    ) -> Result<Self, LinkFilterError> {
        todo!()
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
        clock_a: ClockId,
        clock_b: ClockId,
    ) -> Result<(Self, LinkId), LinkFilterError> {
        if clock_a == clock_b {
            return Err(LinkFilterError::ClocksEqual);
        }

        let clock_a_internal = self.estimation_state.is_internal_clock(clock_a);
        let clock_a_external = self.estimation_state.is_external_clock(clock_a);
        #[expect(clippy::similar_names, reason = "There really is no better names for these.")]
        let clock_b_internal = self.estimation_state.is_internal_clock(clock_b);
        #[expect(clippy::similar_names, reason = "There really is no better names for these.")]
        let clock_b_external = self.estimation_state.is_external_clock(clock_b);

        if !(clock_a_internal || clock_a_external) || !(clock_b_internal || clock_b_external) {
            return Err(LinkFilterError::UnknownClock);
        }

        if clock_a_external && clock_b_external {
            return Err(LinkFilterError::BothClocksExternal);
        }

        let id = LinkId::new();
        let is_internal = clock_a_internal && clock_b_internal;
        self.links.push(LinkInfo {
            id,
            active: false,
            internal: is_internal,
            link_state: LinkState::Tracked(LinkNoiseEstimator::new(clock_a, clock_b)?),
            last_offsets: UnorderedRingBuffer::default(),
        });

        Ok((self, id))
    }

    /// Add a link where delay and link noise are non-tracked.
    ///
    /// # Errors
    /// Returns an error if the provided clocks are invalid, or an invalid combination for the link.
    pub fn add_untracked_link(
        mut self,
        clock_a: ClockId,
        clock_b: ClockId,
    ) -> Result<(Self, LinkId), LinkFilterError> {
        if clock_a == clock_b {
            return Err(LinkFilterError::ClocksEqual);
        }

        let clock_a_internal = self.estimation_state.is_internal_clock(clock_a);
        let clock_a_external = self.estimation_state.is_external_clock(clock_a);
        let clock_b_internal = self.estimation_state.is_internal_clock(clock_b);
        let clock_b_external = self.estimation_state.is_external_clock(clock_b);

        if !(clock_a_internal || clock_a_external) || !(clock_b_internal || clock_b_external) {
            return Err(LinkFilterError::UnknownClock);
        }

        if clock_a_external && clock_b_external {
            return Err(LinkFilterError::BothClocksExternal);
        }

        let id = LinkId::new();
        let is_internal = clock_a_internal && clock_b_internal;
        self.links.push(LinkInfo {
            id,
            active: is_internal,
            internal: is_internal,
            link_state: LinkState::Untracked(clock_a, clock_b),
            last_offsets: UnorderedRingBuffer::default(),
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
        if link.active && matches!(link.link_state, LinkState::Tracked(_)) {
            self.estimation_state = self.estimation_state.remove_link(id)?;
        }

        Ok(self)
    }
}
