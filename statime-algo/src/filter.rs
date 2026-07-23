use crate::{
    ClockId, EstimatorError, EstimatorState, LinkId, LinkNoiseError, LinkNoiseEstimator,
    estimator::UncertainValue, ringbuffer::UnorderedRingBuffer,
};

type Timestamp = f64;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum LinkFilterError {
    UnknownClock,
    UnknownLink,
    BothClocksExternal,
    ClocksEqual,
    EstimatorError(EstimatorError),
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

pub struct LinkFilter {
    links: std::vec::Vec<LinkInfo>,
    estimation_state: EstimatorState,
}

impl LinkFilter {
    pub fn empty(time: Timestamp) -> Self {
        LinkFilter {
            links: std::vec::Vec::new(),
            estimation_state: EstimatorState::empty(time),
        }
    }

    pub fn progress_time(mut self, new_time: Timestamp) -> Result<Self, LinkFilterError> {
        self.estimation_state = self.estimation_state.progress_time(new_time)?;
        Ok(self)
    }

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

    pub fn measurement(
        self,
        from: ClockId,
        to: ClockId,
        offset: UncertainValue,
        link: LinkId,
    ) -> Result<Self, LinkFilterError> {
        todo!()
    }

    pub fn add_external_clock(mut self) -> Result<(Self, ClockId), LinkFilterError> {
        let id = ClockId::new();
        self.estimation_state = self.estimation_state.add_external_clock(id)?;
        Ok((self, id))
    }

    pub fn remove_external_clock(mut self, id: ClockId) -> Result<Self, LinkFilterError> {
        // FIXME: check for existence of links with this clock
        self.estimation_state = self.estimation_state.remove_external_clock(id)?;
        Ok(self)
    }

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

    pub fn remove_clock(mut self, id: ClockId) -> Result<Self, LinkFilterError> {
        // FIXME: check for existence of links with this clock
        self.estimation_state = self.estimation_state.remove_clock(id)?;
        Ok(self)
    }

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
            active: false,
            internal: is_internal,
            link_state: LinkState::Tracked(LinkNoiseEstimator::new(clock_a, clock_b)?),
            last_offsets: UnorderedRingBuffer::default(),
        });

        Ok((self, id))
    }

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
