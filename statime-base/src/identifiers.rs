use core::sync::atomic::AtomicUsize;

/// Unique identifier for a clock
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct ClockId(usize);

impl ClockId {
    /// Get a new identifier for a clock.
    #[expect(
        clippy::new_without_default,
        reason = "The new value is non-trivial and non-constant, therefore not fitting for default."
    )]
    pub fn new() -> ClockId {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        ClockId(COUNTER.fetch_add(1, core::sync::atomic::Ordering::Relaxed))
    }
}

/// Unique identifier for a link
///
/// This consists of the two clocks that are linked, and a unique identifier for the link itself.
/// A link has no direction in nature, so the order of the clocks does not matter. The third
/// element, the unique identifier, is used to distinguish between multiple links between the same
/// two clocks.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct LinkId(ClockId, ClockId, usize);

impl LinkId {
    /// Get a new identifier for a clock.
    pub fn new(a: ClockId, b: ClockId) -> Option<LinkId> {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);

        if a == b {
            None
        } else {
            Some(LinkId(
                a,
                b,
                COUNTER.fetch_add(1, core::sync::atomic::Ordering::Relaxed),
            ))
        }
    }

    /// Get the first clock in the link.
    #[must_use]
    pub fn first_clock(self) -> ClockId {
        self.0
    }

    /// Get the second clock in the link.
    #[must_use]
    pub fn second_clock(self) -> ClockId {
        self.1
    }

    /// Check if the given clock is part of a link.
    #[must_use]
    pub fn contains_clock(self, clock: ClockId) -> bool {
        self.0 == clock || self.1 == clock
    }

    /// Get a directed link identifier for the link in the forward direction.
    ///
    /// This is the direction from the first to the second clock.
    #[must_use]
    pub fn forward(self) -> DirectedLinkId {
        DirectedLinkId(self, Direction::Forward)
    }

    /// Get a directed link identifier for the link in the reverse direction.
    ///
    /// This is the direction from the second to the first clock.
    #[must_use]
    pub fn reverse(self) -> DirectedLinkId {
        DirectedLinkId(self, Direction::Reverse)
    }
}

/// An identifier for a link with a specific direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DirectedLinkId(LinkId, Direction);

impl DirectedLinkId {
    /// Create a new directed link identifier.
    #[must_use]
    pub fn new(link_id: LinkId, direction: Direction) -> DirectedLinkId {
        DirectedLinkId(link_id, direction)
    }

    /// Retrieve the link identifier for the directed link.
    #[must_use]
    pub fn link_id(self) -> LinkId {
        self.0
    }

    /// Return the direction of the directed link.
    #[must_use]
    pub fn direction(self) -> Direction {
        self.1
    }

    /// Reverse the directed link to the other way.
    #[must_use]
    pub fn reverse(self) -> DirectedLinkId {
        DirectedLinkId::new(self.0, self.1.reverse())
    }

    /// Return the clock that is the source of the directed link.
    #[must_use]
    pub fn from_clock(self) -> ClockId {
        match self.1 {
            Direction::Forward => self.0.first_clock(),
            Direction::Reverse => self.0.second_clock(),
        }
    }

    /// Return the clock that is the destination of the directed link.
    #[must_use]
    pub fn to_clock(self) -> ClockId {
        match self.1 {
            Direction::Forward => self.0.second_clock(),
            Direction::Reverse => self.0.first_clock(),
        }
    }

    /// Returns true if the two directed links are the same link but in opposite directions.
    #[must_use]
    pub fn is_reverse_of(self, other: DirectedLinkId) -> bool {
        self.0 == other.0 && self.1.is_reverse_of(other.1)
    }
}

/// Direction of a directed link. This is used to indicate which direction a
/// measurement is being made in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Direction {
    /// The direction from the first clock to the second clock.
    Forward,
    /// The direction from the second clock to the first clock.
    Reverse,
}

impl Direction {
    /// Reverse the direction.
    #[must_use]
    pub fn reverse(self) -> Direction {
        match self {
            Direction::Forward => Direction::Reverse,
            Direction::Reverse => Direction::Forward,
        }
    }

    /// Returns true if the two directed links are the same link but in opposite directions.
    #[must_use]
    pub fn is_reverse_of(self, other: Direction) -> bool {
        self != other
    }
}

/// The type of a used source of time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SourceType {
    /// A generic pulse-per-second source
    Pps,
    /// A socket source
    Sock,
    /// An NTP source.
    Ntp,
    /// A CSPTP source.
    Csptp,
}
