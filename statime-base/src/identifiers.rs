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

/// Unique identifier for a clock
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct LinkId(usize);

impl LinkId {
    /// Get a new identifier for a clock.
    #[expect(
        clippy::new_without_default,
        reason = "The new value is non-trivial and non-constant, therefore not fitting for default."
    )]
    pub fn new() -> LinkId {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        LinkId(COUNTER.fetch_add(1, core::sync::atomic::Ordering::Relaxed))
    }
}
