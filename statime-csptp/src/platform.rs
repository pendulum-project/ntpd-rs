use core::cell::RefCell;

use ntp_proto::{ClockId, TimeSnapshot};

use crate::CsptpState;

/// Internal state used by CSPTP.
///
/// This is publicly nameable and visible to make [`StateMutex`] implementable
/// outside of this crate.
#[derive(Clone, Copy)]
pub struct InternalState {
    pub(crate) csptp_state: CsptpState,
    pub(crate) time_snapshot: TimeSnapshot,
    pub(crate) active_source: Option<ClockId>,
}

/// A mutex over a [`InternalState`]
///
/// This provides an abstraction for locking state in various environments.
/// Implementations are provided for [`core::cell::RefCell`] and
/// [`std::sync::RwLock`].
pub trait StateMutex {
    /// Creates a new instance of the mutex
    fn new(state: InternalState) -> Self;

    /// Takes a shared reference to the contained state and calls `f` with it
    fn with_ref<R, F: FnOnce(&InternalState) -> R>(&self, f: F) -> R;

    /// Takes a mutable reference to the contained state and calls `f` with it
    fn with_mut<R, F: FnOnce(&mut InternalState) -> R>(&self, f: F) -> R;
}

impl StateMutex for RefCell<InternalState> {
    fn new(state: InternalState) -> Self {
        RefCell::new(state)
    }

    fn with_ref<R, F: FnOnce(&InternalState) -> R>(&self, f: F) -> R {
        f(&RefCell::borrow(self))
    }

    fn with_mut<R, F: FnOnce(&mut InternalState) -> R>(&self, f: F) -> R {
        f(&mut RefCell::borrow_mut(self))
    }
}

#[cfg(feature = "std")]
impl StateMutex for std::sync::RwLock<InternalState> {
    fn new(state: InternalState) -> Self {
        std::sync::RwLock::new(state)
    }

    fn with_ref<R, F: FnOnce(&InternalState) -> R>(&self, f: F) -> R {
        f(&self.read().unwrap())
    }

    fn with_mut<R, F: FnOnce(&mut InternalState) -> R>(&self, f: F) -> R {
        f(&mut self.write().unwrap())
    }
}
