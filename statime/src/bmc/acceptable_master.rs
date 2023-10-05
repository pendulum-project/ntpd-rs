use crate::ClockIdentity;

pub trait AcceptableMasterList {
    fn is_acceptable(&self, identity: ClockIdentity) -> bool;
}

impl AcceptableMasterList for () {
    fn is_acceptable(&self, _identity: ClockIdentity) -> bool {
        true
    }
}

impl AcceptableMasterList for &[ClockIdentity] {
    fn is_acceptable(&self, identity: ClockIdentity) -> bool {
        self.contains(&identity)
    }
}

impl<const CAP: usize> AcceptableMasterList for arrayvec::ArrayVec<ClockIdentity, CAP> {
    fn is_acceptable(&self, identity: ClockIdentity) -> bool {
        self.contains(&identity)
    }
}

#[cfg(feature = "std")]
impl AcceptableMasterList for std::vec::Vec<ClockIdentity> {
    fn is_acceptable(&self, identity: ClockIdentity) -> bool {
        self.contains(&identity)
    }
}

#[cfg(feature = "std")]
impl AcceptableMasterList for std::collections::BTreeSet<ClockIdentity> {
    fn is_acceptable(&self, identity: ClockIdentity) -> bool {
        self.contains(&identity)
    }
}

#[cfg(feature = "std")]
impl AcceptableMasterList for std::collections::HashSet<ClockIdentity> {
    fn is_acceptable(&self, identity: ClockIdentity) -> bool {
        self.contains(&identity)
    }
}

impl<T: AcceptableMasterList> AcceptableMasterList for Option<T> {
    fn is_acceptable(&self, identity: ClockIdentity) -> bool {
        match self {
            Some(list) => list.is_acceptable(identity),
            None => true,
        }
    }
}
