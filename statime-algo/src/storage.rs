use core::marker::PhantomData;
use core::{
    cell::RefCell,
    fmt::Debug,
    ops::{Deref, DerefMut},
};

use arrayvec::ArrayVec;
use statime_base::{Clock, ClockId, TAI};

use crate::KalmanControllerState;
use crate::filter::BoundType;

/// Storage provider for a [`KalmanController`](crate::KalmanController)
pub trait KalmanStorage<C: Clock<TAI>>: KalmanStorageInternal<C> {}

/// Internal variant of the storage trait, used to make sure [`KalmanStorage`] is not
/// implementable externally.
pub trait KalmanStorageInternal<C: Clock<TAI>>: KalmanStorageBase {
    type SteeredClockStorage: SteeredClockStorage<C>;
    type StateMutex: StateMutex<Self, C>;
}

/// Parts of the storage traits which do not depend on the type of clock used.
///
/// This is a separate trait to avoid proliferation of generic parameters.
pub trait KalmanStorageBase: Debug + Clone {
    type MatrixStorage: MatrixStorage;
    type ExternalClockStorage: ExternalClockStorage;
    type InternalClockStorage: InternalClockStorage;
    type EstimatorLinkStorage: EstimatorLinkStorage;
    type FilterLinkStorage: FilterLinkStorage;
    type BoundStorage: BoundStorage;
}

/// Storage for the [`KalmanController`](crate::KalmanController) backed by allocations.
#[cfg(feature = "std")]
pub struct StdKalmanStorage<C>(PhantomData<C>);

#[cfg(feature = "std")]
impl<C> Debug for StdKalmanStorage<C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StdKalmanStorage").finish()
    }
}

#[cfg(feature = "std")]
impl<C> Clone for StdKalmanStorage<C> {
    fn clone(&self) -> Self {
        Self(PhantomData)
    }
}

#[cfg(feature = "std")]
impl<C> KalmanStorageBase for StdKalmanStorage<C> {
    type MatrixStorage = std::boxed::Box<[f64]>;
    type ExternalClockStorage = std::vec::Vec<ClockId>;
    type InternalClockStorage = std::vec::Vec<crate::estimator::ClockInfo>;
    type EstimatorLinkStorage = std::vec::Vec<crate::estimator::LinkInfo>;
    type FilterLinkStorage = std::vec::Vec<crate::filter::LinkInfo>;
    type BoundStorage = std::vec::Vec<(f64, crate::filter::BoundType)>;
}

#[cfg(feature = "std")]
impl<C: Clock<TAI>> KalmanStorageInternal<C> for StdKalmanStorage<C> {
    type SteeredClockStorage = std::vec::Vec<crate::ClockInfo<C>>;
    type StateMutex = std::sync::RwLock<crate::KalmanControllerState<StdKalmanStorage<C>, C>>;
}

#[cfg(feature = "std")]
impl<C: Clock<TAI>> KalmanStorage<C> for StdKalmanStorage<C> {}

/// Storage for the [`KalmanController`](crate::KalmanController) backed by fixed buffers.
///
/// N should be larger than the square of twice the number of internal clocks plus the
/// number of links, and larger than the number of external clocks.
///
/// Note: This type is not yet stable, we reserve the right to change it once calculating
/// for const generics becomes a thing in the rust compiler. Until then, this is a bit
/// wastefull for large N.
pub struct NoAllocKalmanStorage<C, const N: usize>(PhantomData<[C; N]>);

impl<C, const N: usize> Debug for NoAllocKalmanStorage<C, N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NoAllocKalmanStorage").finish()
    }
}

impl<C, const N: usize> Clone for NoAllocKalmanStorage<C, N> {
    fn clone(&self) -> Self {
        Self(PhantomData)
    }
}

impl<C, const N: usize> KalmanStorageBase for NoAllocKalmanStorage<C, N> {
    type MatrixStorage = [f64; N];
    type ExternalClockStorage = ArrayVec<ClockId, N>;
    type InternalClockStorage = ArrayVec<crate::estimator::ClockInfo, N>;
    type EstimatorLinkStorage = ArrayVec<crate::estimator::LinkInfo, N>;
    type FilterLinkStorage = ArrayVec<crate::filter::LinkInfo, N>;
    type BoundStorage = ArrayVec<(f64, crate::filter::BoundType), N>;
}

impl<C: Clock<TAI>, const N: usize> KalmanStorageInternal<C> for NoAllocKalmanStorage<C, N> {
    type SteeredClockStorage = ArrayVec<crate::ClockInfo<C>, N>;
    type StateMutex = RefCell<KalmanControllerState<NoAllocKalmanStorage<C, N>, C>>;
}

impl<C: Clock<TAI>, const N: usize> KalmanStorage<C> for NoAllocKalmanStorage<C, N> {}

/// A storage provider for a matrix. Abstracts a dynamically sized array of f64.
///
/// It is explicitly allowed for the  [`AsRef`] and [`AsMut`] implementations to
/// return references to larger arrays, so long as the additional length is always
/// identical and modification to the additional entries does not matter.
pub trait MatrixStorage: AsRef<[f64]> + AsMut<[f64]> + Clone + Debug {
    /// Create a new instance of the storage.
    fn new(len: usize, data: impl FnMut(usize) -> f64) -> Self;
}

#[cfg(feature = "std")]
impl MatrixStorage for std::boxed::Box<[f64]> {
    fn new(len: usize, data: impl FnMut(usize) -> f64) -> Self {
        (0..len).map(data).collect()
    }
}

impl<const N: usize> MatrixStorage for [f64; N] {
    fn new(len: usize, mut data: impl FnMut(usize) -> f64) -> Self {
        assert!(len <= N);
        core::array::from_fn(|index| if index < len { data(index) } else { 0.0 })
    }
}

/// A storage provider for the list of external clocks.
pub trait ExternalClockStorage: Deref<Target = [ClockId]> + DerefMut + Clone + Debug {
    fn new() -> Self;
    fn push(&mut self, id: ClockId);
    fn remove(&mut self, index: usize) -> ClockId;
}

#[cfg(feature = "std")]
impl ExternalClockStorage for std::vec::Vec<ClockId> {
    fn new() -> Self {
        std::vec![]
    }

    fn push(&mut self, id: ClockId) {
        self.push(id);
    }

    fn remove(&mut self, index: usize) -> ClockId {
        self.remove(index)
    }
}

impl<const N: usize> ExternalClockStorage for ArrayVec<ClockId, N> {
    fn new() -> Self {
        ArrayVec::new()
    }

    fn push(&mut self, id: ClockId) {
        self.push(id);
    }

    fn remove(&mut self, index: usize) -> ClockId {
        self.remove(index)
    }
}

/// A storage provider for the list of internal clocks.
pub trait InternalClockStorage:
    Deref<Target = [crate::estimator::ClockInfo]> + DerefMut + Clone + Debug
{
    fn new() -> Self;
    fn push(&mut self, info: crate::estimator::ClockInfo);
    fn remove(&mut self, index: usize) -> crate::estimator::ClockInfo;
}

#[cfg(feature = "std")]
impl InternalClockStorage for std::vec::Vec<crate::estimator::ClockInfo> {
    fn new() -> Self {
        Self::new()
    }

    fn push(&mut self, info: crate::estimator::ClockInfo) {
        self.push(info);
    }

    fn remove(&mut self, index: usize) -> crate::estimator::ClockInfo {
        self.remove(index)
    }
}

impl<const N: usize> InternalClockStorage for ArrayVec<crate::estimator::ClockInfo, N> {
    fn new() -> Self {
        Self::new()
    }

    fn push(&mut self, info: crate::estimator::ClockInfo) {
        self.push(info);
    }

    fn remove(&mut self, index: usize) -> crate::estimator::ClockInfo {
        self.remove(index)
    }
}

/// A storage provider for links in the estimator.
pub trait EstimatorLinkStorage:
    Deref<Target = [crate::estimator::LinkInfo]> + DerefMut + Clone + Debug
{
    fn new() -> Self;
    fn push(&mut self, info: crate::estimator::LinkInfo);
    fn remove(&mut self, index: usize) -> crate::estimator::LinkInfo;
}

#[cfg(feature = "std")]
impl EstimatorLinkStorage for std::vec::Vec<crate::estimator::LinkInfo> {
    fn new() -> Self {
        Self::new()
    }

    fn push(&mut self, info: crate::estimator::LinkInfo) {
        self.push(info);
    }

    fn remove(&mut self, index: usize) -> crate::estimator::LinkInfo {
        self.remove(index)
    }
}

impl<const N: usize> EstimatorLinkStorage for ArrayVec<crate::estimator::LinkInfo, N> {
    fn new() -> Self {
        Self::new()
    }

    fn push(&mut self, info: crate::estimator::LinkInfo) {
        self.push(info);
    }

    fn remove(&mut self, index: usize) -> crate::estimator::LinkInfo {
        self.remove(index)
    }
}

// A storage provider for links in the filter.
pub trait FilterLinkStorage:
    Deref<Target = [crate::filter::LinkInfo]> + DerefMut + Clone + Debug
{
    fn new() -> Self;
    fn push(&mut self, info: crate::filter::LinkInfo);
    fn remove(&mut self, index: usize) -> crate::filter::LinkInfo;
}

#[cfg(feature = "std")]
impl FilterLinkStorage for std::vec::Vec<crate::filter::LinkInfo> {
    fn new() -> Self {
        Self::new()
    }

    fn push(&mut self, info: crate::filter::LinkInfo) {
        self.push(info);
    }

    fn remove(&mut self, index: usize) -> crate::filter::LinkInfo {
        self.remove(index)
    }
}

impl<const N: usize> FilterLinkStorage for ArrayVec<crate::filter::LinkInfo, N> {
    fn new() -> Self {
        Self::new()
    }

    fn push(&mut self, info: crate::filter::LinkInfo) {
        self.push(info);
    }

    fn remove(&mut self, index: usize) -> crate::filter::LinkInfo {
        self.remove(index)
    }
}

pub trait BoundStorage:
    Deref<Target = [(f64, crate::filter::BoundType)]>
    + DerefMut
    + FromIterator<(f64, crate::filter::BoundType)>
{
}

#[cfg(feature = "std")]
impl BoundStorage for std::vec::Vec<(f64, BoundType)> {}

impl<const N: usize> BoundStorage for ArrayVec<(f64, BoundType), N> {}

// Storage for steered clocks
pub trait SteeredClockStorage<C>: Deref<Target = [crate::ClockInfo<C>]> + DerefMut {
    fn new() -> Self;
    fn push(&mut self, info: crate::ClockInfo<C>);
    fn remove(&mut self, index: usize) -> crate::ClockInfo<C>;
}

#[cfg(feature = "std")]
impl<C> SteeredClockStorage<C> for std::vec::Vec<crate::ClockInfo<C>> {
    fn new() -> Self {
        Self::new()
    }

    fn push(&mut self, info: crate::ClockInfo<C>) {
        self.push(info);
    }

    fn remove(&mut self, index: usize) -> crate::ClockInfo<C> {
        self.remove(index)
    }
}

impl<C, const N: usize> SteeredClockStorage<C> for ArrayVec<crate::ClockInfo<C>, N> {
    fn new() -> Self {
        Self::new()
    }

    fn push(&mut self, info: crate::ClockInfo<C>) {
        self.push(info);
    }

    fn remove(&mut self, index: usize) -> crate::ClockInfo<C> {
        self.remove(index)
    }
}

/// Trait for state management
pub trait StateMutex<Storage: KalmanStorageInternal<C>, C: Clock<TAI>> {
    /// Creates a new instance of the mutex
    fn new(state: KalmanControllerState<Storage, C>) -> Self;

    /// Takes a shared reference to the contained state and calls `f` with it
    fn with_ref<R, F: FnOnce(&KalmanControllerState<Storage, C>) -> R>(&self, f: F) -> R;

    /// Takes a mutable reference to the contained state and calls `f` with it
    fn with_mut<R, F: FnOnce(&mut KalmanControllerState<Storage, C>) -> R>(&self, f: F) -> R;
}

#[cfg(feature = "std")]
impl<Storage: KalmanStorageInternal<C>, C: Clock<TAI>> StateMutex<Storage, C>
    for std::sync::RwLock<KalmanControllerState<Storage, C>>
{
    fn new(state: KalmanControllerState<Storage, C>) -> Self {
        std::sync::RwLock::new(state)
    }

    fn with_ref<R, F: FnOnce(&KalmanControllerState<Storage, C>) -> R>(&self, f: F) -> R {
        f(&self.read().unwrap())
    }

    fn with_mut<R, F: FnOnce(&mut KalmanControllerState<Storage, C>) -> R>(&self, f: F) -> R {
        f(&mut self.write().unwrap())
    }
}

impl<Storage: KalmanStorageInternal<C>, C: Clock<TAI>> StateMutex<Storage, C>
    for RefCell<KalmanControllerState<Storage, C>>
{
    fn new(state: KalmanControllerState<Storage, C>) -> Self {
        RefCell::new(state)
    }

    fn with_ref<R, F: FnOnce(&KalmanControllerState<Storage, C>) -> R>(&self, f: F) -> R {
        f(&self.borrow())
    }

    fn with_mut<R, F: FnOnce(&mut KalmanControllerState<Storage, C>) -> R>(&self, f: F) -> R {
        f(&mut self.borrow_mut())
    }
}
