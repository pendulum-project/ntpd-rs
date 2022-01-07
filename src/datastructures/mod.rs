use bitvec::{order::Lsb0, slice::BitSlice, store::BitStore};

pub mod common;
pub mod messages;

pub trait WireFormat: core::fmt::Debug + Clone + Eq {
    const BITSIZE: usize;

    fn serialize<T>(&self, buffer: &mut BitSlice<Lsb0, T>)
    where
        T: BitStore;

    fn deserialize<T>(buffer: &BitSlice<Lsb0, T>) -> Self
    where
        T: BitStore;
}
