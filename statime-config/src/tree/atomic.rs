//! Registration of the leaf types of the tree.

use std::path::PathBuf;

/// Implements the tree traversals for types that have no nested values to
/// visit.
macro_rules! atomic_value {
    ($($type:ty),+ $(,)?) => {$(
        impl $crate::tree::merge::Attribute for $type {
            fn attribute(&mut self, _origin: $crate::tree::merge::OriginId) {}
        }

        impl $crate::tree::defaults::ApplyDefaults for $type {
            fn apply_defaults(&mut self) {}
        }
    )+};
}
pub(crate) use atomic_value;

atomic_value!(
    bool, u8, i8, u16, i16, u32, i32, u64, i64, f64, String, PathBuf
);
