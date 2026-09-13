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

        impl $crate::tree::resolve::Resolve for $type {
            type Resolved = Self;

            fn resolve(
                self,
                _path: &mut $crate::tree::ConfigPath,
            ) -> Result<Self::Resolved, $crate::error::ConfigError> {
                Ok(self)
            }
        }
    )+};
}
pub(crate) use atomic_value;

atomic_value!(
    bool, u8, i8, u16, i16, u32, i32, u64, i64, f64, String, PathBuf
);

// `Option<T>` is an ordinary leaf value: a field is optional because its
// built-in default is `None`, not because of the type it holds.
atomic_value!(Option<bool>);
