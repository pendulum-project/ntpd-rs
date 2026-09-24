//! Registration of the leaf types of the tree.

use std::path::PathBuf;

/// Implements the tree traversals for types that have no nested values to
/// visit.
macro_rules! atomic_value {
    ($($type:ty),+ $(,)?) => {$(
        impl $crate::__private::Attributable for $type {
            fn attribute(&mut self, _origin: $crate::__private::OriginId) {}
        }

        impl $crate::__private::ApplyDefaults for $type {
            fn apply_defaults(&mut self) {}
        }

        impl $crate::__private::Configurable for $type {
            type Partial = Self;
            type Node = $crate::__private::Setting<Self>;
        }

        impl $crate::__private::Resolve for $type {
            type Resolved = Self;

            fn resolve(
                self,
                _path: &mut $crate::__private::ConfigPath,
            ) -> Result<Self::Resolved, $crate::ConfigError> {
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
