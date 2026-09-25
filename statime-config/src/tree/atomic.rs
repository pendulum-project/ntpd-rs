//! The leaf types of the tree.

use std::path::PathBuf;

use crate::{
    ConfigError,
    tree::{
        configurable::Configurable, defaults::ApplyDefaults, merge::Attributable, merge::OriginId,
        path::ConfigPath, resolve::Resolve, setting::Setting,
    },
};

/// Marks a type as a value the tree does not look inside.
///
/// Every traversal stops at such a type, so implementing this is all it takes
/// to make a type usable as a configuration value. The traversals themselves
/// follow from it, rather than being written out once per trait.
pub trait ConfigurableAtomic {}

/// An atomic value is its own partial representation, and a field holding one
/// is a setting.
impl<T> Configurable for T
where
    T: ConfigurableAtomic,
{
    type Partial = Self;
    type Node = Setting<Self>;
}

/// There is nothing inside to attribute; the setting holding it records the
/// origin.
impl<T> Attributable for T
where
    T: ConfigurableAtomic,
{
    fn attribute(&mut self, _origin: OriginId) {}
}

/// There is nothing inside to default; the field supplies the default of the
/// setting holding it.
impl<T> ApplyDefaults for T
where
    T: ConfigurableAtomic,
{
    fn apply_defaults(&mut self) {}
}

/// An atomic value resolves to itself, which is where the recursion stops.
impl<T> Resolve for T
where
    T: ConfigurableAtomic,
{
    type Resolved = Self;

    fn resolve(self, _path: &mut ConfigPath) -> Result<Self::Resolved, ConfigError> {
        Ok(self)
    }
}

impl ConfigurableAtomic for bool {}
impl ConfigurableAtomic for u8 {}
impl ConfigurableAtomic for i8 {}
impl ConfigurableAtomic for u16 {}
impl ConfigurableAtomic for i16 {}
impl ConfigurableAtomic for u32 {}
impl ConfigurableAtomic for i32 {}
impl ConfigurableAtomic for u64 {}
impl ConfigurableAtomic for i64 {}
impl ConfigurableAtomic for f64 {}
impl ConfigurableAtomic for String {}
impl ConfigurableAtomic for PathBuf {}
impl<T> ConfigurableAtomic for Option<T> where T: ConfigurableAtomic {}
