//! The leaf types of the tree.

use std::path::PathBuf;

use crate::{
    ConfigError,
    tree::{
        configurable::Configurable, merge::OriginId, partial_value::PartialValue, path::ConfigPath,
        setting::Setting,
    },
};

/// Marks a type as a value the tree does not look inside.
///
/// Every traversal (i.e. resolving, applying defaults and attributing)
/// stops at such a type, so implementing this is all it takes to make a type
/// usable as a configuration value. It can be derived automatically using
/// `#[derive(ConfigurableAtomic)]`.
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

/// An atomic value has nothing inside for a pass to reach: the setting holding
/// it records the origin and supplies the default, and resolving it is where
/// the recursion stops.
impl<T> PartialValue for T
where
    T: ConfigurableAtomic,
{
    type Resolved = Self;

    fn attribute(&mut self, _origin: OriginId) {}

    fn apply_defaults(&mut self) {}

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
