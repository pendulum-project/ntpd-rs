//! The leaf types of the tree.

use std::{net::SocketAddr, path::PathBuf};

use serde::{Deserialize, Serialize, de};

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
pub trait ConfigurableAtomic:
    std::fmt::Debug + Clone + PartialEq + serde::Serialize + for<'a> serde::Deserialize<'a>
{
}

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
impl ConfigurableAtomic for usize {}
impl ConfigurableAtomic for isize {}
impl ConfigurableAtomic for String {}
impl ConfigurableAtomic for PathBuf {}
impl ConfigurableAtomic for SocketAddr {}
impl<T> ConfigurableAtomic for Option<T> where T: ConfigurableAtomic {}

#[derive(Debug, PartialEq, Clone, Copy)]
pub struct PartialF32(f32);

impl<'de> Deserialize<'de> for PartialF32 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = f32::deserialize(deserializer)?;
        if value.is_nan() || value.is_infinite() {
            Err(de::Error::custom(
                "Invalid float value, should not be NaN or infinite",
            ))
        } else {
            Ok(PartialF32(value))
        }
    }
}

impl Serialize for PartialF32 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_f32(self.0)
    }
}

impl PartialValue for PartialF32 {
    type Resolved = f32;

    fn attribute(&mut self, _origin: OriginId) {}

    fn apply_defaults(&mut self) {}

    fn resolve(self, _path: &mut ConfigPath) -> Result<Self::Resolved, ConfigError> {
        Ok(self.0)
    }
}

impl Configurable for f32 {
    type Partial = PartialF32;
    type Node = Setting<PartialF32>;
}

impl ConfigurableAtomic for Option<f32> {}

#[derive(Debug, PartialEq, Clone, Copy)]
pub struct PartialF64(f64);

impl<'de> Deserialize<'de> for PartialF64 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = f64::deserialize(deserializer)?;
        if value.is_nan() || value.is_infinite() {
            Err(de::Error::custom(
                "Invalid float value, should not be NaN or infinite",
            ))
        } else {
            Ok(PartialF64(value))
        }
    }
}

impl Serialize for PartialF64 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_f64(self.0)
    }
}

impl PartialValue for PartialF64 {
    type Resolved = f64;

    fn attribute(&mut self, _origin: OriginId) {}

    fn apply_defaults(&mut self) {}

    fn resolve(self, _path: &mut ConfigPath) -> Result<Self::Resolved, ConfigError> {
        Ok(self.0)
    }
}

impl Configurable for f64 {
    type Partial = PartialF64;
    type Node = Setting<PartialF64>;
}

impl ConfigurableAtomic for Option<f64> {}
