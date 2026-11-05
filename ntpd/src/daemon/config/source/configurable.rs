//! Implementation of the configurable trait for SourceConfig
//!
//! Parts of this implementation are inspired by how serde derives
//! (de)serialization for internally tagged enums.

use std::marker::PhantomData;

use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{
        self, DeserializeSeed, EnumAccess, MapAccess, SeqAccess, Unexpected, VariantAccess, Visitor,
    },
    forward_to_deserialize_any,
    ser::{self, SerializeMap, SerializeStruct},
};
use statime_config::{Configurable, Merge, PartialValue, Setting, serde_util::Content};

#[cfg(target_os = "linux")]
use super::CsptpSourceConfig;
#[cfg(feature = "pps")]
use super::PpsSourceConfig;
use super::{
    NtpNtsPoolSourceConfig, NtpNtsSourceConfig, NtpPoolSourceConfig, NtpSourceConfig,
    SockSourceConfig, SourceConfig,
};

impl Configurable for SourceConfig {
    type Partial = PartialSourceConfig;
    // We never use source configs in a context where we want
    // to merge them, so using a Setting here saves us from
    // having to write merge code.
    type Node = Setting<PartialSourceConfig>;
}

#[derive(Debug, PartialEq, Clone)]
pub(crate) struct PartialSourceConfig {
    explicit_nts: bool,
    kind: PartialSourceConfigEnum,
}

#[derive(Debug, PartialEq, Clone)]
enum PartialSourceConfigEnum {
    NtpServer(<NtpSourceConfig as Configurable>::Node),
    NtpPool(<NtpPoolSourceConfig as Configurable>::Node),
    NtpNtsServer(<NtpNtsSourceConfig as Configurable>::Node),
    NtpNtsPool(<NtpNtsPoolSourceConfig as Configurable>::Node),
    Sock(<SockSourceConfig as Configurable>::Node),
    #[cfg(feature = "pps")]
    Pps(<PpsSourceConfig as Configurable>::Node),
    #[cfg(target_os = "linux")]
    Csptp(<CsptpSourceConfig as Configurable>::Node),
}

impl PartialValue for PartialSourceConfig {
    type Resolved = SourceConfig;

    fn attribute(&mut self, origin: statime_config::OriginId) {
        match &mut self.kind {
            PartialSourceConfigEnum::NtpServer(config) => config.attribute(origin),
            PartialSourceConfigEnum::NtpPool(config) => config.attribute(origin),
            PartialSourceConfigEnum::NtpNtsServer(config) => config.attribute(origin),
            PartialSourceConfigEnum::NtpNtsPool(config) => config.attribute(origin),
            PartialSourceConfigEnum::Sock(config) => config.attribute(origin),
            #[cfg(feature = "pps")]
            PartialSourceConfigEnum::Pps(config) => config.attribute(origin),
            #[cfg(target_os = "linux")]
            PartialSourceConfigEnum::Csptp(config) => config.attribute(origin),
        }
    }

    fn apply_defaults(&mut self) {
        match &mut self.kind {
            PartialSourceConfigEnum::NtpServer(config) => config.apply_defaults(),
            PartialSourceConfigEnum::NtpPool(config) => config.apply_defaults(),
            PartialSourceConfigEnum::NtpNtsServer(config) => config.apply_defaults(),
            PartialSourceConfigEnum::NtpNtsPool(config) => config.apply_defaults(),
            PartialSourceConfigEnum::Sock(config) => config.apply_defaults(),
            #[cfg(feature = "pps")]
            PartialSourceConfigEnum::Pps(config) => config.apply_defaults(),
            #[cfg(target_os = "linux")]
            PartialSourceConfigEnum::Csptp(config) => config.apply_defaults(),
        }
    }

    fn resolve(
        self,
        path: &mut statime_config::ConfigPath,
    ) -> Result<Self::Resolved, statime_config::ConfigError> {
        Ok(match self.kind {
            PartialSourceConfigEnum::NtpServer(config) => {
                SourceConfig::NtpServer(config.resolve(path)?)
            }
            PartialSourceConfigEnum::NtpPool(config) => {
                SourceConfig::NtpPool(config.resolve(path)?)
            }
            PartialSourceConfigEnum::NtpNtsServer(config) => {
                SourceConfig::NtpNtsServer(config.resolve(path)?)
            }
            PartialSourceConfigEnum::NtpNtsPool(config) => {
                SourceConfig::NtpNtsPool(config.resolve(path)?)
            }
            PartialSourceConfigEnum::Sock(config) => SourceConfig::Sock(config.resolve(path)?),
            #[cfg(feature = "pps")]
            PartialSourceConfigEnum::Pps(config) => SourceConfig::Pps(config.resolve(path)?),
            #[cfg(target_os = "linux")]
            PartialSourceConfigEnum::Csptp(config) => SourceConfig::Csptp(config.resolve(path)?),
        })
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum SourceConfigLabel {
    Ntp,
    NtpPool,
    Sock,
    #[cfg(feature = "pps")]
    Pps,
    #[cfg(target_os = "linux")]
    Csptp,
}

impl<'de> Deserialize<'de> for PartialSourceConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let is_human_readable = deserializer.is_human_readable();
        let (kind, nts, content) =
            deserializer.deserialize_map(ConfigTagFinderVisitor(is_human_readable, PhantomData))?;
        match (kind, nts) {
            (SourceConfigLabel::Ntp, Some(true)) => Ok(PartialSourceConfig {
                explicit_nts: true,
                kind: PartialSourceConfigEnum::NtpNtsServer(
                    <NtpNtsSourceConfig as Configurable>::Node::deserialize(
                        content.into_deserializer(is_human_readable),
                    )?,
                ),
            }),
            (SourceConfigLabel::Ntp, _) => Ok(PartialSourceConfig {
                explicit_nts: nts.is_some(),
                kind: PartialSourceConfigEnum::NtpServer(
                    <NtpSourceConfig as Configurable>::Node::deserialize(
                        content.into_deserializer(is_human_readable),
                    )?,
                ),
            }),
            (SourceConfigLabel::NtpPool, Some(true)) => Ok(PartialSourceConfig {
                explicit_nts: true,
                kind: PartialSourceConfigEnum::NtpNtsPool(
                    <NtpNtsPoolSourceConfig as Configurable>::Node::deserialize(
                        content.into_deserializer(is_human_readable),
                    )?,
                ),
            }),
            (SourceConfigLabel::NtpPool, _) => Ok(PartialSourceConfig {
                explicit_nts: nts.is_some(),
                kind: PartialSourceConfigEnum::NtpPool(
                    <NtpPoolSourceConfig as Configurable>::Node::deserialize(
                        content.into_deserializer(is_human_readable),
                    )?,
                ),
            }),
            #[cfg(target_os = "linux")]
            (SourceConfigLabel::Csptp, None) => Ok(PartialSourceConfig {
                explicit_nts: false,
                kind: PartialSourceConfigEnum::Csptp(
                    <CsptpSourceConfig as Configurable>::Node::deserialize(
                        content.into_deserializer(is_human_readable),
                    )?,
                ),
            }),
            (SourceConfigLabel::Sock, None) => Ok(PartialSourceConfig {
                explicit_nts: false,
                kind: PartialSourceConfigEnum::Sock(
                    <SockSourceConfig as Configurable>::Node::deserialize(
                        content.into_deserializer(is_human_readable),
                    )?,
                ),
            }),
            #[cfg(feature = "pps")]
            (SourceConfigLabel::Pps, None) => Ok(PartialSourceConfig {
                explicit_nts: false,
                kind: PartialSourceConfigEnum::Pps(
                    <PpsSourceConfig as Configurable>::Node::deserialize(
                        content.into_deserializer(is_human_readable),
                    )?,
                ),
            }),
            _ => Err(de::Error::custom("Unknown field `nts`")),
        }
    }
}

impl Serialize for PartialSourceConfig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match &self.kind {
            PartialSourceConfigEnum::NtpServer(config) => {
                config.serialize(PartialSourceConfigSerializer {
                    kind: "ntp",
                    nts: self.explicit_nts.then_some(false),
                    inner: serializer,
                })
            }
            PartialSourceConfigEnum::NtpPool(config) => {
                config.serialize(PartialSourceConfigSerializer {
                    kind: "ntp-pool",
                    nts: self.explicit_nts.then_some(false),
                    inner: serializer,
                })
            }
            PartialSourceConfigEnum::NtpNtsServer(config) => {
                config.serialize(PartialSourceConfigSerializer {
                    kind: "ntp",
                    nts: Some(true),
                    inner: serializer,
                })
            }
            PartialSourceConfigEnum::NtpNtsPool(config) => {
                config.serialize(PartialSourceConfigSerializer {
                    kind: "ntp-pool",
                    nts: Some(true),
                    inner: serializer,
                })
            }
            PartialSourceConfigEnum::Sock(config) => {
                config.serialize(PartialSourceConfigSerializer {
                    kind: "sock",
                    nts: None,
                    inner: serializer,
                })
            }
            #[cfg(feature = "pps")]
            PartialSourceConfigEnum::Pps(config) => {
                config.serialize(PartialSourceConfigSerializer {
                    kind: "pps",
                    nts: None,
                    inner: serializer,
                })
            }
            #[cfg(target_os = "linux")]
            PartialSourceConfigEnum::Csptp(config) => {
                config.serialize(PartialSourceConfigSerializer {
                    kind: "csptp",
                    nts: None,
                    inner: serializer,
                })
            }
        }
    }
}

struct PartialSourceConfigSerializer<S> {
    kind: &'static str,
    nts: Option<bool>,
    inner: S,
}

impl<S: Serializer> Serializer for PartialSourceConfigSerializer<S> {
    type Ok = S::Ok;
    type Error = S::Error;
    type SerializeSeq = S::SerializeSeq;
    type SerializeTuple = S::SerializeTuple;
    type SerializeTupleStruct = S::SerializeTupleStruct;
    type SerializeTupleVariant = S::SerializeTupleVariant;
    type SerializeMap = S::SerializeMap;
    type SerializeStruct = S::SerializeStruct;
    type SerializeStructVariant = S::SerializeStructVariant;

    fn serialize_bool(self, _v: bool) -> Result<Self::Ok, Self::Error> {
        Err(ser::Error::custom(format!(
            "Serializing a bool as source configuration for a {} is not possible.",
            self.kind
        )))
    }

    fn serialize_i8(self, _v: i8) -> Result<Self::Ok, Self::Error> {
        Err(ser::Error::custom(format!(
            "Serializing an i8 as source configuration for a {} is not possible.",
            self.kind
        )))
    }

    fn serialize_i16(self, _v: i16) -> Result<Self::Ok, Self::Error> {
        Err(ser::Error::custom(format!(
            "Serializing an i16 as source configuration for a {} is not possible.",
            self.kind
        )))
    }

    fn serialize_i32(self, _v: i32) -> Result<Self::Ok, Self::Error> {
        Err(ser::Error::custom(format!(
            "Serializing an i32 as source configuration for a {} is not possible.",
            self.kind
        )))
    }

    fn serialize_i64(self, _v: i64) -> Result<Self::Ok, Self::Error> {
        Err(ser::Error::custom(format!(
            "Serializing an i64 as source configuration for a {} is not possible.",
            self.kind
        )))
    }

    fn serialize_i128(self, _v: i128) -> Result<Self::Ok, Self::Error> {
        Err(ser::Error::custom(format!(
            "Serializing an i128 as source configuration for a {} is not possible.",
            self.kind
        )))
    }

    fn serialize_u8(self, _v: u8) -> Result<Self::Ok, Self::Error> {
        Err(ser::Error::custom(format!(
            "Serializing a u8 as source configuration for a {} is not possible.",
            self.kind
        )))
    }

    fn serialize_u16(self, _v: u16) -> Result<Self::Ok, Self::Error> {
        Err(ser::Error::custom(format!(
            "Serializing a u16 as source configuration for a {} is not possible.",
            self.kind
        )))
    }

    fn serialize_u32(self, _v: u32) -> Result<Self::Ok, Self::Error> {
        Err(ser::Error::custom(format!(
            "Serializing a u32 as source configuration for a {} is not possible.",
            self.kind
        )))
    }

    fn serialize_u64(self, _v: u64) -> Result<Self::Ok, Self::Error> {
        Err(ser::Error::custom(format!(
            "Serializing a u64 as source configuration for a {} is not possible.",
            self.kind
        )))
    }

    fn serialize_u128(self, _v: u128) -> Result<Self::Ok, Self::Error> {
        Err(ser::Error::custom(format!(
            "Serializing a u128 as source configuration for a {} is not possible.",
            self.kind
        )))
    }

    fn serialize_f32(self, _v: f32) -> Result<Self::Ok, Self::Error> {
        Err(ser::Error::custom(format!(
            "Serializing an f32 as source configuration for a {} is not possible.",
            self.kind
        )))
    }

    fn serialize_f64(self, _v: f64) -> Result<Self::Ok, Self::Error> {
        Err(ser::Error::custom(format!(
            "Serializing an f64 as source configuration for a {} is not possible.",
            self.kind
        )))
    }

    fn serialize_char(self, _v: char) -> Result<Self::Ok, Self::Error> {
        Err(ser::Error::custom(format!(
            "Serializing a char as source configuration for a {} is not possible.",
            self.kind
        )))
    }

    fn serialize_str(self, v: &str) -> Result<Self::Ok, Self::Error> {
        Err(ser::Error::custom(format!(
            "Serializing a str as source configuration for a {} is not possible.",
            self.kind
        )))
    }

    fn serialize_bytes(self, v: &[u8]) -> Result<Self::Ok, Self::Error> {
        Err(ser::Error::custom(format!(
            "Serializing a [u8] as source configuration for a {} is not possible.",
            self.kind
        )))
    }

    fn serialize_none(self) -> Result<Self::Ok, Self::Error> {
        Err(ser::Error::custom(format!(
            "Serializing an option as source configuration for a {} is not possible.",
            self.kind
        )))
    }

    fn serialize_some<T>(self, _value: &T) -> Result<Self::Ok, Self::Error>
    where
        T: ?Sized + Serialize,
    {
        Err(ser::Error::custom(format!(
            "Serializing an option as source configuration for a {} is not possible.",
            self.kind
        )))
    }

    fn serialize_unit(self) -> Result<Self::Ok, Self::Error> {
        Err(ser::Error::custom(format!(
            "Serializing a unit as source configuration for a {} is not possible.",
            self.kind
        )))
    }

    fn serialize_unit_struct(self, _name: &'static str) -> Result<Self::Ok, Self::Error> {
        Err(ser::Error::custom(format!(
            "Serializing a unit struct as source configuration for a {} is not possible.",
            self.kind
        )))
    }

    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
    ) -> Result<Self::Ok, Self::Error> {
        Err(ser::Error::custom(format!(
            "Serializing an enum as source configuration for a {} is not possible.",
            self.kind
        )))
    }

    fn serialize_newtype_struct<T>(
        self,
        _name: &'static str,
        _value: &T,
    ) -> Result<Self::Ok, Self::Error>
    where
        T: ?Sized + Serialize,
    {
        Err(ser::Error::custom(format!(
            "Serializing a newtype struct as source configuration for a {} is not possible.",
            self.kind
        )))
    }

    fn serialize_newtype_variant<T>(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _value: &T,
    ) -> Result<Self::Ok, Self::Error>
    where
        T: ?Sized + Serialize,
    {
        Err(ser::Error::custom(format!(
            "Serializing an enum as source configuration for a {} is not possible.",
            self.kind
        )))
    }

    fn serialize_seq(self, _len: Option<usize>) -> Result<Self::SerializeSeq, Self::Error> {
        Err(ser::Error::custom(format!(
            "Serializing a sequence as source configuration for a {} is not possible.",
            self.kind
        )))
    }

    fn serialize_tuple(self, _len: usize) -> Result<Self::SerializeTuple, Self::Error> {
        Err(ser::Error::custom(format!(
            "Serializing a tuple as source configuration for a {} is not possible.",
            self.kind
        )))
    }

    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleStruct, Self::Error> {
        Err(ser::Error::custom(format!(
            "Serializing a tuple struct as source configuration for a {} is not possible.",
            self.kind
        )))
    }

    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleVariant, Self::Error> {
        Err(ser::Error::custom(format!(
            "Serializing an enum as source configuration for a {} is not possible.",
            self.kind
        )))
    }

    fn serialize_map(self, len: Option<usize>) -> Result<Self::SerializeMap, Self::Error> {
        let mut map_serializer = self
            .inner
            .serialize_map(len.map(|l| l + 1 + usize::from(self.nts.is_some())))?;
        map_serializer.serialize_entry("type", self.kind)?;
        if let Some(nts) = self.nts {
            map_serializer.serialize_entry("nts", &nts)?;
        }
        Ok(map_serializer)
    }

    fn serialize_struct(
        self,
        name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStruct, Self::Error> {
        let mut struct_serializer = self
            .inner
            .serialize_struct(name, len + 1 + usize::from(self.nts.is_some()))?;
        struct_serializer.serialize_field("type", self.kind)?;
        if let Some(nts) = self.nts {
            struct_serializer.serialize_field("nts", &nts)?;
        }
        Ok(struct_serializer)
    }

    fn serialize_struct_variant(
        self,
        name: &'static str,
        variant_index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStructVariant, Self::Error> {
        Err(ser::Error::custom(format!(
            "Serializing an enum as source configuration for a {} is not possible.",
            self.kind
        )))
    }

    fn collect_str<T>(self, _value: &T) -> Result<Self::Ok, Self::Error>
    where
        T: ?Sized + std::fmt::Display,
    {
        Err(ser::Error::custom(format!(
            "Serializing a string as source configuration for a {} is not possible.",
            self.kind
        )))
    }

    fn is_human_readable(&self) -> bool {
        self.inner.is_human_readable()
    }
}

/// Visitor for deserializing a struct, searching for the type and nts fields,
/// and storing the remaining fields for later deserialization.
///
/// This is used to extract the type and nts use of a source in order to
/// determine which enum variant we are actually dealing with.
struct ConfigTagFinderVisitor<'de>(bool, PhantomData<Content<'de>>);

impl<'de> Visitor<'de> for ConfigTagFinderVisitor<'de> {
    type Value = (SourceConfigLabel, Option<bool>, Content<'de>);

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("A source configuration")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut kind = None;
        let mut nts = None;
        let mut entries = if let Some(cap) = map.size_hint() {
            Vec::with_capacity(cap)
        } else {
            Vec::new()
        };

        while let Some((key, value)) = map.next_entry::<_, Content<'_>>()? {
            match &key {
                Content::BorrowedString("type") => {
                    if kind.is_some() {
                        return Err(de::Error::duplicate_field("type"));
                    }
                    kind = Some(SourceConfigLabel::deserialize(
                        value.into_deserializer(self.0),
                    )?);
                }
                Content::String(s) if s == "type" => {
                    if kind.is_some() {
                        return Err(de::Error::duplicate_field("type"));
                    }
                    kind = Some(SourceConfigLabel::deserialize(
                        value.into_deserializer(self.0),
                    )?);
                }
                Content::BorrowedString("nts") => {
                    if nts.is_some() {
                        return Err(de::Error::duplicate_field("nts"));
                    }
                    nts = Some(bool::deserialize(value.into_deserializer(self.0))?);
                }
                Content::String(s) if s == "nts" => {
                    if nts.is_some() {
                        return Err(de::Error::duplicate_field("nts"));
                    }
                    nts = Some(bool::deserialize(value.into_deserializer(self.0))?);
                }
                _ => entries.push((key, value)),
            }
        }

        let Some(kind) = kind else {
            return Err(de::Error::missing_field("type"));
        };
        Ok((kind, nts, Content::Map(entries)))
    }
}
