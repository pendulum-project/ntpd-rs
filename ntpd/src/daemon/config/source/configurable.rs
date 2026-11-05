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
use statime_config::{Configurable, Merge, PartialValue, Setting};

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

/// A struct for holding arbitrary not-yet-fully-deserialized data.
///
/// This is used to temporarily hold the remaining enum fields when deserializing
/// the type and nts status of a source.
enum Content<'de> {
    Bool(bool),
    I8(i8),
    I16(i16),
    I32(i32),
    I64(i64),
    I128(i128),
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    U128(u128),
    F32(f32),
    F64(f64),
    Char(char),
    String(String),
    BorrowedString(&'de str),
    Bytes(Vec<u8>),
    BorrowedBytes(&'de [u8]),
    None,
    Some(Box<Content<'de>>),
    Unit,
    NewtypeStruct(Box<Content<'de>>),
    Sequence(Vec<Content<'de>>),
    Map(Vec<(Content<'de>, Content<'de>)>),
}

impl<'de> Content<'de> {
    fn into_deserializer<E: de::Error>(
        self,
        is_human_readable: bool,
    ) -> impl Deserializer<'de, Error = E> {
        ContentDeserializer {
            content: self,
            phantom: PhantomData,
            is_human_readable,
        }
    }
}

impl Content<'_> {
    fn as_unexpected(&self) -> Unexpected<'_> {
        match self {
            Content::Bool(b) => Unexpected::Bool(*b),
            Content::I8(v) => Unexpected::Signed((*v).into()),
            Content::I16(v) => Unexpected::Signed((*v).into()),
            Content::I32(v) => Unexpected::Signed((*v).into()),
            Content::I64(v) => Unexpected::Signed(*v),
            Content::I128(v) => Unexpected::Signed(*v as i64),
            Content::U8(v) => Unexpected::Unsigned((*v).into()),
            Content::U16(v) => Unexpected::Unsigned((*v).into()),
            Content::U32(v) => Unexpected::Unsigned((*v).into()),
            Content::U64(v) => Unexpected::Unsigned(*v),
            Content::U128(v) => Unexpected::Unsigned(*v as u64),
            Content::F32(v) => Unexpected::Float((*v).into()),
            Content::F64(v) => Unexpected::Float(*v),
            Content::Char(v) => Unexpected::Char(*v),
            Content::String(v) => Unexpected::Str(v),
            Content::BorrowedString(v) => Unexpected::Str(v),
            Content::Bytes(v) => Unexpected::Bytes(v),
            Content::BorrowedBytes(v) => Unexpected::Bytes(v),
            Content::None | Content::Some(_) => Unexpected::Option,
            Content::Unit => Unexpected::Unit,
            Content::NewtypeStruct(v) => Unexpected::NewtypeStruct,
            Content::Sequence(v) => Unexpected::Seq,
            Content::Map(v) => Unexpected::Map,
        }
    }
}

struct ContentVisitor<'de>(PhantomData<Content<'de>>);

impl<'de> Visitor<'de> for ContentVisitor<'de> {
    type Value = Content<'de>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("any value")
    }

    fn visit_bool<E>(self, v: bool) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Content::Bool(v))
    }

    fn visit_i8<E>(self, v: i8) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Content::I8(v))
    }

    fn visit_i16<E>(self, v: i16) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Content::I16(v))
    }

    fn visit_i32<E>(self, v: i32) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Content::I32(v))
    }

    fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Content::I64(v))
    }

    fn visit_i128<E>(self, v: i128) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Content::I128(v))
    }

    fn visit_u8<E>(self, v: u8) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Content::U8(v))
    }

    fn visit_u16<E>(self, v: u16) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Content::U16(v))
    }

    fn visit_u32<E>(self, v: u32) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Content::U32(v))
    }

    fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Content::U64(v))
    }

    fn visit_u128<E>(self, v: u128) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Content::U128(v))
    }

    fn visit_f32<E>(self, v: f32) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Content::F32(v))
    }

    fn visit_f64<E>(self, v: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Content::F64(v))
    }

    fn visit_char<E>(self, v: char) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Content::Char(v))
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Content::String(v.into()))
    }

    fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Content::BorrowedString(v))
    }

    fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Content::String(v))
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Content::Bytes(v.into()))
    }

    fn visit_borrowed_bytes<E>(self, v: &'de [u8]) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Content::BorrowedBytes(v))
    }

    fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Content::Bytes(v))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Content::None)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(Content::Some(Box::new(Content::deserialize(deserializer)?)))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Content::Unit)
    }

    fn visit_newtype_struct<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(Content::NewtypeStruct(Box::new(Content::deserialize(
            deserializer,
        )?)))
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        let mut data = if let Some(cap) = seq.size_hint() {
            Vec::with_capacity(cap)
        } else {
            Vec::new()
        };
        while let Some(element) = seq.next_element()? {
            data.push(element);
        }
        Ok(Content::Sequence(data))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        let mut data = if let Some(cap) = map.size_hint() {
            Vec::with_capacity(cap)
        } else {
            Vec::new()
        };
        while let Some(entry) = map.next_entry()? {
            data.push(entry);
        }
        Ok(Content::Map(data))
    }

    fn visit_enum<A>(self, _data: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::EnumAccess<'de>,
    {
        Err(de::Error::custom(
            "Enums are not supported inside source configurations",
        ))
    }
}

impl<'de> Deserialize<'de> for Content<'de> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(ContentVisitor::<'de>(PhantomData))
    }
}

/// A deserializer for deserializing from previously parsed contents.
///
/// Used as the deserializer for the contents of the enum, as well as for the
/// values of the type and nts fields.
struct ContentDeserializer<'de, E> {
    content: Content<'de>,
    phantom: PhantomData<E>,
    is_human_readable: bool,
}

impl<'de, E: de::Error> Deserializer<'de> for ContentDeserializer<'de, E> {
    type Error = E;

    fn deserialize_any<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        match self.content {
            Content::Bool(v) => visitor.visit_bool(v),
            Content::I8(v) => visitor.visit_i8(v),
            Content::I16(v) => visitor.visit_i16(v),
            Content::I32(v) => visitor.visit_i32(v),
            Content::I64(v) => visitor.visit_i64(v),
            Content::I128(v) => visitor.visit_i128(v),
            Content::U8(v) => visitor.visit_u8(v),
            Content::U16(v) => visitor.visit_u16(v),
            Content::U32(v) => visitor.visit_u32(v),
            Content::U64(v) => visitor.visit_u64(v),
            Content::U128(v) => visitor.visit_u128(v),
            Content::F32(v) => visitor.visit_f32(v),
            Content::F64(v) => visitor.visit_f64(v),
            Content::Char(v) => visitor.visit_char(v),
            Content::String(v) => visitor.visit_string(v),
            Content::BorrowedString(v) => visitor.visit_borrowed_str(v),
            Content::Bytes(v) => visitor.visit_byte_buf(v),
            Content::BorrowedBytes(v) => visitor.visit_borrowed_bytes(v),
            Content::None => visitor.visit_none(),
            Content::Some(content) => {
                visitor.visit_some(content.into_deserializer(self.is_human_readable))
            }
            Content::Unit => visitor.visit_unit(),
            Content::NewtypeStruct(content) => {
                visitor.visit_newtype_struct(content.into_deserializer(self.is_human_readable))
            }
            Content::Sequence(contents) => visitor.visit_seq(ContentSequenceAccess {
                elements: contents.into_iter(),
                phantom: PhantomData,
                is_human_readable: self.is_human_readable,
            }),
            Content::Map(items) => visitor.visit_map(ContentMapAccess {
                value: None,
                entries: items.into_iter(),
                phantom: PhantomData,
                is_human_readable: self.is_human_readable,
            }),
        }
    }

    fn deserialize_option<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        match self.content {
            Content::None => visitor.visit_none(),
            Content::Some(v) => visitor.visit_some(v.into_deserializer(self.is_human_readable)),
            _ => visitor.visit_some(self),
        }
    }

    fn deserialize_enum<V>(
        self,
        name: &'static str,
        variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        match self.content {
            Content::Map(value) if value.len() == 1 => {
                let (variant, value) = value.into_iter().next().unwrap();
                visitor.visit_enum(ContentEnumAccess {
                    variant,
                    value: Some(value),
                    phantom: PhantomData,
                    is_human_readable: self.is_human_readable,
                })
            }
            s @ (Content::String(_) | Content::BorrowedString(_)) => {
                visitor.visit_enum(ContentEnumAccess {
                    variant: s,
                    value: None,
                    phantom: PhantomData,
                    is_human_readable: self.is_human_readable,
                })
            }
            other => Err(de::Error::invalid_type(
                other.as_unexpected(),
                &"tuple variant",
            )),
        }
    }

    fn deserialize_unit<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        match self.content {
            // Allow tagged enums containing unit to work properly.
            Content::Map(ref v) if v.is_empty() => visitor.visit_unit(),
            _ => self.deserialize_any(visitor),
        }
    }

    fn deserialize_unit_struct<V>(
        self,
        name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        match self.content {
            // Allow tagged enums containing unit structs to work properly.
            Content::Map(ref v) if v.is_empty() => visitor.visit_unit(),
            Content::Sequence(ref v) if v.is_empty() => visitor.visit_unit(),
            _ => self.deserialize_any(visitor),
        }
    }

    forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
        bytes byte_buf newtype_struct seq tuple
        tuple_struct map struct identifier ignored_any
    }

    fn is_human_readable(&self) -> bool {
        self.is_human_readable
    }
}

struct ContentEnumAccess<'de, E> {
    variant: Content<'de>,
    value: Option<Content<'de>>,
    phantom: PhantomData<E>,
    is_human_readable: bool,
}

impl<'de, E: de::Error> EnumAccess<'de> for ContentEnumAccess<'de, E> {
    type Error = E;
    type Variant = ContentVariantAccess<'de, E>;

    fn variant_seed<V>(self, seed: V) -> Result<(V::Value, Self::Variant), Self::Error>
    where
        V: DeserializeSeed<'de>,
    {
        seed.deserialize(self.variant.into_deserializer(self.is_human_readable))
            .map(|v| {
                (
                    v,
                    ContentVariantAccess {
                        value: self.value,
                        phantom: PhantomData,
                        is_human_readable: self.is_human_readable,
                    },
                )
            })
    }
}

struct ContentVariantAccess<'de, E> {
    value: Option<Content<'de>>,
    phantom: PhantomData<E>,
    is_human_readable: bool,
}

impl<'de, E: de::Error> VariantAccess<'de> for ContentVariantAccess<'de, E> {
    type Error = E;

    fn unit_variant(self) -> Result<(), Self::Error> {
        match self.value {
            Some(value) => {
                Deserialize::deserialize(value.into_deserializer(self.is_human_readable))
            }
            None => Ok(()),
        }
    }

    fn newtype_variant_seed<T>(self, seed: T) -> Result<T::Value, Self::Error>
    where
        T: DeserializeSeed<'de>,
    {
        match self.value {
            Some(value) => seed.deserialize(value.into_deserializer(self.is_human_readable)),
            None => Err(de::Error::invalid_type(
                de::Unexpected::UnitVariant,
                &"newtype variant",
            )),
        }
    }

    fn tuple_variant<V>(self, len: usize, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        match self.value {
            Some(Content::Sequence(v)) => visitor.visit_seq(ContentSequenceAccess {
                elements: v.into_iter(),
                phantom: PhantomData,
                is_human_readable: self.is_human_readable,
            }),
            Some(other) => Err(de::Error::invalid_type(
                other.as_unexpected(),
                &"tuple variant",
            )),
            _ => Err(de::Error::invalid_type(
                de::Unexpected::UnitVariant,
                &"tuple variant",
            )),
        }
    }

    fn struct_variant<V>(
        self,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        match self.value {
            Some(Content::Map(v)) => visitor.visit_map(ContentMapAccess {
                value: None,
                entries: v.into_iter(),
                phantom: PhantomData,
                is_human_readable: self.is_human_readable,
            }),
            Some(Content::Sequence(v)) => visitor.visit_seq(ContentSequenceAccess {
                elements: v.into_iter(),
                phantom: PhantomData,
                is_human_readable: self.is_human_readable,
            }),
            Some(other) => Err(de::Error::invalid_type(
                other.as_unexpected(),
                &"struct variant",
            )),
            _ => Err(de::Error::invalid_type(
                de::Unexpected::UnitVariant,
                &"struct variant",
            )),
        }
    }
}

struct ContentSequenceAccess<'de, E> {
    elements: std::vec::IntoIter<Content<'de>>,
    phantom: PhantomData<E>,
    is_human_readable: bool,
}

impl<'de, E: de::Error> SeqAccess<'de> for ContentSequenceAccess<'de, E> {
    type Error = E;

    fn next_element_seed<T>(&mut self, seed: T) -> Result<Option<T::Value>, Self::Error>
    where
        T: DeserializeSeed<'de>,
    {
        let Some(next) = self.elements.next() else {
            return Ok(None);
        };
        seed.deserialize(next.into_deserializer(self.is_human_readable))
            .map(Some)
    }
}

struct ContentMapAccess<'de, E> {
    value: Option<Content<'de>>,
    entries: std::vec::IntoIter<(Content<'de>, Content<'de>)>,
    phantom: PhantomData<E>,
    is_human_readable: bool,
}

impl<'de, E: de::Error> MapAccess<'de> for ContentMapAccess<'de, E> {
    type Error = E;

    fn next_key_seed<K>(&mut self, seed: K) -> Result<Option<K::Value>, Self::Error>
    where
        K: DeserializeSeed<'de>,
    {
        let Some((key, value)) = self.entries.next() else {
            return Ok(None);
        };
        self.value = Some(value);
        seed.deserialize(key.into_deserializer(self.is_human_readable))
            .map(Some)
    }

    fn next_value_seed<V>(&mut self, seed: V) -> Result<V::Value, Self::Error>
    where
        V: DeserializeSeed<'de>,
    {
        seed.deserialize(
            self.value
                .take()
                .unwrap()
                .into_deserializer(self.is_human_readable),
        )
    }
}
