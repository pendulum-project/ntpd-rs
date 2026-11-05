use std::marker::PhantomData;

use serde::{
    Deserialize, Deserializer,
    de::{
        self, DeserializeSeed, EnumAccess, MapAccess, SeqAccess, Unexpected, VariantAccess, Visitor,
    },
    forward_to_deserialize_any,
};

/// A struct for holding arbitrary not-yet-fully-deserialized data.
///
/// This is used to temporarily hold the remaining enum fields when deserializing
/// the type and nts status of a source.
pub enum Content<'de> {
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
    pub fn into_deserializer<E: de::Error>(
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
            Content::NewtypeStruct(_) => Unexpected::NewtypeStruct,
            Content::Sequence(_) => Unexpected::Seq,
            Content::Map(_) => Unexpected::Map,
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
        _name: &'static str,
        _variants: &'static [&'static str],
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
        _name: &'static str,
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

    fn tuple_variant<V>(self, _len: usize, visitor: V) -> Result<V::Value, Self::Error>
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
        _fields: &'static [&'static str],
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
