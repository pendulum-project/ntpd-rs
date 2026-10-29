use serde::{Deserialize, Serialize, de};

use crate::ConfigurableAtomic;

pub trait IsPositive {
    fn is_positive(&self) -> bool;
}

macro_rules! is_positive_int {
    ($int_type:ident) => {
        impl IsPositive for $int_type {
            fn is_positive(&self) -> bool {
                *self > 0
            }
        }
    };
}

macro_rules! is_positive_float {
    ($float_type:ident) => {
        impl IsPositive for $float_type {
            fn is_positive(&self) -> bool {
                *self > 0.0
            }
        }
    };
}

is_positive_int!(u8);
is_positive_int!(u16);
is_positive_int!(u32);
is_positive_int!(u64);
is_positive_int!(i8);
is_positive_int!(i16);
is_positive_int!(i32);
is_positive_int!(i64);
is_positive_float!(f32);
is_positive_float!(f64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Positive<T>(T);

impl<T> Positive<T> {
    pub fn into_inner(self) -> T {
        self.0
    }

    pub fn unchecked_new(value: T) -> Self {
        Positive(value)
    }
}

impl<'de, T: Deserialize<'de> + IsPositive> Deserialize<'de> for Positive<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = T::deserialize(deserializer)?;
        if T::is_positive(&value) {
            Ok(Positive(value))
        } else {
            Err(de::Error::custom("value should be positive."))
        }
    }
}

impl<T: Serialize> Serialize for Positive<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<T: ConfigurableAtomic + IsPositive> ConfigurableAtomic for Positive<T> {}
impl ConfigurableAtomic for Positive<f32> {}
impl ConfigurableAtomic for Positive<f64> {}
