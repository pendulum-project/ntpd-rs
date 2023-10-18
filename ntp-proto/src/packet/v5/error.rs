use crate::packet::error::ParsingError;
use std::fmt::{Display, Formatter};

#[derive(Debug)]
pub enum V5Error {
    InvalidDraftIdentification,
    MalformedTimescale,
    MalformedMode,
    InvalidFlags,
}

impl V5Error {
    /// `const` alternative to `.into()`
    pub const fn into_parse_err(self) -> ParsingError<std::convert::Infallible> {
        ParsingError::V5(self)
    }
}

impl Display for V5Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidDraftIdentification => f.write_str("Draft Identification invalid"),
            Self::MalformedTimescale => f.write_str("Malformed timescale"),
            Self::MalformedMode => f.write_str("Malformed mode"),
            Self::InvalidFlags => f.write_str("Invalid flags specified"),
        }
    }
}

impl From<V5Error> for crate::packet::error::ParsingError<std::convert::Infallible> {
    fn from(value: V5Error) -> Self {
        Self::V5(value)
    }
}
