use core::fmt::Debug;

pub mod common;
pub mod messages;

#[derive(Debug, Clone)]
pub enum WireFormatError {
    EnumConversionError,
    BufferTooShort,
}

impl<Enum: num_enum::TryFromPrimitive> From<num_enum::TryFromPrimitiveError<Enum>> for WireFormatError {
    fn from(_: num_enum::TryFromPrimitiveError<Enum>) -> Self {
        Self::EnumConversionError
    }
}

pub trait WireFormat: Debug + Clone + Eq {
    /// Serializes the object into the PTP wire format.
    /// 
    /// Returns the used buffer size that contains the message or an error.
    fn serialize(&self, buffer: &mut [u8]) -> Result<usize, WireFormatError>;

    /// Deserializes the object from the PTP wire format.
    /// 
    /// Returns the object and the size in the buffer that it takes up or an error.
    fn deserialize(buffer: &[u8]) -> Result<(Self, usize), WireFormatError>;
}
