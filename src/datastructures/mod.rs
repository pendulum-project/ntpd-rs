use core::fmt::Debug;

pub mod common;
pub mod messages;

#[derive(Debug, Clone)]
pub enum WireFormatError {
    EnumConversionError,
    BufferTooShort,
}

impl<Enum: num_enum::TryFromPrimitive> From<num_enum::TryFromPrimitiveError<Enum>>
    for WireFormatError
{
    fn from(_: num_enum::TryFromPrimitiveError<Enum>) -> Self {
        Self::EnumConversionError
    }
}

pub trait WireFormat: Debug + Clone + Eq {
    /// If the size of the type is statically known, then this must be that size.
    /// If the size is dynamic, then it should be None.
    const STATIC_SIZE: Option<usize>;

    /// Serializes the object into the PTP wire format.
    ///
    /// Returns a vector with the bytes of the message or an error.
    fn serialize_vec(&self) -> Result<Vec<u8>, WireFormatError> {
        match Self::STATIC_SIZE {
            Some(size) => {
                let mut buffer = vec![0; size];
                self.serialize(&mut buffer)?;
                Ok(buffer)
            }
            None => {
                // No known size, so create a vec with the max UDP frame size
                // Even if the message would be validly longer, we still couldn't transmit it
                let mut buffer = vec![0; u16::MAX as usize];
                let length = self.serialize(&mut buffer)?;
                buffer.truncate(length);
                Ok(buffer)
            }
        }
    }

    /// Serializes the object into the PTP wire format.
    ///
    /// Returns the used buffer size that contains the message or an error.
    fn serialize(&self, buffer: &mut [u8]) -> Result<usize, WireFormatError>;

    /// Deserializes the object from the PTP wire format.
    ///
    /// Returns the object and the size in the buffer that it takes up or an error.
    fn deserialize(buffer: &[u8]) -> Result<(Self, usize), WireFormatError>;
}
