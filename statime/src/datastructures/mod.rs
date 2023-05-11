//! General datastructures as defined by the ptp spec

use core::fmt::Debug;

pub mod common;
pub mod datasets;
pub mod messages;

#[derive(Clone, Debug)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum WireFormatError {
    #[cfg_attr(feature = "std", error("enum conversion failed"))]
    EnumConversionError,
    #[cfg_attr(feature = "std", error("a buffer is too short"))]
    BufferTooShort,
    #[cfg_attr(feature = "std", error("a container has insufficient capacity"))]
    CapacityError,
}

impl From<arrayvec::CapacityError> for WireFormatError {
    fn from(_: arrayvec::CapacityError) -> Self {
        WireFormatError::CapacityError
    }
}

impl<Enum: num_enum::TryFromPrimitive> From<num_enum::TryFromPrimitiveError<Enum>>
    for WireFormatError
{
    fn from(_: num_enum::TryFromPrimitiveError<Enum>) -> Self {
        Self::EnumConversionError
    }
}

trait WireFormat: Debug + Clone + Eq {
    /// The byte size on the wire of this object
    fn wire_size(&self) -> usize;

    /// Serializes the object into the PTP wire format.
    ///
    /// Returns the used buffer size that contains the message or an error.
    fn serialize(&self, buffer: &mut [u8]) -> Result<(), WireFormatError>;

    /// Deserializes the object from the PTP wire format.
    ///
    /// Returns the object and the size in the buffer that it takes up or an
    /// error.
    fn deserialize(buffer: &[u8]) -> Result<Self, WireFormatError>;
}
