use crate::datastructures::WireFormatError;

pub type Result<T, E = PortError> = core::result::Result<T, E>;

#[derive(Debug)]
pub enum PortError {
    WireFormat(WireFormatError),
}

impl core::fmt::Display for PortError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PortError::WireFormat(e) => f.write_fmt(format_args!("wire_format_error: {}", e)),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PortError {}

#[cfg(feature = "error_in_core")]
impl core::error::Error for WireFormatError {}

impl From<WireFormatError> for PortError {
    fn from(v: WireFormatError) -> Self {
        Self::WireFormat(v)
    }
}
