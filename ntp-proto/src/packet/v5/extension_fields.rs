use crate::io::NonBlockingWrite;
use crate::packet::ExtensionField;
use crate::packet::error::ParsingError;
use crate::packet::extension_fields::ExtensionFieldTypeId;
use crate::packet::v5::server_reference_id::BloomFilter;
use std::borrow::Cow;
use std::convert::Infallible;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct ReferenceIdRequest {
    payload_len: u16,
    offset: u16,
}

impl ReferenceIdRequest {
    pub const fn new(payload_len: u16, offset: u16) -> Option<Self> {
        if payload_len % 4 != 0 {
            return None;
        }

        if payload_len + offset > 512 {
            return None;
        }

        Some(Self {
            payload_len,
            offset,
        })
    }

    pub fn to_response(self, filter: &BloomFilter) -> Option<ReferenceIdResponse> {
        let offset = usize::from(self.offset);
        let payload_len = usize::from(self.payload_len);

        let bytes = filter.as_bytes().get(offset..)?.get(..payload_len)?.into();

        Some(ReferenceIdResponse { bytes })
    }

    pub fn serialize(&self, mut writer: impl NonBlockingWrite) -> std::io::Result<()> {
        let payload_len = self.payload_len;
        let ef_len: u16 = payload_len + 4;

        writer.write_all(
            &ExtensionFieldTypeId::ReferenceIdRequest
                .to_type_id()
                .to_be_bytes(),
        )?;
        writer.write_all(&ef_len.to_be_bytes())?;
        writer.write_all(&self.offset.to_be_bytes())?;
        writer.write_all(&[0; 2])?;

        let words = payload_len / 4;
        assert_eq!(payload_len % 4, 0);

        for _ in 1..words {
            writer.write_all(&[0; 4])?;
        }

        Ok(())
    }

    pub fn decode(msg: &[u8]) -> Result<Self, ParsingError<Infallible>> {
        let payload_len =
            u16::try_from(msg.len()).expect("NTP fields can not be longer than u16::MAX");
        let offset_bytes: [u8; 2] = msg
            .get(0..2)
            .ok_or(ParsingError::IncorrectLength)?
            .try_into()
            .unwrap();

        Ok(Self {
            payload_len,
            offset: u16::from_be_bytes(offset_bytes),
        })
    }

    pub const fn offset(&self) -> u16 {
        self.offset
    }

    pub const fn payload_len(&self) -> u16 {
        self.payload_len
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ReferenceIdResponse<'a> {
    bytes: Cow<'a, [u8]>,
}

impl<'a> ReferenceIdResponse<'a> {
    pub const fn new(bytes: &'a [u8]) -> Option<Self> {
        if bytes.len() % 4 != 0 {
            return None;
        }

        if bytes.len() > 512 {
            return None;
        }

        Some(Self {
            bytes: Cow::Borrowed(bytes),
        })
    }

    pub fn into_owned(self) -> ReferenceIdResponse<'static> {
        ReferenceIdResponse {
            bytes: Cow::Owned(self.bytes.into_owned()),
        }
    }

    pub fn serialize(&self, mut writer: impl NonBlockingWrite) -> std::io::Result<()> {
        let len: u16 = self.bytes.len().try_into().unwrap();
        let len = len + 4; // Add room for type and length
        assert_eq!(len % 4, 0);

        writer.write_all(
            &ExtensionFieldTypeId::ReferenceIdResponse
                .to_type_id()
                .to_be_bytes(),
        )?;
        writer.write_all(&len.to_be_bytes())?;
        writer.write_all(self.bytes.as_ref())?;

        Ok(())
    }

    pub const fn decode(bytes: &'a [u8]) -> Self {
        Self {
            bytes: Cow::Borrowed(bytes),
        }
    }

    // TODO: Clippy 0.1.86 complains that this function could be const, but that is not true
    // allow can be removed in later versions
    #[allow(clippy::missing_const_for_fn)]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl From<ReferenceIdRequest> for ExtensionField<'static> {
    fn from(value: ReferenceIdRequest) -> Self {
        Self::ReferenceIdRequest(value)
    }
}

impl<'a> From<ReferenceIdResponse<'a>> for ExtensionField<'a> {
    fn from(value: ReferenceIdResponse<'a>) -> Self {
        Self::ReferenceIdResponse(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reference_id_request_too_short() {
        assert!(matches!(
            ReferenceIdRequest::decode(&[]),
            Err(ParsingError::IncorrectLength)
        ));
    }

    #[test]
    fn test_reference_id_request_decode() {
        let res = ReferenceIdRequest::decode(&[0, 2, 0, 0, 0]).unwrap();
        assert_eq!(res.payload_len, 5);
        assert_eq!(res.offset, 2);
    }
}
