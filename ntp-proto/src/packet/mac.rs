use std::borrow::Cow;

use crate::io::NonBlockingWrite;

use super::error::ParsingError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Mac<'a> {
    keyid: u32,
    mac: Cow<'a, [u8]>,
}

impl<'a> Mac<'a> {
    // As per RFC7822:
    // If a MAC is used, it resides at the end of the packet.  This field
    // can be either 24 octets long, 20 octets long, or a 4-octet
    // crypto-NAK.
    pub(super) const MAXIMUM_SIZE: usize = 24;

    pub(super) fn into_owned(self) -> Mac<'static> {
        Mac {
            keyid: self.keyid,
            mac: Cow::Owned(self.mac.into_owned()),
        }
    }

    pub(super) fn serialize(&self, mut w: impl NonBlockingWrite) -> std::io::Result<()> {
        w.write_all(&self.keyid.to_be_bytes())?;
        w.write_all(&self.mac)
    }

    pub(super) fn deserialize(
        data: &'a [u8],
    ) -> Result<Mac<'a>, ParsingError<std::convert::Infallible>> {
        if data.len() < 4 || data.len() >= Self::MAXIMUM_SIZE {
            return Err(ParsingError::IncorrectLength);
        }

        Ok(Mac {
            keyid: u32::from_be_bytes(data[0..4].try_into().unwrap()),
            mac: Cow::Borrowed(&data[4..]),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let input = Mac {
            keyid: 42,
            mac: Cow::Borrowed(&[1, 2, 3, 4, 5, 6, 7, 8]),
        };

        let input = input.clone();

        let mut w = Vec::new();
        input.serialize(&mut w).unwrap();

        let output = Mac::deserialize(&w).unwrap();

        assert_eq!(input, output);
    }
}
