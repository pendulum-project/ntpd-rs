use crate::packet::error::ParsingError;
use crate::{NtpDuration, NtpLeapIndicator, NtpTimestamp};

#[allow(dead_code)]
pub mod extension_fields;

#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum NtpMode {
    Request = 3,
    Response = 4,
}

impl NtpMode {
    fn from_bits(bits: u8) -> Result<Self, ParsingError<std::convert::Infallible>> {
        Ok(match bits {
            3 => Self::Request,
            4 => Self::Response,
            _ => return Err(ParsingError::MalformedMode),
        })
    }

    fn to_bits(self) -> u8 {
        match self {
            Self::Request => 3,
            Self::Response => 4,
        }
    }

    #[allow(dead_code)]
    pub(crate) fn is_request(&self) -> bool {
        self == &Self::Request
    }

    #[allow(dead_code)]
    pub(crate) fn is_response(&self) -> bool {
        self == &Self::Response
    }
}

#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum NtpTimescale {
    Utc = 0,
    Tai = 1,
    Ut1 = 2,
    LeadSmearedUtc = 3,
}

impl NtpTimescale {
    fn from_bits(bits: u8) -> Result<Self, ParsingError<std::convert::Infallible>> {
        Ok(match bits {
            0 => Self::Utc,
            1 => Self::Tai,
            2 => Self::Ut1,
            3 => Self::LeadSmearedUtc,
            _ => return Err(ParsingError::MalformedTimescale),
        })
    }

    fn to_bits(self) -> u8 {
        match self {
            Self::Utc => 0,
            Self::Tai => 1,
            Self::Ut1 => 2,
            Self::LeadSmearedUtc => 3,
        }
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct NtpEra(pub u8);

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct NtpFlags {
    unknown_leap: bool,
    interleaved_mode: bool,
}

impl NtpFlags {
    fn from_bits(bits: [u8; 2]) -> Result<Self, ParsingError<std::convert::Infallible>> {
        if bits[0] != 0x00 || bits[1] & 0xFC != 0 {
            return Err(ParsingError::InvalidFlags);
        }

        Ok(Self {
            unknown_leap: bits[1] & 0x01 != 0,
            interleaved_mode: bits[1] & 0x02 != 0,
        })
    }

    fn as_bits(&self) -> [u8; 2] {
        let mut flags = self.unknown_leap as u8;
        flags |= 0x02 * self.interleaved_mode as u8;

        [0x00, flags]
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct NtpServerCookie([u8; 8]);

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct NtpClientCookie([u8; 8]);

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct NtpHeaderV5 {
    pub leap: NtpLeapIndicator,
    pub mode: NtpMode,
    pub stratum: u8,
    pub poll: i8,
    pub precision: i8,
    pub timescale: NtpTimescale,
    pub era: NtpEra,
    pub flags: NtpFlags,
    pub root_delay: NtpDuration,
    pub root_dispersion: NtpDuration,
    pub server_cookie: NtpServerCookie,
    pub client_cookie: NtpClientCookie,
    /// Time at the server when the request arrived from the client
    pub receive_timestamp: NtpTimestamp,
    /// Time at the server when the response left for the client
    pub transmit_timestamp: NtpTimestamp,
}

impl NtpHeaderV5 {
    const LENGTH: usize = 48;

    pub(crate) fn deserialize(
        data: &[u8],
    ) -> Result<(Self, usize), ParsingError<std::convert::Infallible>> {
        if data.len() < Self::LENGTH {
            return Err(ParsingError::IncorrectLength);
        }

        let version = (data[0] >> 3) & 0b111;
        if version != 5 {
            return Err(ParsingError::InvalidVersion(version));
        }

        Ok((
            Self {
                leap: NtpLeapIndicator::from_bits((data[0] & 0xC0) >> 6),
                mode: NtpMode::from_bits(data[0] & 0x07)?,
                stratum: data[1],
                poll: data[2] as i8,
                precision: data[3] as i8,
                timescale: NtpTimescale::from_bits(data[4])?,
                era: NtpEra(data[5]),
                flags: NtpFlags::from_bits(data[6..8].try_into().unwrap())?,
                root_delay: NtpDuration::from_bits_short(data[8..12].try_into().unwrap()),
                root_dispersion: NtpDuration::from_bits_short(data[12..16].try_into().unwrap()),
                server_cookie: NtpServerCookie(data[16..24].try_into().unwrap()),
                client_cookie: NtpClientCookie(data[24..32].try_into().unwrap()),
                receive_timestamp: NtpTimestamp::from_bits(data[32..40].try_into().unwrap()),
                transmit_timestamp: NtpTimestamp::from_bits(data[40..48].try_into().unwrap()),
            },
            Self::LENGTH,
        ))
    }

    #[allow(dead_code)]
    pub(crate) fn serialize<W: std::io::Write>(&self, w: &mut W) -> std::io::Result<()> {
        w.write_all(&[(self.leap.to_bits() << 6) | (5 << 3) | self.mode.to_bits()])?;
        w.write_all(&[self.stratum, self.poll as u8, self.precision as u8])?;
        w.write_all(&[self.timescale.to_bits()])?;
        w.write_all(&[self.era.0])?;
        w.write_all(&self.flags.as_bits())?;
        w.write_all(&self.root_delay.to_bits_short())?;
        w.write_all(&self.root_dispersion.to_bits_short())?;
        w.write_all(&self.server_cookie.0)?;
        w.write_all(&self.client_cookie.0)?;
        w.write_all(&self.receive_timestamp.to_bits())?;
        w.write_all(&self.transmit_timestamp.to_bits())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn round_trip_timescale() {
        for i in 0..=u8::MAX {
            if let Ok(ts) = NtpTimescale::from_bits(i) {
                assert_eq!(ts as u8, i);
            }
        }
    }

    #[test]
    fn flags() {
        let flags = NtpFlags::from_bits([0x00, 0x00]).unwrap();
        assert!(!flags.unknown_leap);
        assert!(!flags.interleaved_mode);

        let flags = NtpFlags::from_bits([0x00, 0x01]).unwrap();
        assert!(flags.unknown_leap);
        assert!(!flags.interleaved_mode);

        let flags = NtpFlags::from_bits([0x00, 0x02]).unwrap();
        assert!(!flags.unknown_leap);
        assert!(flags.interleaved_mode);

        let flags = NtpFlags::from_bits([0x00, 0x03]).unwrap();
        assert!(flags.unknown_leap);
        assert!(flags.interleaved_mode);

        let result = NtpFlags::from_bits([0xFF, 0xFF]);
        assert!(matches!(result, Err(ParsingError::InvalidFlags)));
    }

    #[test]
    fn parse_request() {
        #[allow(clippy::unusual_byte_groupings)] // Bits are grouped by fields
        #[rustfmt::skip]
        let data = [
            // LI VN  Mode
            0b_00_101_011,
            // Stratum
            0x00,
            // Poll
            0x05,
            // Precision
            0x00,
            // Timescale (0: UTC, 1: TAI, 2: UT1, 3: Leap-smeared UTC)
            0x02,
            // Era
            0x00,
            // Flags
            0x00,
            0b0000_00_1_0,
            // Root Delay
            0x00, 0x00, 0x00, 0x00,
            // Root Dispersion
            0x00, 0x00, 0x00, 0x00,
            // Server Cookie
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            // Client Cookie
            0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
            // Receive Timestamp
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            // Transmit Timestamp
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let (parsed, len) = NtpHeaderV5::deserialize(&data).unwrap();

        assert_eq!(len, 48);
        assert_eq!(parsed.leap, NtpLeapIndicator::NoWarning);
        assert!(parsed.mode.is_request());
        assert_eq!(parsed.stratum, 0);
        assert_eq!(parsed.poll, 5);
        assert_eq!(parsed.precision, 0);
        assert_eq!(parsed.timescale, NtpTimescale::Ut1);
        assert_eq!(parsed.era, NtpEra(0));
        assert!(parsed.flags.interleaved_mode);
        assert!(!parsed.flags.unknown_leap);
        assert!(parsed.flags.interleaved_mode);
        assert_eq!(parsed.root_delay, NtpDuration::from_seconds(0.0));
        assert_eq!(parsed.root_dispersion, NtpDuration::from_seconds(0.0));
        assert_eq!(parsed.server_cookie, NtpServerCookie([0x0; 8]));
        assert_eq!(
            parsed.client_cookie,
            NtpClientCookie([0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01])
        );
        assert_eq!(parsed.receive_timestamp, NtpTimestamp::from_fixed_int(0x0));
        assert_eq!(parsed.transmit_timestamp, NtpTimestamp::from_fixed_int(0x0));

        let mut buffer: [u8; 48] = [0u8; 48];
        let mut cursor = Cursor::new(buffer.as_mut_slice());
        parsed.serialize(&mut cursor).unwrap();

        assert_eq!(data, buffer);
    }

    #[test]
    fn parse_resonse() {
        #[allow(clippy::unusual_byte_groupings)] // Bits are grouped by fields
        #[rustfmt::skip]
        let data = [
            // LI VN  Mode
            0b_00_101_100,
            // Stratum
            0x04,
            // Poll
            0x05,
            // Precision
            0x06,
            // Timescale (0: UTC, 1: TAI, 2: UT1, 3: Leap-smeared UTC)
            0x01,
            // Era
            0x07,
            // Flags
            0x00,
            0b0000_00_1_0,
            // Root Delay
            0x00, 0x00, 0x02, 0x3f,
            // Root Dispersion
            0x00, 0x00, 0x00, 0x42,
            // Server Cookie
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            // Client Cookie
            0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
            // Receive Timestamp
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            // Transmit Timestamp
            0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
        ];

        let (parsed, len) = NtpHeaderV5::deserialize(&data).unwrap();

        assert_eq!(len, 48);
        assert_eq!(parsed.leap, NtpLeapIndicator::NoWarning);
        assert!(parsed.mode.is_response());
        assert_eq!(parsed.stratum, 4);
        assert_eq!(parsed.poll, 5);
        assert_eq!(parsed.precision, 6);
        assert_eq!(parsed.timescale, NtpTimescale::Tai);
        assert_eq!(parsed.era, NtpEra(7));
        assert!(parsed.flags.interleaved_mode);
        assert!(!parsed.flags.unknown_leap);
        assert!(parsed.flags.interleaved_mode);
        assert_eq!(
            parsed.root_delay,
            NtpDuration::from_seconds(0.00877380371298031)
        );
        assert_eq!(
            parsed.root_dispersion,
            NtpDuration::from_seconds(0.001007080078359479)
        );
        assert_eq!(
            parsed.server_cookie,
            NtpServerCookie([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
        );
        assert_eq!(
            parsed.client_cookie,
            NtpClientCookie([0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01])
        );
        assert_eq!(
            parsed.receive_timestamp,
            NtpTimestamp::from_fixed_int(0x1111111111111111)
        );
        assert_eq!(
            parsed.transmit_timestamp,
            NtpTimestamp::from_fixed_int(0x2222222222222222)
        );

        let mut buffer: [u8; 48] = [0u8; 48];
        let mut cursor = Cursor::new(buffer.as_mut_slice());
        parsed.serialize(&mut cursor).unwrap();

        assert_eq!(data, buffer);
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        for i in 0..=u8::MAX {
            let header = NtpHeaderV5 {
                leap: NtpLeapIndicator::from_bits(i % 4),
                mode: NtpMode::from_bits(3 + (i % 2)).unwrap(),
                stratum: i.wrapping_add(1),
                poll: i.wrapping_add(3) as i8,
                precision: i.wrapping_add(4) as i8,
                timescale: NtpTimescale::from_bits(i % 4).unwrap(),
                era: NtpEra(i.wrapping_add(6)),
                flags: NtpFlags {
                    unknown_leap: i % 3 == 0,
                    interleaved_mode: i % 4 == 0,
                },
                root_delay: NtpDuration::from_bits_short([i; 4]),
                root_dispersion: NtpDuration::from_bits_short([i.wrapping_add(1); 4]),
                server_cookie: NtpServerCookie([i.wrapping_add(2); 8]),
                client_cookie: NtpClientCookie([i.wrapping_add(3); 8]),
                receive_timestamp: NtpTimestamp::from_bits([i.wrapping_add(4); 8]),
                transmit_timestamp: NtpTimestamp::from_bits([i.wrapping_add(5); 8]),
            };

            let mut buffer: [u8; 48] = [0u8; 48];
            let mut cursor = Cursor::new(buffer.as_mut_slice());
            header.serialize(&mut cursor).unwrap();

            let (parsed, _) = NtpHeaderV5::deserialize(&buffer).unwrap();

            assert_eq!(header, parsed);
        }
    }

    #[test]
    fn fail_on_incorrect_length() {
        let data: [u8; 47] = [0u8; 47];

        assert!(matches!(
            NtpHeaderV5::deserialize(&data),
            Err(ParsingError::IncorrectLength)
        ));
    }

    #[test]
    #[allow(clippy::unusual_byte_groupings)] // Bits are grouped by fields
    fn fail_on_incorrect_version() {
        let mut data: [u8; 48] = [0u8; 48];
        data[0] = 0b_00_111_100;

        assert!(matches!(
            NtpHeaderV5::deserialize(&data),
            Err(ParsingError::InvalidVersion(7))
        ));
    }
}
