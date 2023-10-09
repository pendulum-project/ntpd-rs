use crate::packet::error::ParsingError;
use crate::{NtpDuration, NtpLeapIndicator, NtpTimestamp};

#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum NtpMode {
    Request = 3,
    Response = 4,
}

impl NtpMode {
    fn from_bits(bits: u8) -> Option<Self> {
        Some(match bits {
            3 => Self::Request,
            4 => Self::Response,
            _ => return None,
        })
    }

    pub fn is_request(&self) -> bool {
        self == &Self::Request
    }

    pub fn is_response(&self) -> bool {
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
    fn from_bits(bits: u8) -> Option<Self> {
        Some(match bits {
            0 => Self::Utc,
            1 => Self::Tai,
            2 => Self::Ut1,
            3 => Self::LeadSmearedUtc,
            _ => return None,
        })
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct NtpEra(pub u8);

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct NtpFlags(u16);

impl NtpFlags {
    fn from_bits(bits: [u8; 2]) -> Self {
        Self(u16::from_be_bytes(bits))
    }

    pub fn unknown_leap(&self) -> bool {
        self.0 & 0x01 != 0
    }

    pub fn interleaved_mode(&self) -> bool {
        self.0 & 0x02 != 0
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
                mode: NtpMode::from_bits(data[0] & 0x07).unwrap(),
                stratum: data[1],
                poll: data[2] as i8,
                precision: data[3] as i8,
                timescale: NtpTimescale::from_bits(data[4]).unwrap(),
                era: NtpEra(data[5]),
                flags: NtpFlags::from_bits(data[6..8].try_into().unwrap()),
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{NoCipher, NtpPacket};

    #[test]
    fn round_trip_timescale() {
        for i in 0..=u8::MAX {
            match NtpTimescale::from_bits(i) {
                None => {}
                Some(ts) => assert_eq!(ts as u8, i),
            }
        }
    }

    #[test]
    fn flags() {
        let flags = NtpFlags(0x00);
        assert_eq!(flags.unknown_leap(), false);
        assert_eq!(flags.interleaved_mode(), false);

        let flags = NtpFlags(0x01);
        assert_eq!(flags.unknown_leap(), true);
        assert_eq!(flags.interleaved_mode(), false);

        let flags = NtpFlags(0x02);
        assert_eq!(flags.unknown_leap(), false);
        assert_eq!(flags.interleaved_mode(), true);

        let flags = NtpFlags(0x03);
        assert_eq!(flags.unknown_leap(), true);
        assert_eq!(flags.interleaved_mode(), true);
    }

    #[test]
    fn parse_request() {
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
        assert!(parsed.flags.interleaved_mode());
        assert!(!parsed.flags.unknown_leap());
        assert!(parsed.flags.interleaved_mode());
        assert_eq!(parsed.root_delay, NtpDuration::from_seconds(0.0));
        assert_eq!(parsed.root_dispersion, NtpDuration::from_seconds(0.0));
        assert_eq!(parsed.server_cookie, NtpServerCookie([0x0; 8]));
        assert_eq!(
            parsed.client_cookie,
            NtpClientCookie([0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01])
        );
        assert_eq!(parsed.receive_timestamp, NtpTimestamp::from_fixed_int(0x0));
        assert_eq!(parsed.transmit_timestamp, NtpTimestamp::from_fixed_int(0x0));
    }

    #[test]
    fn parse_resonse() {
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
        assert!(parsed.flags.interleaved_mode());
        assert!(!parsed.flags.unknown_leap());
        assert!(parsed.flags.interleaved_mode());
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
    }

    #[test]
    fn deserialize_v5() {
        let mut packet = [0u8; 48];
        // Alter       LI VN  Mode
        packet[0] = 0b_00_101_011;

        NtpPacket::deserialize(&packet, &NoCipher).unwrap();
    }
}
