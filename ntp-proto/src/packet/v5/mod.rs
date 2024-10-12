#![warn(clippy::missing_const_for_fn)]
use crate::{
    io::NonBlockingWrite, NtpClock, NtpDuration, NtpLeapIndicator, NtpTimestamp, PollInterval,
    SystemSnapshot,
};
use rand::random;

mod error;
#[allow(dead_code)]
pub mod extension_fields;
pub mod server_reference_id;

use crate::packet::error::ParsingError;
pub use error::V5Error;

use super::RequestIdentifier;

#[allow(dead_code)]
pub(crate) const DRAFT_VERSION: &str = "draft-ietf-ntp-ntpv5-02";
pub(crate) const UPGRADE_TIMESTAMP: NtpTimestamp = NtpTimestamp::from_bits(*b"NTP5DRFT");

#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum NtpMode {
    Request = 3,
    Response = 4,
}

impl NtpMode {
    const fn from_bits(bits: u8) -> Result<Self, ParsingError<std::convert::Infallible>> {
        Ok(match bits {
            3 => Self::Request,
            4 => Self::Response,
            _ => return Err(V5Error::MalformedMode.into_parse_err()),
        })
    }

    const fn to_bits(self) -> u8 {
        self as u8
    }

    #[allow(dead_code)]
    pub(crate) const fn is_request(self) -> bool {
        matches!(self, Self::Request)
    }

    #[allow(dead_code)]
    pub(crate) const fn is_response(self) -> bool {
        matches!(self, Self::Response)
    }
}

#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum NtpTimescale {
    Utc = 0,
    Tai = 1,
    Ut1 = 2,
    LeapSmearedUtc = 3,
}

impl NtpTimescale {
    const fn from_bits(bits: u8) -> Result<Self, ParsingError<std::convert::Infallible>> {
        Ok(match bits {
            0 => Self::Utc,
            1 => Self::Tai,
            2 => Self::Ut1,
            3 => Self::LeapSmearedUtc,
            _ => return Err(V5Error::MalformedTimescale.into_parse_err()),
        })
    }

    const fn to_bits(self) -> u8 {
        self as u8
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct NtpEra(pub u8);

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct NtpFlags {
    pub unknown_leap: bool,
    pub interleaved_mode: bool,
    pub authnak: bool,
}

impl NtpFlags {
    const fn from_bits(bits: [u8; 2]) -> Result<Self, ParsingError<std::convert::Infallible>> {
        if bits[0] != 0x00 || bits[1] & 0b1111_1000 != 0 {
            return Err(V5Error::InvalidFlags.into_parse_err());
        }

        Ok(Self {
            unknown_leap: bits[1] & 0b01 != 0,
            interleaved_mode: bits[1] & 0b10 != 0,
            authnak: bits[1] & 0b100 != 0,
        })
    }

    const fn as_bits(self) -> [u8; 2] {
        let mut flags: u8 = 0;

        if self.unknown_leap {
            flags |= 0b01;
        }

        if self.interleaved_mode {
            flags |= 0b10;
        }

        if self.authnak {
            flags |= 0b100;
        }

        [0x00, flags]
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct NtpServerCookie(pub [u8; 8]);

impl NtpServerCookie {
    fn new_random() -> Self {
        // TODO does this match entropy handling of the rest of the system?
        Self(random())
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct NtpClientCookie(pub [u8; 8]);

impl NtpClientCookie {
    fn new_random() -> Self {
        // TODO does this match entropy handling of the rest of the system?
        Self(random())
    }

    pub const fn from_ntp_timestamp(ts: NtpTimestamp) -> Self {
        Self(ts.to_bits())
    }

    pub const fn into_ntp_timestamp(self) -> NtpTimestamp {
        NtpTimestamp::from_bits(self.0)
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct NtpHeaderV5 {
    pub leap: NtpLeapIndicator,
    pub mode: NtpMode,
    pub stratum: u8,
    pub poll: PollInterval,
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
    fn new() -> Self {
        Self {
            leap: NtpLeapIndicator::NoWarning,
            mode: NtpMode::Request,
            stratum: 0,
            poll: PollInterval::from_byte(0),
            precision: 0,
            root_delay: NtpDuration::default(),
            root_dispersion: NtpDuration::default(),
            receive_timestamp: NtpTimestamp::default(),
            transmit_timestamp: NtpTimestamp::default(),
            timescale: NtpTimescale::Utc,
            era: NtpEra(0),
            flags: NtpFlags {
                unknown_leap: false,
                interleaved_mode: false,
                authnak: false,
            },
            server_cookie: NtpServerCookie([0; 8]),
            client_cookie: NtpClientCookie([0; 8]),
        }
    }

    pub(crate) fn timestamp_response<C: NtpClock>(
        system: &SystemSnapshot,
        input: Self,
        recv_timestamp: NtpTimestamp,
        clock: &C,
    ) -> Self {
        Self {
            leap: system.time_snapshot.leap_indicator,
            mode: NtpMode::Response,
            stratum: system.stratum,
            // TODO this changed in NTPv5
            poll: input.poll,
            precision: system.time_snapshot.precision.log2(),
            // TODO this is new in NTPv5
            timescale: NtpTimescale::Utc,
            // TODO this is new in NTPv5
            era: NtpEra(0),
            // TODO this is new in NTPv5
            flags: NtpFlags {
                unknown_leap: false,
                interleaved_mode: false,
                authnak: false,
            },
            root_delay: system.time_snapshot.root_delay,
            root_dispersion: system.time_snapshot.root_dispersion,
            server_cookie: NtpServerCookie::new_random(),
            client_cookie: input.client_cookie,
            receive_timestamp: recv_timestamp,
            transmit_timestamp: clock.now().expect("Failed to read time"),
        }
    }

    fn kiss_response(packet_from_client: Self) -> Self {
        Self {
            mode: NtpMode::Response,
            flags: NtpFlags {
                unknown_leap: false,
                interleaved_mode: false,
                authnak: false,
            },
            server_cookie: NtpServerCookie::new_random(),
            client_cookie: packet_from_client.client_cookie,
            stratum: 0,
            ..Self::new()
        }
    }

    pub(crate) fn rate_limit_response(packet_from_client: Self) -> Self {
        Self {
            poll: packet_from_client.poll.force_inc(),
            ..Self::kiss_response(packet_from_client)
        }
    }

    pub(crate) fn deny_response(packet_from_client: Self) -> Self {
        Self {
            poll: PollInterval::NEVER,
            ..Self::kiss_response(packet_from_client)
        }
    }

    pub(crate) fn nts_nak_response(packet_from_client: Self) -> Self {
        Self {
            flags: NtpFlags {
                unknown_leap: false,
                interleaved_mode: false,
                authnak: true,
            },
            ..Self::kiss_response(packet_from_client)
        }
    }

    const WIRE_LENGTH: usize = 48;
    const VERSION: u8 = 5;

    pub(crate) fn deserialize(
        data: &[u8],
    ) -> Result<(Self, usize), ParsingError<std::convert::Infallible>> {
        if data.len() < Self::WIRE_LENGTH {
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
                poll: PollInterval::from_byte(data[2]),
                precision: data[3] as i8,
                timescale: NtpTimescale::from_bits(data[4])?,
                era: NtpEra(data[5]),
                flags: NtpFlags::from_bits(data[6..8].try_into().unwrap())?,
                root_delay: NtpDuration::from_bits_time32(data[8..12].try_into().unwrap()),
                root_dispersion: NtpDuration::from_bits_time32(data[12..16].try_into().unwrap()),
                server_cookie: NtpServerCookie(data[16..24].try_into().unwrap()),
                client_cookie: NtpClientCookie(data[24..32].try_into().unwrap()),
                receive_timestamp: NtpTimestamp::from_bits(data[32..40].try_into().unwrap()),
                transmit_timestamp: NtpTimestamp::from_bits(data[40..48].try_into().unwrap()),
            },
            Self::WIRE_LENGTH,
        ))
    }

    #[allow(dead_code)]
    pub(crate) fn serialize(&self, mut w: impl NonBlockingWrite) -> std::io::Result<()> {
        w.write_all(&[(self.leap.to_bits() << 6) | (Self::VERSION << 3) | self.mode.to_bits()])?;
        w.write_all(&[self.stratum, self.poll.as_byte(), self.precision as u8])?;
        w.write_all(&[self.timescale.to_bits()])?;
        w.write_all(&[self.era.0])?;
        w.write_all(&self.flags.as_bits())?;
        w.write_all(&self.root_delay.to_bits_time32())?;
        w.write_all(&self.root_dispersion.to_bits_time32())?;
        w.write_all(&self.server_cookie.0)?;
        w.write_all(&self.client_cookie.0)?;
        w.write_all(&self.receive_timestamp.to_bits())?;
        w.write_all(&self.transmit_timestamp.to_bits())?;
        Ok(())
    }

    pub fn poll_message(poll_interval: PollInterval) -> (Self, RequestIdentifier) {
        let mut packet = Self::new();
        packet.poll = poll_interval;
        packet.mode = NtpMode::Request;

        let client_cookie = NtpClientCookie::new_random();
        packet.client_cookie = client_cookie;

        (
            packet,
            RequestIdentifier {
                expected_origin_timestamp: client_cookie.into_ntp_timestamp(),
                uid: None,
            },
        )
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
        assert!(matches!(
            result,
            Err(ParsingError::V5(V5Error::InvalidFlags))
        ));
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
        assert_eq!(parsed.poll, PollInterval::from_byte(5));
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
        let cursor = Cursor::new(buffer.as_mut_slice());
        parsed.serialize(cursor).unwrap();

        assert_eq!(data, buffer);
    }

    #[test]
    fn parse_response() {
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
            0x10, 0x00, 0x00, 0x00,
            // Root Dispersion
            0x20, 0x00, 0x00, 0x00,
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
        assert_eq!(parsed.poll, PollInterval::from_byte(5));
        assert_eq!(parsed.precision, 6);
        assert_eq!(parsed.timescale, NtpTimescale::Tai);
        assert_eq!(parsed.era, NtpEra(7));
        assert!(parsed.flags.interleaved_mode);
        assert!(!parsed.flags.unknown_leap);
        assert!(parsed.flags.interleaved_mode);
        assert_eq!(parsed.root_delay, NtpDuration::from_seconds(1.0));
        assert_eq!(parsed.root_dispersion, NtpDuration::from_seconds(2.0));
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
            NtpTimestamp::from_fixed_int(0x1111_1111_1111_1111)
        );
        assert_eq!(
            parsed.transmit_timestamp,
            NtpTimestamp::from_fixed_int(0x2222_2222_2222_2222)
        );

        let mut buffer: [u8; 48] = [0u8; 48];
        let cursor = Cursor::new(buffer.as_mut_slice());
        parsed.serialize(cursor).unwrap();

        assert_eq!(data, buffer);
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        for i in 0..=u8::MAX {
            let header = NtpHeaderV5 {
                leap: NtpLeapIndicator::from_bits(i % 4),
                mode: NtpMode::from_bits(3 + (i % 2)).unwrap(),
                stratum: i.wrapping_add(1),
                poll: PollInterval::from_byte(i.wrapping_add(3)),
                precision: i.wrapping_add(4) as i8,
                timescale: NtpTimescale::from_bits(i % 4).unwrap(),
                era: NtpEra(i.wrapping_add(6)),
                flags: NtpFlags {
                    unknown_leap: i % 3 == 0,
                    interleaved_mode: i % 4 == 0,
                    authnak: i % 5 == 0,
                },
                root_delay: NtpDuration::from_bits_time32([i; 4]),
                root_dispersion: NtpDuration::from_bits_time32([i.wrapping_add(1); 4]),
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
