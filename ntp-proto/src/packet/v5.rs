use crate::packet::error::ParsingError;
use crate::{NtpAssociationMode, NtpDuration, NtpLeapIndicator, NtpTimestamp, ReferenceId};

#[repr(u8)]
enum NtpTimescale {
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

#[derive(Copy, Clone, Default, Ord, PartialOrd, Eq, PartialEq)]
struct NtpEra(pub u8);

struct NtpFlags(u16);

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

struct NtpClientCookie(u64);

struct NtpServerCookie(u64);

struct NtpHeaderV5 {
    leap: NtpLeapIndicator,
    mode: NtpAssociationMode,
    stratum: u8,
    poll: i8,
    precision: i8,
    timescale: NtpTimescale,
    era: NtpEra,
    flags: NtpFlags,
    root_delay: NtpDuration,
    root_dispersion: NtpDuration,
    client_cookie: NtpClientCookie,
    server_cookie: NtpServerCookie,
    /// Time at the server when the request arrived from the client
    receive_timestamp: NtpTimestamp,
    /// Time at the server when the response left for the client
    transmit_timestamp: NtpTimestamp,
}

impl NtpHeaderV5 {
    fn deserialize(data: &[u8]) -> Result<(Self, usize), ParsingError<std::convert::Infallible>> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn parse() {
        #[rustfmt::skip]
        let data = [
            // LI VN  Mode
            0b_00_101_000,
            // Stratum
            0x00,
            // Poll
            0x00,
            // Precision
            0x00,
            // Timescale (0: UTC, 1: TAI, 2: UT1, 3: Leap-smeared UTC)
            0x00,
            // Era
            0x00,
            // Flags
            0x00,
            0b0000_00_0_0,
            // Root Delay
            0x00, 0x00, 0x00, 0x00,
            // Root Dispersion
            0x00, 0x00, 0x00, 0x00,
            // Server Cookie
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            // Client Cookie
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            // Receive Timestamp
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            // Transmit Timestamp
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
    }
}
