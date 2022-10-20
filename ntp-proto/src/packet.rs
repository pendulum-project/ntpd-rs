use std::fmt::Display;

use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};

use crate::{NtpClock, NtpDuration, NtpTimestamp, PollInterval, ReferenceId, SystemSnapshot};

#[derive(Debug)]
pub enum PacketParsingError {
    InvalidVersion(u8),
}

impl Display for PacketParsingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidVersion(version) => {
                f.write_fmt(format_args!("Invalid version {}", version))
            }
        }
    }
}

impl std::error::Error for PacketParsingError {}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NtpLeapIndicator {
    NoWarning,
    Leap61,
    Leap59,
    Unknown,
}

impl NtpLeapIndicator {
    // This function should only ever be called with 2 bit values
    // (in the least significant position)
    fn from_bits(bits: u8) -> NtpLeapIndicator {
        match bits {
            0 => NtpLeapIndicator::NoWarning,
            1 => NtpLeapIndicator::Leap61,
            2 => NtpLeapIndicator::Leap59,
            3 => NtpLeapIndicator::Unknown,
            // This function should only ever be called from the packet parser
            // with just two bits, so this really should be unreachable
            _ => unreachable!(),
        }
    }

    fn to_bits(self) -> u8 {
        match self {
            NtpLeapIndicator::NoWarning => 0,
            NtpLeapIndicator::Leap61 => 1,
            NtpLeapIndicator::Leap59 => 2,
            NtpLeapIndicator::Unknown => 3,
        }
    }

    pub fn is_synchronized(&self) -> bool {
        !matches!(self, Self::Unknown)
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum NtpAssociationMode {
    Reserved,
    SymmetricActive,
    SymmetricPassive,
    Client,
    Server,
    Broadcast,
    Control,
    Private,
}

impl NtpAssociationMode {
    // This function should only ever be called with 3 bit values
    // (in the least significant position)
    fn from_bits(bits: u8) -> NtpAssociationMode {
        match bits {
            0 => NtpAssociationMode::Reserved,
            1 => NtpAssociationMode::SymmetricActive,
            2 => NtpAssociationMode::SymmetricPassive,
            3 => NtpAssociationMode::Client,
            4 => NtpAssociationMode::Server,
            5 => NtpAssociationMode::Broadcast,
            6 => NtpAssociationMode::Control,
            7 => NtpAssociationMode::Private,
            // This function should only ever be called from the packet parser
            // with just three bits, so this really should be unreachable
            _ => unreachable!(),
        }
    }

    fn to_bits(self) -> u8 {
        match self {
            NtpAssociationMode::Reserved => 0,
            NtpAssociationMode::SymmetricActive => 1,
            NtpAssociationMode::SymmetricPassive => 2,
            NtpAssociationMode::Client => 3,
            NtpAssociationMode::Server => 4,
            NtpAssociationMode::Broadcast => 5,
            NtpAssociationMode::Control => 6,
            NtpAssociationMode::Private => 7,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtpPacket {
    header: NtpHeader,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum NtpHeader {
    V4(NtpHeaderV4),
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
struct NtpHeaderV4 {
    leap: NtpLeapIndicator,
    mode: NtpAssociationMode,
    stratum: u8,
    poll: i8,
    precision: i8,
    root_delay: NtpDuration,
    root_dispersion: NtpDuration,
    reference_id: ReferenceId,
    reference_timestamp: NtpTimestamp,
    /// Time at the client when the request departed for the server
    origin_timestamp: NtpTimestamp,
    /// Time at the server when the request arrived from the client
    receive_timestamp: NtpTimestamp,
    /// Time at the server when the response left for the client
    transmit_timestamp: NtpTimestamp,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct RequestIdentifier {
    expected_origin_timestamp: NtpTimestamp,
}

impl NtpHeaderV4 {
    const VERSION: u8 = 4;

    /// A new, empty NtpHeader
    fn new() -> Self {
        Self {
            leap: NtpLeapIndicator::NoWarning,
            mode: NtpAssociationMode::Client,
            stratum: 0,
            poll: 0,
            precision: 0,
            root_delay: NtpDuration::default(),
            root_dispersion: NtpDuration::default(),
            reference_id: ReferenceId::from_int(0),
            reference_timestamp: NtpTimestamp::default(),
            origin_timestamp: NtpTimestamp::default(),
            receive_timestamp: NtpTimestamp::default(),
            transmit_timestamp: NtpTimestamp::default(),
        }
    }

    fn deserialize(data: &[u8; 48]) -> Self {
        Self {
            leap: NtpLeapIndicator::from_bits((data[0] & 0xC0) >> 6),
            mode: NtpAssociationMode::from_bits(data[0] & 0x07),
            stratum: data[1],
            poll: data[2] as i8,
            precision: data[3] as i8,
            root_delay: NtpDuration::from_bits_short(data[4..8].try_into().unwrap()),
            root_dispersion: NtpDuration::from_bits_short(data[8..12].try_into().unwrap()),
            reference_id: ReferenceId::from_bytes(data[12..16].try_into().unwrap()),
            reference_timestamp: NtpTimestamp::from_bits(data[16..24].try_into().unwrap()),
            origin_timestamp: NtpTimestamp::from_bits(data[24..32].try_into().unwrap()),
            receive_timestamp: NtpTimestamp::from_bits(data[32..40].try_into().unwrap()),
            transmit_timestamp: NtpTimestamp::from_bits(data[40..48].try_into().unwrap()),
        }
    }

    fn serialize(&self) -> [u8; 48] {
        let root_delay = self.root_delay.to_bits_short();
        let root_dispersion = self.root_dispersion.to_bits_short();
        let reference_id = self.reference_id.to_bytes();
        let reference_timestamp = self.reference_timestamp.to_bits();
        let origin_timestamp = self.origin_timestamp.to_bits();
        let receive_timestamp = self.receive_timestamp.to_bits();
        let transmit_timestamp = self.transmit_timestamp.to_bits();

        [
            (self.leap.to_bits() << 6) | (Self::VERSION << 3) | self.mode.to_bits(),
            self.stratum,
            self.poll as u8,
            self.precision as u8,
            root_delay[0],
            root_delay[1],
            root_delay[2],
            root_delay[3],
            root_dispersion[0],
            root_dispersion[1],
            root_dispersion[2],
            root_dispersion[3],
            reference_id[0],
            reference_id[1],
            reference_id[2],
            reference_id[3],
            reference_timestamp[0],
            reference_timestamp[1],
            reference_timestamp[2],
            reference_timestamp[3],
            reference_timestamp[4],
            reference_timestamp[5],
            reference_timestamp[6],
            reference_timestamp[7],
            origin_timestamp[0],
            origin_timestamp[1],
            origin_timestamp[2],
            origin_timestamp[3],
            origin_timestamp[4],
            origin_timestamp[5],
            origin_timestamp[6],
            origin_timestamp[7],
            receive_timestamp[0],
            receive_timestamp[1],
            receive_timestamp[2],
            receive_timestamp[3],
            receive_timestamp[4],
            receive_timestamp[5],
            receive_timestamp[6],
            receive_timestamp[7],
            transmit_timestamp[0],
            transmit_timestamp[1],
            transmit_timestamp[2],
            transmit_timestamp[3],
            transmit_timestamp[4],
            transmit_timestamp[5],
            transmit_timestamp[6],
            transmit_timestamp[7],
        ]
    }

    fn poll_message(poll_interval: PollInterval) -> (Self, RequestIdentifier) {
        let mut packet = Self::new();
        let poll_interval = poll_interval;
        packet.poll = poll_interval.as_log();
        packet.mode = NtpAssociationMode::Client;

        // In order to increase the entropy of the transmit timestamp
        // it is just a randomly generated timestamp.
        // We then expect to get it back identically from the remote
        // in the origin field.
        let transmit_timestamp = thread_rng().gen();
        packet.transmit_timestamp = transmit_timestamp;

        (
            packet,
            RequestIdentifier {
                expected_origin_timestamp: transmit_timestamp,
            },
        )
    }

    fn timestamp_response<C: NtpClock>(
        system: &SystemSnapshot,
        input: Self,
        recv_timestamp: NtpTimestamp,
        clock: &C,
    ) -> Self {
        Self {
            mode: NtpAssociationMode::Server,
            stratum: system.stratum,
            origin_timestamp: input.transmit_timestamp,
            receive_timestamp: recv_timestamp,
            reference_id: system.reference_id,
            poll: input.poll,
            precision: system.precision.log2(),
            root_delay: system.root_delay,
            root_dispersion: system.root_dispersion,
            // Timestamp must be last to make it as accurate as possible.
            transmit_timestamp: clock.now().expect("Failed to read time"),
            ..Self::new()
        }
    }

    fn rate_limit_response(packet_from_client: Self) -> Self {
        Self {
            mode: NtpAssociationMode::Server,
            stratum: 0, // indicates a kiss code
            reference_id: ReferenceId::KISS_RATE,
            origin_timestamp: packet_from_client.transmit_timestamp,
            ..Self::new()
        }
    }

    fn deny_response(packet_from_client: Self) -> Self {
        Self {
            mode: NtpAssociationMode::Server,
            stratum: 0, // indicates a kiss code
            reference_id: ReferenceId::KISS_DENY,
            origin_timestamp: packet_from_client.transmit_timestamp,
            ..Self::new()
        }
    }
}

impl NtpPacket {
    pub fn deserialize(data: &[u8; 48]) -> Result<Self, PacketParsingError> {
        let version = (data[0] & 0x38) >> 3;

        match version {
            4 => Ok(NtpPacket {
                header: NtpHeader::V4(NtpHeaderV4::deserialize(data)),
            }),
            _ => Err(PacketParsingError::InvalidVersion(version)),
        }
    }

    pub fn serialize(&self) -> [u8; 48] {
        match self.header {
            NtpHeader::V4(header) => header.serialize(),
        }
    }

    pub fn poll_message(poll_interval: PollInterval) -> (Self, RequestIdentifier) {
        let (header, id) = NtpHeaderV4::poll_message(poll_interval);
        (
            NtpPacket {
                header: NtpHeader::V4(header),
            },
            id,
        )
    }

    pub fn timestamp_response<C: NtpClock>(
        system: &SystemSnapshot,
        input: Self,
        recv_timestamp: NtpTimestamp,
        clock: &C,
    ) -> Self {
        match input.header {
            NtpHeader::V4(header) => NtpPacket {
                header: NtpHeader::V4(NtpHeaderV4::timestamp_response(
                    system,
                    header,
                    recv_timestamp,
                    clock,
                )),
            },
        }
    }

    pub fn rate_limit_response(packet_from_client: Self) -> Self {
        match packet_from_client.header {
            NtpHeader::V4(header) => NtpPacket {
                header: NtpHeader::V4(NtpHeaderV4::rate_limit_response(header)),
            },
        }
    }

    pub fn deny_response(packet_from_client: Self) -> Self {
        match packet_from_client.header {
            NtpHeader::V4(header) => NtpPacket {
                header: NtpHeader::V4(NtpHeaderV4::deny_response(header)),
            },
        }
    }
}

impl NtpPacket {
    pub fn leap(&self) -> NtpLeapIndicator {
        match self.header {
            NtpHeader::V4(header) => header.leap,
        }
    }

    pub fn mode(&self) -> NtpAssociationMode {
        match self.header {
            NtpHeader::V4(header) => header.mode,
        }
    }

    pub fn stratum(&self) -> u8 {
        match self.header {
            NtpHeader::V4(header) => header.stratum,
        }
    }

    pub fn precision(&self) -> i8 {
        match self.header {
            NtpHeader::V4(header) => header.precision,
        }
    }

    pub fn root_delay(&self) -> NtpDuration {
        match self.header {
            NtpHeader::V4(header) => header.root_delay,
        }
    }

    pub fn root_dispersion(&self) -> NtpDuration {
        match self.header {
            NtpHeader::V4(header) => header.root_dispersion,
        }
    }

    pub fn receive_timestamp(&self) -> NtpTimestamp {
        match self.header {
            NtpHeader::V4(header) => header.receive_timestamp,
        }
    }

    pub fn transmit_timestamp(&self) -> NtpTimestamp {
        match self.header {
            NtpHeader::V4(header) => header.transmit_timestamp,
        }
    }

    pub fn reference_id(&self) -> ReferenceId {
        match self.header {
            NtpHeader::V4(header) => header.reference_id,
        }
    }

    pub fn is_kiss(&self) -> bool {
        match self.header {
            NtpHeader::V4(header) => header.stratum == 0,
        }
    }

    pub fn is_kiss_deny(&self) -> bool {
        self.is_kiss() && self.reference_id().is_deny()
    }

    pub fn is_kiss_rate(&self) -> bool {
        self.is_kiss() && self.reference_id().is_rate()
    }

    pub fn is_kiss_rstr(&self) -> bool {
        self.is_kiss() && self.reference_id().is_rstr()
    }

    pub fn valid_server_response(&self, identifier: RequestIdentifier) -> bool {
        match self.header {
            NtpHeader::V4(header) => {
                header.origin_timestamp == identifier.expected_origin_timestamp
            }
        }
    }
}

#[cfg(any(test, feature = "fuzz"))]
impl NtpPacket {
    pub fn test() -> Self {
        Self::default()
    }

    pub fn set_mode(&mut self, mode: NtpAssociationMode) {
        match &mut self.header {
            NtpHeader::V4(ref mut header) => header.mode = mode,
        }
    }

    pub fn set_origin_timestamp(&mut self, timestamp: NtpTimestamp) {
        match &mut self.header {
            NtpHeader::V4(ref mut header) => header.origin_timestamp = timestamp,
        }
    }

    pub fn set_transmit_timestamp(&mut self, timestamp: NtpTimestamp) {
        match &mut self.header {
            NtpHeader::V4(ref mut header) => header.transmit_timestamp = timestamp,
        }
    }

    pub fn set_receive_timestamp(&mut self, timestamp: NtpTimestamp) {
        match &mut self.header {
            NtpHeader::V4(ref mut header) => header.receive_timestamp = timestamp,
        }
    }

    pub fn set_precision(&mut self, precision: i8) {
        match &mut self.header {
            NtpHeader::V4(ref mut header) => header.precision = precision,
        }
    }

    pub fn set_leap(&mut self, leap: NtpLeapIndicator) {
        match &mut self.header {
            NtpHeader::V4(ref mut header) => header.leap = leap,
        }
    }

    pub fn set_stratum(&mut self, stratum: u8) {
        match &mut self.header {
            NtpHeader::V4(ref mut header) => header.stratum = stratum,
        }
    }

    pub fn set_reference_id(&mut self, reference_id: ReferenceId) {
        match &mut self.header {
            NtpHeader::V4(ref mut header) => header.reference_id = reference_id,
        }
    }

    pub fn set_root_delay(&mut self, root_delay: NtpDuration) {
        match &mut self.header {
            NtpHeader::V4(ref mut header) => header.root_delay = root_delay,
        }
    }

    pub fn set_root_dispersion(&mut self, root_dispersion: NtpDuration) {
        match &mut self.header {
            NtpHeader::V4(ref mut header) => header.root_dispersion = root_dispersion,
        }
    }
}

impl Default for NtpPacket {
    fn default() -> Self {
        Self {
            header: NtpHeader::V4(NtpHeaderV4::new()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_bitrep_leap() {
        for i in 0..4u8 {
            let a = NtpLeapIndicator::from_bits(i);
            let b = a.to_bits();
            let c = NtpLeapIndicator::from_bits(b);
            assert_eq!(i, b);
            assert_eq!(a, c);
        }
    }

    #[test]
    fn roundtrip_bitrep_mode() {
        for i in 0..8u8 {
            let a = NtpAssociationMode::from_bits(i);
            let b = a.to_bits();
            let c = NtpAssociationMode::from_bits(b);
            assert_eq!(i, b);
            assert_eq!(a, c);
        }
    }

    #[test]
    fn test_captured_client() {
        let packet = b"\x23\x02\x06\xe8\x00\x00\x03\xff\x00\x00\x03\x7d\x5e\xc6\x9f\x0f\xe5\xf6\x62\x98\x7b\x61\xb9\xaf\xe5\xf6\x63\x66\x7b\x64\x99\x5d\xe5\xf6\x63\x66\x81\x40\x55\x90\xe5\xf6\x63\xa8\x76\x1d\xde\x48";
        let reference = NtpPacket {
            header: NtpHeader::V4(NtpHeaderV4 {
                leap: NtpLeapIndicator::NoWarning,
                mode: NtpAssociationMode::Client,
                stratum: 2,
                poll: 6,
                precision: -24,
                root_delay: NtpDuration::from_fixed_int(1023 << 16),
                root_dispersion: NtpDuration::from_fixed_int(893 << 16),
                reference_id: ReferenceId::from_int(0x5ec69f0f),
                reference_timestamp: NtpTimestamp::from_fixed_int(0xe5f662987b61b9af),
                origin_timestamp: NtpTimestamp::from_fixed_int(0xe5f663667b64995d),
                receive_timestamp: NtpTimestamp::from_fixed_int(0xe5f6636681405590),
                transmit_timestamp: NtpTimestamp::from_fixed_int(0xe5f663a8761dde48),
            }),
        };

        assert_eq!(reference, NtpPacket::deserialize(packet).unwrap());
        assert_eq!(packet[..], reference.serialize()[..]);
    }

    #[test]
    fn test_captured_server() {
        let packet = b"\x24\x02\x06\xe9\x00\x00\x02\x36\x00\x00\x03\xb7\xc0\x35\x67\x6c\xe5\xf6\x61\xfd\x6f\x16\x5f\x03\xe5\xf6\x63\xa8\x76\x19\xef\x40\xe5\xf6\x63\xa8\x79\x8c\x65\x81\xe5\xf6\x63\xa8\x79\x8e\xae\x2b";
        let reference = NtpPacket {
            header: NtpHeader::V4(NtpHeaderV4 {
                leap: NtpLeapIndicator::NoWarning,
                mode: NtpAssociationMode::Server,
                stratum: 2,
                poll: 6,
                precision: -23,
                root_delay: NtpDuration::from_fixed_int(566 << 16),
                root_dispersion: NtpDuration::from_fixed_int(951 << 16),
                reference_id: ReferenceId::from_int(0xc035676c),
                reference_timestamp: NtpTimestamp::from_fixed_int(0xe5f661fd6f165f03),
                origin_timestamp: NtpTimestamp::from_fixed_int(0xe5f663a87619ef40),
                receive_timestamp: NtpTimestamp::from_fixed_int(0xe5f663a8798c6581),
                transmit_timestamp: NtpTimestamp::from_fixed_int(0xe5f663a8798eae2b),
            }),
        };

        assert_eq!(reference, NtpPacket::deserialize(packet).unwrap());
        assert_eq!(packet[..], reference.serialize()[..])
    }

    #[test]
    fn test_version() {
        let packet = b"\x04\x02\x06\xe9\x00\x00\x02\x36\x00\x00\x03\xb7\xc0\x35\x67\x6c\xe5\xf6\x61\xfd\x6f\x16\x5f\x03\xe5\xf6\x63\xa8\x76\x19\xef\x40\xe5\xf6\x63\xa8\x79\x8c\x65\x81\xe5\xf6\x63\xa8\x79\x8e\xae\x2b";
        assert!(NtpPacket::deserialize(packet).is_err());
        let packet = b"\x0B\x02\x06\xe9\x00\x00\x02\x36\x00\x00\x03\xb7\xc0\x35\x67\x6c\xe5\xf6\x61\xfd\x6f\x16\x5f\x03\xe5\xf6\x63\xa8\x76\x19\xef\x40\xe5\xf6\x63\xa8\x79\x8c\x65\x81\xe5\xf6\x63\xa8\x79\x8e\xae\x2b";
        assert!(NtpPacket::deserialize(packet).is_err());
        let packet = b"\x14\x02\x06\xe9\x00\x00\x02\x36\x00\x00\x03\xb7\xc0\x35\x67\x6c\xe5\xf6\x61\xfd\x6f\x16\x5f\x03\xe5\xf6\x63\xa8\x76\x19\xef\x40\xe5\xf6\x63\xa8\x79\x8c\x65\x81\xe5\xf6\x63\xa8\x79\x8e\xae\x2b";
        assert!(NtpPacket::deserialize(packet).is_err());
        let packet = b"\x1B\x02\x06\xe9\x00\x00\x02\x36\x00\x00\x03\xb7\xc0\x35\x67\x6c\xe5\xf6\x61\xfd\x6f\x16\x5f\x03\xe5\xf6\x63\xa8\x76\x19\xef\x40\xe5\xf6\x63\xa8\x79\x8c\x65\x81\xe5\xf6\x63\xa8\x79\x8e\xae\x2b";
        assert!(NtpPacket::deserialize(packet).is_err());
        let packet = b"\x2B\x02\x06\xe9\x00\x00\x02\x36\x00\x00\x03\xb7\xc0\x35\x67\x6c\xe5\xf6\x61\xfd\x6f\x16\x5f\x03\xe5\xf6\x63\xa8\x76\x19\xef\x40\xe5\xf6\x63\xa8\x79\x8c\x65\x81\xe5\xf6\x63\xa8\x79\x8e\xae\x2b";
        assert!(NtpPacket::deserialize(packet).is_err());
        let packet = b"\x34\x02\x06\xe9\x00\x00\x02\x36\x00\x00\x03\xb7\xc0\x35\x67\x6c\xe5\xf6\x61\xfd\x6f\x16\x5f\x03\xe5\xf6\x63\xa8\x76\x19\xef\x40\xe5\xf6\x63\xa8\x79\x8c\x65\x81\xe5\xf6\x63\xa8\x79\x8e\xae\x2b";
        assert!(NtpPacket::deserialize(packet).is_err());
        let packet = b"\x3B\x02\x06\xe9\x00\x00\x02\x36\x00\x00\x03\xb7\xc0\x35\x67\x6c\xe5\xf6\x61\xfd\x6f\x16\x5f\x03\xe5\xf6\x63\xa8\x76\x19\xef\x40\xe5\xf6\x63\xa8\x79\x8c\x65\x81\xe5\xf6\x63\xa8\x79\x8e\xae\x2b";
        assert!(NtpPacket::deserialize(packet).is_err());
    }

    #[test]
    fn test_packed_flags() {
        let base = b"\x24\x02\x06\xe9\x00\x00\x02\x36\x00\x00\x03\xb7\xc0\x35\x67\x6c\xe5\xf6\x61\xfd\x6f\x16\x5f\x03\xe5\xf6\x63\xa8\x76\x19\xef\x40\xe5\xf6\x63\xa8\x79\x8c\x65\x81\xe5\xf6\x63\xa8\x79\x8e\xae\x2b".to_owned();
        let base_structured = NtpPacket::deserialize(&base).unwrap();

        for leap_type in 0..3 {
            for mode in 0..8 {
                let mut header = base_structured.clone();
                header.set_leap(NtpLeapIndicator::from_bits(leap_type));
                header.set_mode(NtpAssociationMode::from_bits(mode));

                let data = header.serialize();
                let copy = NtpPacket::deserialize(&data).unwrap();
                assert_eq!(header, copy);
            }
        }

        for i in 0..=0xFF {
            let mut packet = base;
            packet[0] = i;

            if let Ok(a) = NtpPacket::deserialize(&packet) {
                let b = a.serialize();
                assert_eq!(packet, b);
            }
        }
    }
}
