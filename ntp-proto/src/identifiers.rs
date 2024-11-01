use std::net::IpAddr;

use md5::{Digest, Md5};
use serde::{Deserialize, Serialize};

#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReferenceId(u32);

impl ReferenceId {
    // Note: Names chosen to match the identifiers given in rfc5905
    pub const KISS_DENY: ReferenceId = ReferenceId(u32::from_be_bytes(*b"DENY"));
    pub const KISS_RATE: ReferenceId = ReferenceId(u32::from_be_bytes(*b"RATE"));
    pub const KISS_RSTR: ReferenceId = ReferenceId(u32::from_be_bytes(*b"RSTR"));
    pub const NONE: ReferenceId = ReferenceId(u32::from_be_bytes(*b"XNON"));
    pub const SOCK: ReferenceId = ReferenceId(u32::from_be_bytes(*b"SOCK"));

    // Network Time Security (NTS) negative-acknowledgment (NAK), from rfc8915
    pub const KISS_NTSN: ReferenceId = ReferenceId(u32::from_be_bytes(*b"NTSN"));

    pub fn from_ip(addr: IpAddr) -> ReferenceId {
        match addr {
            IpAddr::V4(addr) => ReferenceId(u32::from_be_bytes(addr.octets())),
            IpAddr::V6(addr) => ReferenceId(u32::from_be_bytes(
                Md5::digest(addr.octets())[0..4].try_into().unwrap(),
            )),
        }
    }

    pub(crate) const fn from_int(value: u32) -> ReferenceId {
        ReferenceId(value)
    }

    pub(crate) fn is_deny(&self) -> bool {
        *self == Self::KISS_DENY
    }

    pub(crate) fn is_rate(&self) -> bool {
        *self == Self::KISS_RATE
    }

    pub(crate) fn is_rstr(&self) -> bool {
        *self == Self::KISS_RSTR
    }

    pub(crate) fn is_ntsn(&self) -> bool {
        *self == Self::KISS_NTSN
    }

    pub(crate) fn to_bytes(self) -> [u8; 4] {
        self.0.to_be_bytes()
    }

    pub(crate) fn from_bytes(bits: [u8; 4]) -> ReferenceId {
        ReferenceId(u32::from_be_bytes(bits))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn referenceid_serialization_roundtrip() {
        let a = [12, 34, 56, 78];
        let b = ReferenceId::from_bytes(a);
        let c = b.to_bytes();
        let d = ReferenceId::from_bytes(c);
        assert_eq!(a, c);
        assert_eq!(b, d);
    }

    #[test]
    fn referenceid_kiss_codes() {
        let a = [b'R', b'A', b'T', b'E'];
        let b = ReferenceId::from_bytes(a);
        assert!(b.is_rate());

        let a = [b'R', b'S', b'T', b'R'];
        let b = ReferenceId::from_bytes(a);
        assert!(b.is_rstr());

        let a = [b'D', b'E', b'N', b'Y'];
        let b = ReferenceId::from_bytes(a);
        assert!(b.is_deny());
    }

    #[test]
    fn referenceid_from_ipv4() {
        let ip: IpAddr = "12.34.56.78".parse().unwrap();
        let rep = [12, 34, 56, 78];
        let a = ReferenceId::from_ip(ip);
        let b = ReferenceId::from_bytes(rep);
        assert_eq!(a, b);

        // TODO: Generate and add a testcase for ipv6 addresses once
        // we have access to an ipv6 network.
    }
}
