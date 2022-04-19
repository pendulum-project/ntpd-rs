use std::net::IpAddr;

use md5::{Digest, Md5};

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct ReferenceId(u32);

impl ReferenceId {
    // Note: Names chosen to match the identifiers given in rfc5905
    const KISS_DENY: u32 = 0x44454E59;
    const KISS_RATE: u32 = 0x52415445;
    const KISS_RSTR: u32 = 0x52535452;

    pub fn from_ip(addr: IpAddr) -> ReferenceId {
        match addr {
            IpAddr::V4(addr) => ReferenceId(u32::from_be_bytes(addr.octets())),
            IpAddr::V6(addr) => ReferenceId(u32::from_be_bytes(
                Md5::digest(addr.octets())[0..4].try_into().unwrap(),
            )),
        }
    }

    pub(crate) fn from_int(value: u32) -> ReferenceId {
        ReferenceId(value)
    }

    pub(crate) fn is_deny(&self) -> bool {
        self.0 == Self::KISS_DENY
    }

    pub(crate) fn is_rate(&self) -> bool {
        self.0 == Self::KISS_RATE
    }

    pub(crate) fn is_rstr(&self) -> bool {
        self.0 == Self::KISS_RSTR
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

        // TODO: Generate and add a testcase for ipv6 adresses once
        // we have access to an ipv6 network.
    }
}
