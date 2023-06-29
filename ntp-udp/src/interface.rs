//! taken from https://docs.rs/nix/latest/src/nix/ifaddrs.rs.html
//! stripped to just the parts that we need.
//!
//! Query network interface addresses
//!
//! Uses the Linux and/or BSD specific function `getifaddrs` to query the list
//! of interfaces and their associated addresses.

use std::iter::Iterator;
use std::net::SocketAddr;
use std::option::Option;

use crate::raw_socket::interface_iterator::InterfaceIterator;

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct InterfaceName {
    bytes: [u8; libc::IFNAMSIZ],
}

impl std::ops::Deref for InterfaceName {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.bytes.as_slice()
    }
}

impl<'de> serde::Deserialize<'de> for InterfaceName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use std::str::FromStr;
        use InterfaceNameParseError::*;

        let name: String = serde::Deserialize::deserialize(deserializer)?;

        match Self::from_str(&name) {
            Ok(v) => Ok(v),
            Err(Empty) => Err(serde::de::Error::custom("interface name empty")),
            Err(TooLong) => Err(serde::de::Error::custom("interface name too long")),
        }
    }
}

#[derive(Debug)]
pub enum InterfaceNameParseError {
    Empty,
    TooLong,
}

impl std::str::FromStr for InterfaceName {
    type Err = InterfaceNameParseError;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        if name.is_empty() {
            return Err(InterfaceNameParseError::Empty);
        }

        let mut it = name.bytes();
        let bytes = std::array::from_fn(|_| it.next().unwrap_or_default());

        if it.next().is_some() {
            Err(InterfaceNameParseError::TooLong)
        } else {
            Ok(InterfaceName { bytes })
        }
    }
}

impl InterfaceName {
    pub const DEFAULT: Option<Self> = None;

    #[cfg(test)]
    pub const LOOPBACK: Self = Self {
        bytes: *b"lo\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
    };

    #[cfg(test)]
    pub const INVALID: Self = Self {
        bytes: *b"123412341234123\0",
    };

    pub fn as_str(&self) -> &str {
        std::str::from_utf8(self.bytes.as_slice())
            .unwrap_or_default()
            .trim_end_matches('\0')
    }

    pub fn as_cstr(&self) -> &std::ffi::CStr {
        // TODO: in rust 1.69.0, use
        // std::ffi::CStr::from_bytes_until_nul(&self.bytes[..]).unwrap()

        // it is an invariant of InterfaceName that the bytes are null-terminated
        let first_null = self.bytes.iter().position(|b| *b == 0).unwrap();
        std::ffi::CStr::from_bytes_with_nul(&self.bytes[..=first_null]).unwrap()
    }

    pub fn to_ifr_name(self) -> [libc::c_char; libc::IFNAMSIZ] {
        let mut it = self.bytes.iter().copied();
        [0; libc::IFNAMSIZ].map(|_| it.next().unwrap_or(0) as libc::c_char)
    }

    pub fn from_socket_addr(local_addr: SocketAddr) -> std::io::Result<Option<Self>> {
        let matches_inferface = |interface: &InterfaceData| match interface.socket_addr {
            None => false,
            Some(address) => address.ip() == local_addr.ip(),
        };

        match InterfaceIterator::new()?.find(matches_inferface) {
            Some(interface) => Ok(Some(interface.name)),
            None => Ok(None),
        }
    }
}

impl std::fmt::Debug for InterfaceName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("InterfaceName")
            .field(&self.as_str())
            .finish()
    }
}

impl std::fmt::Display for InterfaceName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.as_str().fmt(f)
    }
}

pub fn sockaddr_storage_to_socket_addr(
    sockaddr_storage: &libc::sockaddr_storage,
) -> Option<SocketAddr> {
    // Safety:
    //
    // sockaddr_storage always has enough space to store either a sockaddr_in or sockaddr_in6
    unsafe { sockaddr_to_socket_addr(sockaddr_storage as *const _ as *const libc::sockaddr) }
}

/// Convert a libc::sockaddr to a rust std::net::SocketAddr
///
/// # Safety
///
/// According to the posix standard, `sockaddr` does not have a defined size: the size depends on
/// the value of the `ss_family` field. We assume this to be correct.
///
/// In practice, types in rust/c need a statically-known stack size, so they pick some value. In
/// practice it can be (and is) larger than the `sizeof<libc::sockaddr>` value.
pub unsafe fn sockaddr_to_socket_addr(sockaddr: *const libc::sockaddr) -> Option<SocketAddr> {
    // Most (but not all) of the fields in a socket addr are in network byte ordering.
    // As such, when doing conversions here, we should start from the NATIVE
    // byte representation, as this will actualy be the big-endian representation
    // of the underlying value regardless of platform.
    match unsafe { (*sockaddr).sa_family as libc::c_int } {
        libc::AF_INET => {
            let inaddr: libc::sockaddr_in = unsafe { *(sockaddr as *const libc::sockaddr_in) };

            let socketaddr = std::net::SocketAddrV4::new(
                std::net::Ipv4Addr::from(inaddr.sin_addr.s_addr.to_ne_bytes()),
                u16::from_be_bytes(inaddr.sin_port.to_ne_bytes()),
            );

            Some(std::net::SocketAddr::V4(socketaddr))
        }
        libc::AF_INET6 => {
            let inaddr: libc::sockaddr_in6 = unsafe { *(sockaddr as *const libc::sockaddr_in6) };

            let sin_addr = inaddr.sin6_addr.s6_addr;
            let segment_bytes: [u8; 16] =
                unsafe { std::ptr::read_unaligned(&sin_addr as *const _ as *const _) };

            let socketaddr = std::net::SocketAddrV6::new(
                std::net::Ipv6Addr::from(segment_bytes),
                u16::from_be_bytes(inaddr.sin6_port.to_ne_bytes()),
                inaddr.sin6_flowinfo, // NOTE: Despite network byte order, no conversion is needed (see https://github.com/rust-lang/rust/issues/101605)
                inaddr.sin6_scope_id,
            );

            Some(std::net::SocketAddr::V6(socketaddr))
        }
        _ => None,
    }
}

pub struct InterfaceData {
    pub name: InterfaceName,
    pub mac: Option<[u8; 6]>,
    pub socket_addr: Option<SocketAddr>,
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use super::*;

    #[test]
    fn find_interface() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:8014").unwrap();
        let name = InterfaceName::from_socket_addr(socket.local_addr().unwrap()).unwrap();

        assert!(name.is_some());
    }

    #[test]
    fn find_interface_ipv6() {
        let socket = std::net::UdpSocket::bind("::1:8015").unwrap();
        let name = InterfaceName::from_socket_addr(socket.local_addr().unwrap()).unwrap();

        assert!(name.is_some());
    }

    #[test]
    fn decode_socket_addr_v4() {
        let sockaddr = libc::sockaddr {
            sa_family: libc::AF_INET as libc::sa_family_t,
            sa_data: [0, 0, 127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0],
            #[cfg(any(target_os = "macos", target_os = "freebsd"))]
            sa_len: 14u8,
        };

        let socket_addr = unsafe { sockaddr_to_socket_addr(&sockaddr) }.unwrap();

        assert_eq!(
            socket_addr,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0)
        );

        //

        let sockaddr = libc::sockaddr {
            sa_family: libc::AF_INET as libc::sa_family_t,
            sa_data: [0, 42, -84 as _, 23, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0],
            #[cfg(any(target_os = "macos", target_os = "freebsd"))]
            sa_len: 14u8,
        };

        let socket_addr = unsafe { sockaddr_to_socket_addr(&sockaddr) }.unwrap();

        assert_eq!(
            socket_addr,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 23, 0, 1)), 42)
        );
    }

    #[test]
    fn decode_socket_addr_v6() {
        let raw = [
            0x20, 0x01, 0x08, 0x88, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x02,
        ];

        let sockaddr = libc::sockaddr_in6 {
            sin6_family: libc::AF_INET6 as libc::sa_family_t,
            sin6_port: u16::from_ne_bytes([0, 32]),
            sin6_flowinfo: 0,
            sin6_addr: libc::in6_addr { s6_addr: raw },
            sin6_scope_id: 0,
            #[cfg(any(target_os = "macos", target_os = "freebsd"))]
            sin6_len: 14u8,
        };

        let socket_addr =
            unsafe { sockaddr_to_socket_addr(&sockaddr as *const _ as *const _) }.unwrap();

        assert_eq!(socket_addr, "[2001:888:0:2::2]:32".parse().unwrap());
    }
}
