use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    str::FromStr,
};

use super::cerr;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{lookup_phc, ChangeDetector};

// NOTE: this detection logic is not sharable with macos!
#[cfg(target_os = "freebsd")]
mod freebsd;
#[cfg(target_os = "freebsd")]
pub use freebsd::{lookup_phc, ChangeDetector};

#[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
mod fallback;
#[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
pub use fallback::{lookup_phc, ChangeDetector};

pub fn interfaces() -> std::io::Result<HashMap<InterfaceName, InterfaceData>> {
    let mut elements = HashMap::default();

    for data in InterfaceIterator::new()? {
        let current: &mut InterfaceData = elements.entry(data.name).or_default();

        current.socket_addrs.extend(data.socket_addr);
        assert!(!(current.mac.is_some() && data.mac.is_some()));
        current.mac = current.mac.or(data.mac);
    }

    Ok(elements)
}

#[derive(Default, Debug)]
pub struct InterfaceData {
    socket_addrs: Vec<SocketAddr>,
    mac: Option<[u8; 6]>,
}

impl InterfaceData {
    pub fn has_ip_addr(&self, address: IpAddr) -> bool {
        self.socket_addrs
            .iter()
            .any(|socket_addr| socket_addr.ip() == address)
    }

    pub fn ips(&self) -> impl Iterator<Item = IpAddr> + '_ {
        self.socket_addrs.iter().map(|a| a.ip())
    }

    pub fn mac(&self) -> Option<[u8; 6]> {
        self.mac
    }
}

// Invariants:
// self.base always contains a pointer received from libc::getifaddrs that is not NULL. The region pointed to is never modified in rust code.
// self.next always contains either a pointer pointing to a valid ifaddr received from libc::getifaddrs or null.
//
// These invariants are setup by InterfaceIterator::new and guaranteed by drop and next, which are the only places these pointers are used.
struct InterfaceIterator {
    base: *mut libc::ifaddrs,
    next: *const libc::ifaddrs,
}

impl InterfaceIterator {
    pub fn new() -> std::io::Result<Self> {
        let mut addrs: *mut libc::ifaddrs = std::ptr::null_mut();

        // Safety:
        // addrs lives for the duration of the call to getifaddrs.
        //
        // Invariant preservation:
        // we validate that the received address is not null, and
        // by the guarantees from getifaddrs points to a valid
        // ifaddr returned from getifaddrs
        unsafe {
            cerr(libc::getifaddrs(&mut addrs))?;

            assert!(!addrs.is_null());

            Ok(Self {
                base: addrs,
                next: addrs,
            })
        }
    }
}

impl Drop for InterfaceIterator {
    fn drop(&mut self) {
        // Safety:
        // By the invariants, self.base is guaranteed to point to a memory region allocated by getifaddrs
        unsafe { libc::freeifaddrs(self.base) };
    }
}

struct InterfaceDataInternal {
    name: InterfaceName,
    mac: Option<[u8; 6]>,
    socket_addr: Option<SocketAddr>,
}

impl Iterator for InterfaceIterator {
    type Item = InterfaceDataInternal;

    fn next(&mut self) -> Option<<Self as Iterator>::Item> {
        // Safety:
        // By the invariants, self.next is guaranteed to be a valid pointer to an ifaddrs struct or null.
        let ifaddr = unsafe { self.next.as_ref() }?;

        // Invariant preservation
        // By the guarantees given by getifaddrs, ifaddr.ifa_next is either null or points to a valid
        // ifaddr.
        self.next = ifaddr.ifa_next;

        // Safety:
        // getifaddrs guarantees that ifa_name is not null and points to a valid C string.
        let ifname = unsafe { std::ffi::CStr::from_ptr(ifaddr.ifa_name) };
        let name = match std::str::from_utf8(ifname.to_bytes()) {
            Err(_) => unreachable!("interface names must be ascii"),
            Ok(name) => InterfaceName::from_str(name).expect("name from os"),
        };

        // Safety:
        // getifaddrs guarantees that ifa_addr either points to a valid address or is NULL.
        let family = unsafe { ifaddr.ifa_addr.as_ref() }.map(|a| a.sa_family);

        #[allow(unused)]
        let mac: Option<[u8; 6]> = None;

        #[cfg(target_os = "linux")]
        // Safety: getifaddrs ensures that, if an address is present, it is valid. A valid address
        // of type AF_PACKET is always reinterpret castable to sockaddr_ll, and we know an address
        // is present since family is not None
        let mac = if family == Some(libc::AF_PACKET as _) {
            let sockaddr_ll: libc::sockaddr_ll =
                unsafe { std::ptr::read_unaligned(ifaddr.ifa_addr as *const _) };

            Some([
                sockaddr_ll.sll_addr[0],
                sockaddr_ll.sll_addr[1],
                sockaddr_ll.sll_addr[2],
                sockaddr_ll.sll_addr[3],
                sockaddr_ll.sll_addr[4],
                sockaddr_ll.sll_addr[5],
            ])
        } else {
            None
        };

        #[cfg(any(target_os = "freebsd", target_os = "macos"))]
        let mac = if family == Some(libc::AF_LINK as _) {
            // Safety: getifaddrs ensures that, if an address is present, it is valid. A valid address
            // of type AF_LINK is always reinterpret castable to sockaddr_ll, and we know an address
            // is present since family is not None
            let sockaddr_dl: libc::sockaddr_dl =
                unsafe { std::ptr::read_unaligned(ifaddr.ifa_addr as *const _) };

            // From sys/net/if_types.h in freebsd:
            const IFT_ETHER: u8 = 0x6;

            if sockaddr_dl.sdl_type == IFT_ETHER
                && sockaddr_dl.sdl_nlen.saturating_add(6) as usize <= sockaddr_dl.sdl_data.len()
            {
                Some([
                    sockaddr_dl.sdl_data[sockaddr_dl.sdl_nlen as usize] as u8,
                    sockaddr_dl.sdl_data[sockaddr_dl.sdl_nlen as usize + 1] as u8,
                    sockaddr_dl.sdl_data[sockaddr_dl.sdl_nlen as usize + 2] as u8,
                    sockaddr_dl.sdl_data[sockaddr_dl.sdl_nlen as usize + 3] as u8,
                    sockaddr_dl.sdl_data[sockaddr_dl.sdl_nlen as usize + 4] as u8,
                    sockaddr_dl.sdl_data[sockaddr_dl.sdl_nlen as usize + 5] as u8,
                ])
            } else {
                None
            }
        } else {
            None
        };

        // Safety: ifaddr.ifa_addr is always either NULL, or by the guarantees of getifaddrs, points to a valid address.
        let socket_addr = unsafe { sockaddr_to_socket_addr(ifaddr.ifa_addr) };

        let data = InterfaceDataInternal {
            name,
            mac,
            socket_addr,
        };

        Some(data)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct InterfaceName {
    bytes: [u8; libc::IFNAMSIZ],
}

impl InterfaceName {
    #[cfg(all(test, target_os = "linux"))]
    pub const LOOPBACK: Self = Self {
        bytes: *b"lo\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
    };

    #[cfg(all(test, any(target_os = "freebsd", target_os = "macos")))]
    pub const LOOPBACK: Self = Self {
        bytes: *b"lo0\0\0\0\0\0\0\0\0\0\0\0\0\0",
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
        let matches_inferface = |interface: &InterfaceDataInternal| match interface.socket_addr {
            None => false,
            Some(address) => address.ip() == local_addr.ip(),
        };

        match InterfaceIterator::new()?.find(matches_inferface) {
            Some(interface) => Ok(Some(interface.name)),
            None => Ok(None),
        }
    }

    pub fn get_index(&self) -> Option<libc::c_uint> {
        // # SAFETY
        //
        // self lives for the duration of the call, and is null terminated.
        match unsafe { libc::if_nametoindex(self.as_cstr().as_ptr()) } {
            0 => None,
            n => Some(n),
        }
    }

    /// Do a lookup for the Physical Hardware Clock index for this interface.
    pub fn lookup_phc(&self) -> Option<u32> {
        lookup_phc(*self)
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

impl std::str::FromStr for InterfaceName {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut bytes = [0; libc::IFNAMSIZ];

        // >= so that we always retain a NUL byte at the end
        if s.len() >= bytes.len() {
            return Err(());
        }

        if s.is_empty() {
            // this causes problems down the line when giving the interface name to tokio
            return Err(());
        }

        let mut it = s.bytes();
        bytes = bytes.map(|_| it.next().unwrap_or_default());

        Ok(Self { bytes })
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for InterfaceName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        FromStr::from_str(&s).map_err(|_| serde::de::Error::custom("invalid interface name"))
    }
}

/// Convert a libc::sockaddr to a rust std::net::SocketAddr
///
/// # Safety
///
/// This function assumes that sockaddr is either NULL or points to a valid address.
unsafe fn sockaddr_to_socket_addr(sockaddr: *const libc::sockaddr) -> Option<SocketAddr> {
    // Most (but not all) of the fields in a socket addr are in network byte
    // ordering. As such, when doing conversions here, we should start from the
    // NATIVE byte representation, as this will actualy be the big-endian
    // representation of the underlying value regardless of platform.

    // Check for null pointers
    if sockaddr.is_null() {
        return None;
    }

    // Safety: by the previous check, sockaddr is not NULL and hence points to a valid address
    match unsafe { (*sockaddr).sa_family as libc::c_int } {
        libc::AF_INET => {
            // SAFETY: we cast from a libc::sockaddr (alignment 2) to a libc::sockaddr_in (alignment 4)
            // that means that the pointer is now potentially unaligned. We must used read_unaligned!
            // However, the rest of the cast is safe as a valid AF_INET address is always reinterpret castable
            // as a sockaddr_in
            let inaddr: libc::sockaddr_in =
                unsafe { std::ptr::read_unaligned(sockaddr as *const libc::sockaddr_in) };

            let socketaddr = std::net::SocketAddrV4::new(
                std::net::Ipv4Addr::from(inaddr.sin_addr.s_addr.to_ne_bytes()),
                u16::from_be_bytes(inaddr.sin_port.to_ne_bytes()),
            );

            Some(std::net::SocketAddr::V4(socketaddr))
        }
        libc::AF_INET6 => {
            // SAFETY: we cast from a libc::sockaddr (alignment 2) to a libc::sockaddr_in6 (alignment 4)
            // that means that the pointer is now potentially unaligned. We must used read_unaligned!
            // However, the cast is safe as a valid AF_INET6 address is always reinterpret catable as a sockaddr_in6
            let inaddr: libc::sockaddr_in6 =
                unsafe { std::ptr::read_unaligned(sockaddr as *const libc::sockaddr_in6) };

            // Safety:
            // sin_addr lives for the duration fo the call and matches type
            let sin_addr = inaddr.sin6_addr.s6_addr;
            let segment_bytes: [u8; 16] =
                unsafe { std::ptr::read_unaligned(&sin_addr as *const _ as *const _) };

            let socketaddr = std::net::SocketAddrV6::new(
                std::net::Ipv6Addr::from(segment_bytes),
                u16::from_be_bytes(inaddr.sin6_port.to_ne_bytes()),
                inaddr.sin6_flowinfo, /* NOTE: Despite network byte order, no conversion is needed (see https://github.com/rust-lang/rust/issues/101605) */
                inaddr.sin6_scope_id,
            );

            Some(std::net::SocketAddr::V6(socketaddr))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn interface_name_from_string() {
        assert!(InterfaceName::from_str("").is_err());
        assert!(InterfaceName::from_str("a string that is too long").is_err());

        let input = "enp0s31f6";
        assert_eq!(InterfaceName::from_str(input).unwrap().as_str(), input);

        let ifr_name = (*b"enp0s31f6\0\0\0\0\0\0\0").map(|b| b as libc::c_char);
        assert_eq!(
            InterfaceName::from_str(input).unwrap().to_ifr_name(),
            ifr_name
        );
    }

    #[test]
    fn test_mac_address_iterator() {
        let v: Vec<_> = InterfaceIterator::new()
            .unwrap()
            .filter_map(|d| d.mac)
            .collect();

        assert!(!v.is_empty());
    }

    #[test]
    fn test_interface_name_iterator() {
        let v: Vec<_> = InterfaceIterator::new().unwrap().map(|d| d.name).collect();

        assert!(v.contains(&InterfaceName::LOOPBACK));
    }

    #[test]
    fn test_socket_addr_iterator() {
        let v: Vec<_> = InterfaceIterator::new()
            .unwrap()
            .filter_map(|d| d.socket_addr)
            .collect();

        let localhost_0 = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));

        assert!(v.contains(&localhost_0));
    }

    #[test]
    fn interface_index_ipv4() {
        assert!(InterfaceName::LOOPBACK.get_index().is_some());
    }

    #[test]
    fn interface_index_ipv6() {
        assert!(InterfaceName::LOOPBACK.get_index().is_some());
    }

    #[test]
    fn interface_index_invalid() {
        assert!(InterfaceName::INVALID.get_index().is_none());
    }
}
