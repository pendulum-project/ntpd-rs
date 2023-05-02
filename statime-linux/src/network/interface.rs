use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

/// Turn a C failure (-1 is returned) into a rust Result
pub(crate) fn cerr(t: libc::c_int) -> std::io::Result<libc::c_int> {
    match t {
        -1 => Err(std::io::Error::last_os_error()),
        _ => Ok(t),
    }
}

pub struct InterfaceIterator {
    base: *mut libc::ifaddrs,
    next: *mut libc::ifaddrs,
}

impl InterfaceIterator {
    pub fn new() -> std::io::Result<Self> {
        let mut addrs = core::mem::MaybeUninit::<*mut libc::ifaddrs>::uninit();

        unsafe {
            cerr(libc::getifaddrs(addrs.as_mut_ptr()))?;

            Ok(Self {
                base: addrs.assume_init(),
                next: addrs.assume_init(),
            })
        }
    }
}

impl Drop for InterfaceIterator {
    fn drop(&mut self) {
        unsafe { libc::freeifaddrs(self.base) };
    }
}

pub struct InterfaceData {
    pub name: InterfaceName,
    pub mac: Option<[u8; 6]>,
    pub socket_addr: Option<SocketAddr>,
}

impl InterfaceData {
    pub fn has_ip_addr(&self, address: IpAddr) -> bool {
        match self.socket_addr {
            None => false,
            Some(socket_addr) => socket_addr.ip() == address,
        }
    }
}

impl Iterator for InterfaceIterator {
    type Item = InterfaceData;

    fn next(&mut self) -> Option<<Self as Iterator>::Item> {
        let ifaddr = unsafe { self.next.as_ref() }?;

        self.next = ifaddr.ifa_next;

        let ifname = unsafe { std::ffi::CStr::from_ptr(ifaddr.ifa_name) };
        let name = match std::str::from_utf8(ifname.to_bytes()) {
            Err(_) => unreachable!("interface names must be ascii"),
            Ok(name) => InterfaceName::from_str(name).expect("name from os"),
        };

        let family = unsafe { (*ifaddr.ifa_addr).sa_family };

        let mac = if family as i32 == libc::AF_PACKET {
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

        let socket_addr = unsafe { sockaddr_to_socket_addr(ifaddr.ifa_addr) };

        let data = InterfaceData {
            name,
            mac,
            socket_addr,
        };

        Some(data)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct InterfaceName {
    bytes: [u8; libc::IFNAMSIZ],
}

impl InterfaceName {
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
        // it is an invariant of InterfaceName that the bytes are null-terminated
        std::ffi::CStr::from_bytes_until_nul(&self.bytes[..]).unwrap()
    }

    pub fn to_ifr_name(self) -> [i8; libc::IFNAMSIZ] {
        let mut it = self.bytes.iter().copied();
        [0; libc::IFNAMSIZ].map(|_| it.next().unwrap_or(0) as i8)
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

/// Convert a libc::sockaddr to a rust std::net::SocketAddr
///
/// # Safety
///
/// According to the posix standard, `sockaddr` does not have a defined size: the size depends on
/// the value of the `ss_family` field. We assume this to be correct.
///
/// In practice, types in rust/c need a statically-known stack size, so they pick some value. In
/// practice it can be (and is) larger than the `sizeof<libc::sockaddr>` value.
unsafe fn sockaddr_to_socket_addr(sockaddr: *const libc::sockaddr) -> Option<SocketAddr> {
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

pub fn sockaddr_storage_to_socket_addr(
    sockaddr_storage: &libc::sockaddr_storage,
) -> Option<SocketAddr> {
    // Safety:
    //
    // sockaddr_storage always has enough space to store either a sockaddr_in or sockaddr_in6
    unsafe { sockaddr_to_socket_addr(sockaddr_storage as *const _ as *const libc::sockaddr) }
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

        let ifr_name = (*b"enp0s31f6\0\0\0\0\0\0\0").map(|b| b as i8);
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
}
