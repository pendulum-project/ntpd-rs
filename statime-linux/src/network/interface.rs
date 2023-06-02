use std::{
    net::{IpAddr, SocketAddr},
    str::FromStr,
};

use super::cerr;

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

#[derive(Debug, Clone)]
pub struct InterfaceDescriptor {
    pub interface_name: Option<InterfaceName>,
    pub mode: LinuxNetworkMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxNetworkMode {
    Ipv4,
    Ipv6,
}

impl LinuxNetworkMode {
    pub fn unspecified_ip_addr(&self) -> IpAddr {
        match self {
            LinuxNetworkMode::Ipv4 => IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            LinuxNetworkMode::Ipv6 => IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
        }
    }
}

fn cannot_iterate_interfaces() -> std::io::Error {
    let msg = "Could not iterate over interfaces";
    std::io::Error::new(std::io::ErrorKind::Other, msg)
}

fn interface_does_not_exist() -> std::io::Error {
    let msg = "The specified interface does not exist";
    std::io::Error::new(std::io::ErrorKind::Other, msg)
}

impl InterfaceDescriptor {
    pub fn get_index(&self) -> Option<u32> {
        let name = self.interface_name.as_ref()?;

        // # SAFETY
        //
        // The pointer is valid and null-terminated
        match unsafe { libc::if_nametoindex(name.as_cstr().as_ptr()) } {
            0 => None,
            n => Some(n),
        }
    }

    pub fn get_address(&self) -> std::io::Result<IpAddr> {
        if let Some(name) = self.interface_name {
            let interfaces = InterfaceIterator::new().map_err(|_| cannot_iterate_interfaces())?;

            interfaces
                .filter(|i| name == i.name)
                .filter_map(|i| i.socket_addr)
                .map(|socket_addr| socket_addr.ip())
                .find(|ip| match self.mode {
                    LinuxNetworkMode::Ipv4 => ip.is_ipv4(),
                    LinuxNetworkMode::Ipv6 => ip.is_ipv6(),
                })
                .ok_or(interface_does_not_exist())
        } else {
            Ok(self.mode.unspecified_ip_addr())
        }
    }
}

impl FromStr for InterfaceDescriptor {
    type Err = std::io::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut interfaces = match InterfaceIterator::new() {
            Ok(a) => a,
            Err(_) => return Err(cannot_iterate_interfaces()),
        };

        match std::net::IpAddr::from_str(s) {
            Ok(addr) => {
                if addr.is_unspecified() {
                    return Ok(InterfaceDescriptor {
                        interface_name: None,
                        mode: match addr {
                            IpAddr::V4(_) => LinuxNetworkMode::Ipv4,
                            IpAddr::V6(_) => LinuxNetworkMode::Ipv6,
                        },
                    });
                }

                interfaces
                    .find(|data| data.has_ip_addr(addr))
                    .map(|data| InterfaceDescriptor {
                        interface_name: Some(data.name),
                        mode: LinuxNetworkMode::Ipv4,
                    })
                    .ok_or(interface_does_not_exist())
            }
            Err(_) => {
                if interfaces.any(|if_data| if_data.name.as_str() == s) {
                    // the interface name came straight from the OS, so it must be valid
                    let interface_name = InterfaceName::from_str(s).unwrap();

                    Ok(InterfaceDescriptor {
                        interface_name: Some(interface_name),
                        mode: LinuxNetworkMode::Ipv4,
                    })
                } else {
                    Err(interface_does_not_exist())
                }
            }
        }
    }
}

/// Convert a libc::sockaddr to a rust std::net::SocketAddr
///
/// # Safety
///
/// According to the posix standard, `sockaddr` does not have a defined size:
/// the size depends on the value of the `ss_family` field. We assume this to be
/// correct.
///
/// In practice, types in rust/c need a statically-known stack size, so they
/// pick some value. In practice it can be (and is) larger than the
/// `sizeof<libc::sockaddr>` value.
unsafe fn sockaddr_to_socket_addr(sockaddr: *const libc::sockaddr) -> Option<SocketAddr> {
    // Most (but not all) of the fields in a socket addr are in network byte
    // ordering. As such, when doing conversions here, we should start from the
    // NATIVE byte representation, as this will actualy be the big-endian
    // representation of the underlying value regardless of platform.
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
                inaddr.sin6_flowinfo, /* NOTE: Despite network byte order, no conversion is needed (see https://github.com/rust-lang/rust/issues/101605) */
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
    // sockaddr_storage always has enough space to store either a sockaddr_in or
    // sockaddr_in6
    unsafe { sockaddr_to_socket_addr(sockaddr_storage as *const _ as *const libc::sockaddr) }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

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

    #[test]
    fn test_interface_from_str() {
        let interface = InterfaceDescriptor::from_str("0.0.0.0").unwrap();

        assert!(matches!(interface.mode, LinuxNetworkMode::Ipv4));
        assert!(interface.interface_name.is_none());

        let interface = InterfaceDescriptor::from_str("::").unwrap();

        assert!(matches!(interface.mode, LinuxNetworkMode::Ipv6));
        assert!(interface.interface_name.is_none());

        let interface = InterfaceDescriptor::from_str("lo").unwrap();

        assert!(matches!(interface.mode, LinuxNetworkMode::Ipv4));
        assert_eq!(interface.interface_name.unwrap(), InterfaceName::LOOPBACK);

        let error = InterfaceDescriptor::from_str("xxx").unwrap_err();

        assert_eq!(error.to_string(), interface_does_not_exist().to_string());
    }

    #[tokio::test]
    async fn get_address_ipv4_invalid() {
        let interface = InterfaceDescriptor {
            interface_name: Some(InterfaceName::from_str("invalid").unwrap()),
            mode: LinuxNetworkMode::Ipv4,
        };

        assert_eq!(
            interface.get_address().unwrap_err().to_string(),
            interface_does_not_exist().to_string()
        );
    }

    #[tokio::test]
    async fn get_address_ipv6_invalid() {
        let interface = InterfaceDescriptor {
            interface_name: Some(InterfaceName::from_str("invalid").unwrap()),
            mode: LinuxNetworkMode::Ipv6,
        };

        assert_eq!(
            interface.get_address().unwrap_err().to_string(),
            interface_does_not_exist().to_string()
        );
    }

    #[tokio::test]
    async fn interface_index_ipv4() -> std::io::Result<()> {
        let interface = InterfaceDescriptor {
            interface_name: Some(InterfaceName::LOOPBACK),
            mode: LinuxNetworkMode::Ipv4,
        };

        assert!(interface.get_index().is_some());

        Ok(())
    }

    #[tokio::test]
    async fn interface_index_ipv6() -> std::io::Result<()> {
        let interface = InterfaceDescriptor {
            interface_name: Some(InterfaceName::LOOPBACK),
            mode: LinuxNetworkMode::Ipv6,
        };

        assert!(interface.get_index().is_some());

        Ok(())
    }

    #[tokio::test]
    async fn interface_index_invalid() -> std::io::Result<()> {
        let interface = InterfaceDescriptor {
            interface_name: Some(InterfaceName::INVALID),
            mode: LinuxNetworkMode::Ipv4,
        };

        assert!(interface.get_index().is_none());

        Ok(())
    }

    #[tokio::test]
    async fn get_address_ipv4_valid() -> Result<(), Box<dyn std::error::Error>> {
        let interface = InterfaceDescriptor {
            interface_name: Some(InterfaceName::LOOPBACK),
            mode: LinuxNetworkMode::Ipv4,
        };

        assert_eq!(interface.get_address()?, Ipv4Addr::LOCALHOST);

        Ok(())
    }

    #[tokio::test]
    async fn get_address_ipv6_valid() -> Result<(), Box<dyn std::error::Error>> {
        let interface = InterfaceDescriptor {
            interface_name: Some(InterfaceName::LOOPBACK),
            mode: LinuxNetworkMode::Ipv6,
        };

        assert_eq!(interface.get_address()?, Ipv6Addr::LOCALHOST);

        Ok(())
    }
}
