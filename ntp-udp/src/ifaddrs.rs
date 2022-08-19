//! taken from https://docs.rs/nix/latest/src/nix/ifaddrs.rs.html
//! stripped to just the parts that we need.
//!
//! Query network interface addresses
//!
//! Uses the Linux and/or BSD specific function `getifaddrs` to query the list
//! of interfaces and their associated addresses.

use std::ffi;
use std::iter::Iterator;
use std::mem;
use std::option::Option;

/// Describes a single address for an interface as returned by `getifaddrs`.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct InterfaceAddress {
    /// Name of the network interface
    pub interface_name: String,
    /// Network address of this interface
    pub address: Option<std::net::SocketAddr>,
}

impl InterfaceAddress {
    /// Create an `InterfaceAddress` from the libc struct.
    fn from_libc_ifaddrs(info: &libc::ifaddrs) -> InterfaceAddress {
        let ifname = unsafe { ffi::CStr::from_ptr(info.ifa_name) };

        let sockaddr: *mut libc::sockaddr = info.ifa_addr;
        let address = match unsafe { (*info.ifa_addr).sa_family } as libc::c_int {
            libc::AF_INET => {
                let inaddr: libc::sockaddr_in = unsafe { *(sockaddr as *mut libc::sockaddr_in) };

                let [a, b, c, d] = inaddr.sin_addr.s_addr.to_le_bytes();
                let socketaddr = std::net::SocketAddrV4::new(
                    std::net::Ipv4Addr::new(a, b, c, d),
                    inaddr.sin_port,
                );

                Some(std::net::SocketAddr::V4(socketaddr))
            }
            libc::AF_INET6 => {
                let inaddr: libc::sockaddr_in6 = unsafe { *(sockaddr as *mut libc::sockaddr_in6) };

                // the array could be misaligned (we need an alignment of 2 now)
                let sin_addr = inaddr.sin6_addr.s6_addr;
                let segments: [u16; 8] =
                    unsafe { std::ptr::read_unaligned(&sin_addr as *const _ as *const _) };

                let [a, b, c, d, e, f, g, h] = segments;
                let socketaddr = std::net::SocketAddrV6::new(
                    std::net::Ipv6Addr::new(a, b, c, d, e, f, g, h),
                    inaddr.sin6_port,
                    inaddr.sin6_flowinfo,
                    inaddr.sin6_scope_id,
                );

                Some(std::net::SocketAddr::V6(socketaddr))
            }
            _ => None,
        };

        let addr = InterfaceAddress {
            interface_name: ifname.to_string_lossy().to_string(),
            address,
        };

        addr
    }
}

/// Holds the results of `getifaddrs`.
///
/// Use the function `getifaddrs` to create this Iterator. Note that the
/// actual list of interfaces can be iterated once and will be freed as
/// soon as the Iterator goes out of scope.
#[derive(Debug, Eq, Hash, PartialEq)]
pub struct InterfaceAddressIterator {
    base: *mut libc::ifaddrs,
    next: *mut libc::ifaddrs,
}

impl Drop for InterfaceAddressIterator {
    fn drop(&mut self) {
        unsafe { libc::freeifaddrs(self.base) };
    }
}

impl Iterator for InterfaceAddressIterator {
    type Item = InterfaceAddress;
    fn next(&mut self) -> Option<<Self as Iterator>::Item> {
        match unsafe { self.next.as_ref() } {
            Some(ifaddr) => {
                self.next = ifaddr.ifa_next;
                Some(InterfaceAddress::from_libc_ifaddrs(ifaddr))
            }
            None => None,
        }
    }
}

/// Get interface addresses using libc's `getifaddrs`
pub fn getifaddrs() -> std::io::Result<InterfaceAddressIterator> {
    let mut addrs = mem::MaybeUninit::<*mut libc::ifaddrs>::uninit();
    let errorcode = unsafe { libc::getifaddrs(addrs.as_mut_ptr()) };

    match errorcode {
        -1 => Err(std::io::Error::last_os_error()),
        _ => Ok(InterfaceAddressIterator {
            base: unsafe { addrs.assume_init() },
            next: unsafe { addrs.assume_init() },
        }),
    }
}
