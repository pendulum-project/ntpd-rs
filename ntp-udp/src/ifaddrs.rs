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
use std::net::{Ipv4Addr, SocketAddr};
use std::option::Option;

/// Describes a single address for an interface as returned by `getifaddrs`.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct InterfaceAddress {
    /// Name of the network interface
    pub interface_name: String,
    /// Network address of this interface
    pub address: Option<SocketAddr>,
}

impl InterfaceAddress {
    /// Create an `InterfaceAddress` from the libc struct.
    fn from_libc_ifaddrs(info: &libc::ifaddrs) -> InterfaceAddress {
        let ifname = unsafe { ffi::CStr::from_ptr(info.ifa_name) };

        let sockaddr: *mut libc::sockaddr = info.ifa_addr;
        let address = Self::to_socket_addr(unsafe { *sockaddr });

        let addr = InterfaceAddress {
            interface_name: ifname.to_string_lossy().to_string(),
            address,
        };

        addr
    }

    fn to_socket_addr(addr: libc::sockaddr) -> Option<SocketAddr> {
        match addr.sa_family as i32 {
            libc::AF_INET => {
                // kernel assures us this conversion is safe
                let sin = &addr as *const _ as *const libc::c_void as *const libc::sockaddr_in;
                let sin = unsafe { &*sin };

                // no direct (u32, u16) conversion is available, so we convert the address first
                let addr = Ipv4Addr::from(sin.sin_addr.s_addr);
                Some(SocketAddr::from((addr, sin.sin_port)))
            }
            libc::AF_INET6 => {
                // kernel assures us this conversion is safe
                let sin = &addr as *const _ as *const libc::c_void as *const libc::sockaddr_in6;
                let sin = unsafe { &*sin };
                Some(SocketAddr::from((sin.sin6_addr.s6_addr, sin.sin6_port)))
            }
            _ => None,
        }
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

    crate::cerr(unsafe { libc::getifaddrs(addrs.as_mut_ptr()) })?;

    Ok(InterfaceAddressIterator {
        base: unsafe { addrs.assume_init() },
        next: unsafe { addrs.assume_init() },
    })
}
