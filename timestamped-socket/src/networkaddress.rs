use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    os::fd::RawFd,
};

use crate::{control_message::zeroed_sockaddr_storage, interface::InterfaceName};

use self::sealed::{PrivateToken, SealedMC, SealedNA};

#[cfg(target_os = "linux")]
pub use self::linux::*;

#[cfg(target_os = "linux")]
mod linux;

pub(crate) mod sealed {
    // Seal to ensure NetworkAddress can't be implemented outside our crate
    pub trait SealedNA {}

    // Seal to ensure MulticastJoinable can't be implemented outside our crate
    pub trait SealedMC {}

    // Token to ensure trait functions cannot be called outside our crate
    pub struct PrivateToken;
}

pub trait NetworkAddress: Copy + Sized + SealedNA {
    #[doc(hidden)]
    fn to_sockaddr(&self, _token: PrivateToken) -> libc::sockaddr_storage;
    #[doc(hidden)]
    fn from_sockaddr(addr: libc::sockaddr_storage, _token: PrivateToken) -> Option<Self>;
    #[doc(hidden)]
    fn from_ip_and_port(addr: IpAddr, port: u16) -> Option<Self>;
    #[doc(hidden)]
    fn port(&self) -> u16;
}

pub trait MulticastJoinable: NetworkAddress + SealedMC {
    #[doc(hidden)]
    fn join_multicast(
        &self,
        socket: RawFd,
        interface: InterfaceName,
        _token: PrivateToken,
    ) -> std::io::Result<()>;
    #[doc(hidden)]
    fn leave_multicast(
        &self,
        socket: RawFd,
        interface: InterfaceName,
        _token: PrivateToken,
    ) -> std::io::Result<()>;
}

impl SealedNA for SocketAddrV4 {}

impl NetworkAddress for SocketAddrV4 {
    fn to_sockaddr(&self, _token: PrivateToken) -> libc::sockaddr_storage {
        const _: () = assert!(
            std::mem::size_of::<libc::sockaddr_storage>()
                >= std::mem::size_of::<libc::sockaddr_in>()
        );
        const _: () = assert!(
            std::mem::align_of::<libc::sockaddr_storage>()
                >= std::mem::align_of::<libc::sockaddr_in>()
        );

        let mut result = zeroed_sockaddr_storage();
        // Safety: the above assertions guarantee that alignment and size are correct.
        // the resulting reference won't outlast the function, and result lives the entire
        // duration of the function
        let out = unsafe { &mut (*(&mut result as *mut _ as *mut libc::sockaddr_in)) };
        out.sin_family = libc::AF_INET as _;
        out.sin_port = u16::from_ne_bytes(self.port().to_be_bytes());
        out.sin_addr = libc::in_addr {
            s_addr: u32::from_ne_bytes(self.ip().octets()),
        };

        result
    }

    fn from_sockaddr(addr: libc::sockaddr_storage, _token: PrivateToken) -> Option<Self> {
        const _: () = assert!(
            std::mem::size_of::<libc::sockaddr_storage>()
                >= std::mem::size_of::<libc::sockaddr_in>()
        );
        const _: () = assert!(
            std::mem::align_of::<libc::sockaddr_storage>()
                >= std::mem::align_of::<libc::sockaddr_in>()
        );

        if addr.ss_family != libc::AF_INET as _ {
            return None;
        }

        // Safety: the above assertions guarantee that alignment and size are correct
        // the resulting reference won't outlast the function, and addr lives the entire
        // duration of the function
        let input = unsafe { &(*(&addr as *const _ as *const libc::sockaddr_in)) };
        Some(SocketAddrV4::new(
            Ipv4Addr::from(input.sin_addr.s_addr.to_ne_bytes()),
            u16::from_be_bytes(input.sin_port.to_ne_bytes()),
        ))
    }

    fn from_ip_and_port(addr: IpAddr, port: u16) -> Option<Self> {
        match addr {
            IpAddr::V4(addr) => Some(SocketAddrV4::new(addr, port)),
            IpAddr::V6(_) => None,
        }
    }

    fn port(&self) -> u16 {
        self.port()
    }
}

impl SealedNA for SocketAddrV6 {}

impl NetworkAddress for SocketAddrV6 {
    fn to_sockaddr(&self, _token: PrivateToken) -> libc::sockaddr_storage {
        const _: () = assert!(
            std::mem::size_of::<libc::sockaddr_storage>()
                >= std::mem::size_of::<libc::sockaddr_in6>()
        );
        const _: () = assert!(
            std::mem::align_of::<libc::sockaddr_storage>()
                >= std::mem::align_of::<libc::sockaddr_in6>()
        );

        let mut result = zeroed_sockaddr_storage();
        // Safety: the above assertions guarantee that alignment and size are correct.
        // the resulting reference won't outlast the function, and result lives the entire
        // duration of the function
        let out = unsafe { &mut (*(&mut result as *mut _ as *mut libc::sockaddr_in6)) };
        out.sin6_family = libc::AF_INET6 as _;
        out.sin6_port = u16::from_ne_bytes(self.port().to_be_bytes());
        out.sin6_addr = libc::in6_addr {
            s6_addr: self.ip().octets(),
        };
        out.sin6_flowinfo = self.flowinfo();
        out.sin6_scope_id = self.scope_id();

        result
    }

    fn from_sockaddr(addr: libc::sockaddr_storage, _token: PrivateToken) -> Option<Self> {
        const _: () = assert!(
            std::mem::size_of::<libc::sockaddr_storage>()
                >= std::mem::size_of::<libc::sockaddr_in6>()
        );
        const _: () = assert!(
            std::mem::align_of::<libc::sockaddr_storage>()
                >= std::mem::align_of::<libc::sockaddr_in6>()
        );

        if addr.ss_family != libc::AF_INET6 as _ {
            return None;
        }

        // Safety: the above assertions guarantee that alignment and size are correct
        // the resulting reference won't outlast the function, and addr lives the entire
        // duration of the function
        let input = unsafe { &(*(&addr as *const _ as *const libc::sockaddr_in6)) };
        Some(SocketAddrV6::new(
            Ipv6Addr::from(input.sin6_addr.s6_addr),
            u16::from_be_bytes(input.sin6_port.to_ne_bytes()),
            input.sin6_flowinfo,
            input.sin6_scope_id,
        ))
    }

    fn from_ip_and_port(addr: IpAddr, port: u16) -> Option<Self> {
        match addr {
            IpAddr::V4(_) => None,
            IpAddr::V6(addr) => Some(SocketAddrV6::new(addr, port, 0, 0)),
        }
    }

    fn port(&self) -> u16 {
        self.port()
    }
}

impl SealedNA for SocketAddr {}

impl NetworkAddress for SocketAddr {
    fn to_sockaddr(&self, _token: PrivateToken) -> libc::sockaddr_storage {
        match self {
            SocketAddr::V4(addr) => addr.to_sockaddr(PrivateToken),
            SocketAddr::V6(addr) => addr.to_sockaddr(PrivateToken),
        }
    }

    fn from_sockaddr(addr: libc::sockaddr_storage, _token: PrivateToken) -> Option<Self> {
        match addr.ss_family as _ {
            libc::AF_INET => Some(SocketAddr::V4(SocketAddrV4::from_sockaddr(
                addr,
                PrivateToken,
            )?)),
            libc::AF_INET6 => Some(SocketAddr::V6(SocketAddrV6::from_sockaddr(
                addr,
                PrivateToken,
            )?)),
            _ => None,
        }
    }

    fn from_ip_and_port(addr: IpAddr, port: u16) -> Option<Self> {
        Some(SocketAddr::new(addr, port))
    }

    fn port(&self) -> u16 {
        self.port()
    }
}
