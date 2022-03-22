//! Implementation of the abstract network types for the linux platform

use crate::time::Instant;

use super::{NetworkPacket, NetworkPort, NetworkRuntime};
use nix::{
    cmsg_space,
    errno::Errno,
    ifaddrs::{getifaddrs, InterfaceAddress, InterfaceAddressIterator},
    net::if_::if_nametoindex,
    sys::{
        select::{select, FdSet},
        socket::{
            recvmsg, sendmsg, setsockopt, socket,
            sockopt::{BindToDevice, ReuseAddr, Timestamping},
            AddressFamily, ControlMessageOwned, InetAddr, IpAddr, Ipv4Addr, Ipv6Addr, MsgFlags,
            SetSockOpt, SockAddr, SockFlag, SockType, TimestampingFlag, Timestamps,
        },
        uio::IoVec,
    },
};
use std::{os::unix::prelude::RawFd, str::FromStr, sync::mpsc::Sender, thread::JoinHandle};

#[derive(Clone)]
pub struct LinuxRuntime {
    tx: Sender<NetworkPacket>,
}

impl LinuxRuntime {
    pub fn new(tx: Sender<NetworkPacket>) -> Self {
        LinuxRuntime { tx }
    }

    const IPV6_PRIMARY_MULTICAST: Ipv6Addr = Ipv6Addr::new(0xFF, 0x0E, 0, 0, 0, 0, 0x01, 0x81);
    const IPV6_PDELAY_MULTICAST: Ipv6Addr = Ipv6Addr::new(0xFF, 0x02, 0, 0, 0, 0, 0, 0x6B);

    const IPV4_PRIMARY_MULTICAST: Ipv4Addr = Ipv4Addr::new(224, 0, 1, 129);
    const IPV4_PDELAY_MULTICAST: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 107);
}

#[derive(Debug, Clone)]
pub struct LinuxInterfaceDescriptor {
    interface_name: Option<String>,
    mode: LinuxNetworkMode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinuxNetworkMode {
    Ipv4,
    Ipv6,
}

#[derive(thiserror::Error, Debug)]
pub enum NetworkError {
    #[error("Unknown error")]
    UnknownError,
    #[error("Not allowed to bind to port {0}")]
    NoBindPermission(u16),
    #[error("Socket bind port {0} already in use")]
    AddressInUse(u16),
    #[error("Could not bind socket to a specific device")]
    BindToDeviceFailed,
    #[error("Could not iterate over interfaces")]
    CannotIterateInterfaces,
    #[error("The specified interface does not exist")]
    InterfaceDoesNotExist,
    #[error("No more packets")]
    NoMorePackets,
}

impl LinuxInterfaceDescriptor {
    fn get_index(&self) -> Option<u32> {
        if let Some(ref name) = self.interface_name {
            if_nametoindex(&name[..]).ok()
        } else {
            None
        }
    }

    fn get_address(&self) -> Result<IpAddr, NetworkError> {
        if let Some(ref name) = self.interface_name {
            let interfaces = match getifaddrs() {
                Ok(a) => a,
                Err(_) => return Err(NetworkError::CannotIterateInterfaces),
            };
            for i in interfaces {
                if name == &i.interface_name {
                    if self.mode == LinuxNetworkMode::Ipv6 {
                        if let Some(SockAddr::Inet(a @ InetAddr::V6(_))) = i.address {
                            return Ok(a.ip());
                        }
                    } else {
                        if let Some(SockAddr::Inet(a @ InetAddr::V4(_))) = i.address {
                            return Ok(a.ip());
                        }
                    }
                }
            }
            Err(NetworkError::InterfaceDoesNotExist)
        } else {
            if self.mode == LinuxNetworkMode::Ipv6 {
                Ok(IpAddr::V6(Ipv6Addr::from_std(
                    &std::net::Ipv6Addr::UNSPECIFIED,
                )))
            } else {
                Ok(IpAddr::V4(Ipv4Addr::any()))
            }
        }
    }
}

impl FromStr for LinuxInterfaceDescriptor {
    type Err = NetworkError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let interfaces = match getifaddrs() {
            Ok(a) => a,
            Err(_) => return Err(NetworkError::CannotIterateInterfaces),
        };

        match std::net::IpAddr::from_str(s) {
            Ok(addr) => {
                if addr.is_unspecified() {
                    return Ok(LinuxInterfaceDescriptor {
                        interface_name: None,
                        mode: if addr.is_ipv4() {
                            LinuxNetworkMode::Ipv4
                        } else {
                            LinuxNetworkMode::Ipv6
                        },
                    });
                }

                let sock_addr = InetAddr::from_std(&std::net::SocketAddr::new(addr, 0));
                for ifaddr in interfaces {
                    if if_has_address(&ifaddr, &sock_addr) {
                        return Ok(LinuxInterfaceDescriptor {
                            interface_name: Some(ifaddr.interface_name.clone()),
                            mode: LinuxNetworkMode::Ipv4,
                        });
                    }
                }

                Err(NetworkError::InterfaceDoesNotExist)
            }
            Err(_) => {
                if if_name_exists(interfaces, s) {
                    Ok(LinuxInterfaceDescriptor {
                        interface_name: Some(s.to_owned()),
                        mode: LinuxNetworkMode::Ipv4,
                    })
                } else {
                    Err(NetworkError::InterfaceDoesNotExist)
                }
            }
        }
    }
}

fn if_has_address(ifaddr: &InterfaceAddress, address: &InetAddr) -> bool {
    if let Some(SockAddr::Inet(a)) = ifaddr.address {
        match (a, address) {
            (InetAddr::V4(if_v4), InetAddr::V4(req_v4)) => if_v4.sin_addr == req_v4.sin_addr,
            (InetAddr::V6(if_v6), InetAddr::V6(req_v6)) => if_v6.sin6_addr == req_v6.sin6_addr,
            _ => false,
        }
    } else {
        false
    }
}

fn if_name_exists(interfaces: InterfaceAddressIterator, name: &str) -> bool {
    for i in interfaces {
        if i.interface_name == name {
            return true;
        }
    }

    false
}

/// Request for multicast socket operations
///
/// This is a wrapper type around `ip_mreqn`.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct IpMembershipRequest(libc::ip_mreqn);

impl IpMembershipRequest {
    /// Instantiate a new `IpMembershipRequest`
    ///
    ///
    pub fn new(group: Ipv4Addr, interface_idx: Option<u32>) -> Self {
        IpMembershipRequest(libc::ip_mreqn {
            imr_multiaddr: group.0,
            imr_address: libc::in_addr { s_addr: 0 },
            imr_ifindex: interface_idx.unwrap_or(0) as i32,
        })
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct IpAddMembership;

impl SetSockOpt for IpAddMembership {
    type Val = IpMembershipRequest;

    fn set(&self, fd: RawFd, val: &Self::Val) -> nix::Result<()> {
        let ptr = val as *const Self::Val as *const libc::c_void;
        let ptr_len = std::mem::size_of::<Self::Val>() as libc::socklen_t;
        let res = unsafe {
            libc::setsockopt(fd, libc::IPPROTO_IP, libc::IP_ADD_MEMBERSHIP, ptr, ptr_len)
        };
        Errno::result(res).map(drop)
    }
}

/// Request for ipv6 multicast socket operations
///
/// This is a wrapper type around `ipv6_mreq`.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Ipv6MembershipRequest(libc::ipv6_mreq);

impl Ipv6MembershipRequest {
    /// Instantiate a new `Ipv6MembershipRequest`
    pub const fn new(group: Ipv6Addr, interface_idx: Option<u32>) -> Self {
        Ipv6MembershipRequest(libc::ipv6_mreq {
            ipv6mr_multiaddr: group.0,
            ipv6mr_interface: match interface_idx {
                Some(v) => v,
                _ => 0,
            },
        })
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct Ipv6AddMembership;

impl SetSockOpt for Ipv6AddMembership {
    type Val = Ipv6MembershipRequest;

    fn set(&self, fd: RawFd, val: &Self::Val) -> nix::Result<()> {
        let ptr = val as *const Self::Val as *const libc::c_void;
        let ptr_len = std::mem::size_of::<Self::Val>() as libc::socklen_t;
        let res = unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IPV6,
                libc::IPV6_ADD_MEMBERSHIP,
                ptr,
                ptr_len,
            )
        };
        Errno::result(res).map(drop)
    }
}

impl<'a> NetworkRuntime for LinuxRuntime {
    type InterfaceDescriptor = LinuxInterfaceDescriptor;
    type PortType = LinuxNetworkPort;
    type Error = NetworkError;

    fn open(
        &mut self,
        interface: Self::InterfaceDescriptor,
        time_critical: bool,
    ) -> Result<Self::PortType, NetworkError> {
        // create the socket
        let socket = socket(
            AddressFamily::Inet,
            SockType::Datagram,
            SockFlag::empty(),
            None,
        )
        .map_err(|_| NetworkError::UnknownError)?;

        // create the socket
        let port = if time_critical { 319 } else { 320 };
        let sock_addr = SockAddr::new_inet(InetAddr::new(
            if interface.mode == LinuxNetworkMode::Ipv6 {
                IpAddr::V6(Ipv6Addr::from_std(&std::net::Ipv6Addr::UNSPECIFIED))
            } else {
                IpAddr::V4(Ipv4Addr::any())
            },
            port,
        ));

        // we want to allow multiple listening sockets, as we bind to a specific interface later
        setsockopt(socket, ReuseAddr, &true).map_err(|_| NetworkError::UnknownError)?;

        // bind the socket
        nix::sys::socket::bind(socket, &sock_addr).map_err(|e| match e {
            // not allowed to bind to the port
            Errno::EACCES => NetworkError::NoBindPermission(port),
            // maybe someone else is listening on the address exclusively
            Errno::EADDRINUSE => NetworkError::AddressInUse(port),
            _ => NetworkError::UnknownError,
        })?;

        // bind to device specified
        if let Some(ref name) = interface.interface_name {
            setsockopt(socket, BindToDevice, &name.into())
                .map_err(|_| NetworkError::BindToDeviceFailed)?;
        }

        // TODO: multicast ttl limit for ipv4/multicast hops limit for ipv6

        let interface_idx = interface.get_index();

        // join the multicast groups
        if interface.mode == LinuxNetworkMode::Ipv6 {
            // TODO: set the scope for the primary multicast
            let multicast_req =
                Ipv6MembershipRequest::new(LinuxRuntime::IPV6_PRIMARY_MULTICAST, interface_idx);
            setsockopt(socket, Ipv6AddMembership, &multicast_req)
                .map_err(|_| NetworkError::UnknownError)?;

            let multicast_req =
                Ipv6MembershipRequest::new(LinuxRuntime::IPV6_PDELAY_MULTICAST, interface_idx);
            setsockopt(socket, Ipv6AddMembership, &multicast_req)
                .map_err(|_| NetworkError::UnknownError)?;
        } else {
            let multicast_req =
                IpMembershipRequest::new(LinuxRuntime::IPV4_PRIMARY_MULTICAST, interface_idx);
            setsockopt(socket, IpAddMembership, &multicast_req)
                .map_err(|_| NetworkError::UnknownError)?;

            let multicast_req =
                IpMembershipRequest::new(LinuxRuntime::IPV4_PDELAY_MULTICAST, interface_idx);
            setsockopt(socket, IpAddMembership, &multicast_req)
                .map_err(|_| NetworkError::UnknownError)?;
        }

        log::info!(
            "Bound {}on {}",
            if time_critical { "time critical " } else { "" },
            sock_addr
        );

        // Setup timestamping if needed
        if time_critical {
            setsockopt(socket, Timestamping, &TimestampingFlag::all())
                .map_err(|_| NetworkError::UnknownError)?;
        }

        // TODO: replace recv thread with select
        let tx = self.tx.clone();
        let recv_thread = std::thread::Builder::new()
            .name(format!("ptp {}", port))
            .spawn(move || LinuxNetworkPort::recv_thread(socket, tx))
            .unwrap();

        Ok(LinuxNetworkPort {
            addr: SockAddr::Inet(InetAddr::new(
                nix::sys::socket::IpAddr::new_v4(224, 0, 1, 129),
                port,
            )),
            socket,
            _recv_thread: recv_thread,
        })
    }

    fn recv(&mut self) -> Result<NetworkPacket, Self::Error> {
        let mut read_set = FdSet::new();
        // for s in self.sockets {
        //     read_set.insert(s);
        // }
        let _res = select(None, &mut read_set, None, None, None)
            .map_err(|_| NetworkError::UnknownError)?;
        todo!()
    }
}

pub struct LinuxNetworkPort {
    addr: SockAddr,
    socket: RawFd,
    _recv_thread: JoinHandle<()>,
}

impl NetworkPort for LinuxNetworkPort {
    fn send(&mut self, data: &[u8]) -> Option<usize> {
        let io_vec = [IoVec::from_slice(data)];
        sendmsg(
            self.socket,
            &io_vec,
            &[],
            MsgFlags::empty(),
            Some(&self.addr),
        )
        .unwrap();

        // TODO: Implement better method for send timestamps
        Some(u16::from_be_bytes(data[30..32].try_into().unwrap()) as usize)
    }
}

impl LinuxNetworkPort {
    fn recv_thread(socket: i32, tx: Sender<NetworkPacket>) {
        let mut read_buf = [0u8; 2048];
        let io_vec = [IoVec::from_mut_slice(&mut read_buf)];
        let mut cmsg = cmsg_space!(Timestamps);
        let flags = MsgFlags::empty();
        loop {
            let recv = recvmsg(socket, &io_vec, Some(&mut cmsg), flags).unwrap();
            let mut ts = None;
            for c in recv.cmsgs() {
                if let ControlMessageOwned::ScmTimestampsns(timestamps) = c {
                    ts = Some(Instant::from_timespec(&timestamps.system));
                }
            }
            tx.send(NetworkPacket {
                data: io_vec[0].as_slice()[0..recv.bytes].to_vec(),
                timestamp: ts,
            })
            .unwrap();
        }
    }
}

pub fn get_clock_id() -> Option<[u8; 8]> {
    let candidates = getifaddrs().unwrap();
    for candidate in candidates {
        if let Some(SockAddr::Link(mac)) = candidate.address {
            // Ignore multicast and locally administered mac addresses
            if mac.addr()[0] & 0x3 == 0 && mac.addr().iter().any(|x| *x != 0) {
                let mut result: [u8; 8] = [0; 8];
                for (i, v) in mac.addr().iter().enumerate() {
                    result[i] = *v;
                }
                return Some(result);
            }
        }
    }
    None
}
