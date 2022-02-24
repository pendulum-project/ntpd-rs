use std::{os::unix::prelude::RawFd, str::FromStr, sync::mpsc::Sender, thread::JoinHandle};

use crate::time::{OffsetTime, TimeType};
use nix::{
    cmsg_space,
    errno::Errno,
    ifaddrs::getifaddrs,
    sys::{
        socket::{
            recvmsg, sendmsg, setsockopt, socket,
            sockopt::{IpAddMembership, Ipv6AddMembership, Timestamping},
            AddressFamily, ControlMessageOwned, InetAddr, IpAddr, IpMembershipRequest, Ipv4Addr,
            Ipv6Addr, Ipv6MembershipRequest, MsgFlags, SockAddr, SockFlag, SockType,
            TimestampingFlag, Timestamps,
        },
        uio::IoVec,
    },
};

use super::{NetworkPacket, NetworkPort, NetworkRuntime};

#[derive(Clone)]
pub struct LinuxRuntime {
    tx: Sender<NetworkPacket>,
}

impl LinuxRuntime {
    pub fn new(tx: Sender<NetworkPacket>) -> Self {
        LinuxRuntime { tx }
    }
}

#[derive(Debug, Clone)]
pub struct LinuxInterfaceDescriptor(IpAddr);

#[derive(thiserror::Error, Debug)]
#[error("The interface could not be parsed")]
pub struct InvalidInterfaceError;

#[derive(thiserror::Error, Debug)]
pub enum NetworkError {
    #[error("Unknown error")]
    UnknownError,
    #[error("Not allowed to bind to port {0}")]
    NoBindPermission(u16),
    #[error("Socket bind port {0} already in use")]
    AddressInUse(u16),
}

impl FromStr for LinuxInterfaceDescriptor {
    type Err = InvalidInterfaceError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match std::net::IpAddr::from_str(s) {
            Ok(addr) => Ok(LinuxInterfaceDescriptor(IpAddr::from_std(&addr))),
            Err(_) => match find_interface_with_name(s) {
                Some(v4) => Ok(LinuxInterfaceDescriptor(IpAddr::V4(v4))),
                None => Err(InvalidInterfaceError),
            },
        }
    }
}

fn find_interface_with_name(s: &str) -> Option<Ipv4Addr> {
    let interfaces = match getifaddrs() {
        Ok(a) => a,
        Err(_) => return None,
    };

    for ifaddr in interfaces {
        if ifaddr.interface_name == s {
            match ifaddr.address {
                Some(SockAddr::Inet(InetAddr::V4(addr))) => return Some(Ipv4Addr(addr.sin_addr)),
                _ => {}
            }
        }
    }
    None
}

impl NetworkRuntime for LinuxRuntime {
    type InterfaceDescriptor = LinuxInterfaceDescriptor;
    type PortType = LinuxNetworkPort;
    type Error = NetworkError;

    fn open(
        &self,
        interface: Self::InterfaceDescriptor,
        time_critical: bool,
    ) -> Result<Self::PortType, NetworkError> {
        let port = if time_critical { 319 } else { 320 };
        let is_ipv6 = if let IpAddr::V6(_) = interface.0 {
            true
        } else {
            false
        };
        let sock_addr = SockAddr::new_inet(InetAddr::new(interface.0, port));
        let socket = socket(
            AddressFamily::Inet,
            SockType::Datagram,
            SockFlag::empty(),
            None,
        )
        .map_err(|_| NetworkError::UnknownError)?;
        nix::sys::socket::bind(socket, &sock_addr).map_err(|e| match e {
            Errno::EACCES => NetworkError::NoBindPermission(port),
            Errno::EADDRINUSE => NetworkError::AddressInUse(port),
            _ => NetworkError::UnknownError,
        })?;
        log::info!(
            "Bound {}on {}",
            if time_critical { "time critical " } else { "" },
            sock_addr
        );

        if is_ipv6 {
            let multicast_req = Ipv6MembershipRequest::new(
                // TODO: Which multicast address scope?
                Ipv6Addr::new(0xFF, 0x02, 0, 0, 0, 0, 0x01, 0x81),
            );
            setsockopt(socket, Ipv6AddMembership, &multicast_req)
                .map_err(|_| NetworkError::UnknownError)?;
        } else {
            let multicast_req = IpMembershipRequest::new(Ipv4Addr::new(224, 0, 1, 129), None);
            setsockopt(socket, IpAddMembership, &multicast_req)
                .map_err(|_| NetworkError::UnknownError)?;
        }

        // Setup timestamping if needed
        if time_critical {
            setsockopt(socket, Timestamping, &TimestampingFlag::all())
                .map_err(|_| NetworkError::UnknownError)?;
        }

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
                    ts = Some(OffsetTime::from_timespec(&timestamps.system));
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
        if let Some(address) = candidate.address {
            if let SockAddr::Link(mac) = address {
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
    }
    None
}
