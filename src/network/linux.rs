use std::{os::unix::prelude::RawFd, sync::mpsc::Sender, thread::JoinHandle};

use nix::{
    cmsg_space,
    ifaddrs::getifaddrs,
    sys::{
        socket::{
            recvmsg, sendmsg, setsockopt, socket,
            sockopt::{IpAddMembership, Timestamping},
            AddressFamily, ControlMessageOwned, InetAddr, IpMembershipRequest, Ipv4Addr,
            MsgFlags, SockAddr, SockFlag, SockType, TimestampingFlag, Timestamps,
        },
        uio::IoVec,
    },
};

use crate::time::{OffsetTime, TimeType};

use super::{NetworkPacket, NetworkRuntime, NetworkPort, NetworkError};

pub struct LinuxRuntime;

impl NetworkRuntime for LinuxRuntime {
    type InterfaceDescriptor = SockAddr;
    type PortType = LinuxNetworkPort;

    fn open(&self, interface: Self::InterfaceDescriptor, time_critical: bool) -> Result<Self::PortType, NetworkError> {
        if let SockAddr::Inet(InetAddr::V4(addr)) = &interface {
            let socket = socket(
                AddressFamily::Inet,
                SockType::Datagram,
                SockFlag::empty(),
                None,
            ).map_err(|_e| NetworkError)?; // TODO: mapping errno to networkerror somehow, but errno depends on context, so no simple From<_>
            nix::sys::socket::bind(socket, &interface).map_err(|_e| NetworkError)?;

            // TODO: extract interface from provided SockAddr, as the multicast should be on the same interface as we are listening on
            let multicast_req = IpMembershipRequest::new(
                Ipv4Addr::new(224, 0, 1, 129),
                Some(Ipv4Addr::new(0, 0, 0, 0)),
            );
            setsockopt(socket, IpAddMembership, &multicast_req).map_err(|_e| NetworkError)?;

            // Setup timestamping if needed
            if time_critical {
                setsockopt(socket, Timestamping, &TimestampingFlag::all()).map_err(|_e| NetworkError)?;
            }

            let recv_thread = std::thread::Builder::new()
                .name(format!("ptp recv"))
                .spawn(move || LinuxNetworkPort::recv_thread(socket, tx)) // TODO: store channel in runtime
                .unwrap();

            LinuxNetworkPort {
                socket,
                _recv_thread: recv_thread,
            }
        } else {
            Err(NetworkError)
        }
    }
}

pub struct LinuxNetworkPort {
    socket: RawFd,
    _recv_thread: JoinHandle<()>,
}

impl NetworkPort for LinuxNetworkPort {

}

impl LinuxNetworkPort {
    pub fn send(&self, data: &[u8]) {
        let io_vec = [IoVec::from_slice(data)];
        sendmsg(
            self.socket,
            &io_vec,
            &[],
            MsgFlags::empty(),
            Some(&self.addr),
        )
        .unwrap();
    }

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
