use std::{os::unix::prelude::RawFd, sync::mpsc::Sender, thread::JoinHandle};

use nix::{
    cmsg_space,
    ifaddrs::getifaddrs,
    sys::{
        socket::{
            recvmsg, sendmsg, setsockopt, socket,
            sockopt::{IpAddMembership, Timestamping},
            AddressFamily, ControlMessageOwned, InetAddr, IpAddr, IpMembershipRequest, Ipv4Addr,
            MsgFlags, SockAddr, SockFlag, SockType, TimestampingFlag, Timestamps,
        },
        uio::IoVec,
    },
};

use crate::time::{OffsetTime, TimeType};

pub struct NetworkPacket {
    pub data: Vec<u8>,
    pub addr: SockAddr,
    pub timestamp: Option<OffsetTime>,
}

pub struct NetworkPort {
    socket: RawFd,
    _recv_thread: JoinHandle<()>,
    addr: SockAddr,
}

impl NetworkPort {
    pub fn new(port: u16, tx: Sender<NetworkPacket>, timestamping: bool) -> Self {
        let sock_addr = SockAddr::new_inet(InetAddr::new(IpAddr::new_v4(0, 0, 0, 0), port));
        let socket = socket(
            AddressFamily::Inet,
            SockType::Datagram,
            SockFlag::empty(),
            None,
        )
        .unwrap();
        nix::sys::socket::bind(socket, &sock_addr).unwrap();

        // join ipv4 multicast group
        let multicast_req = IpMembershipRequest::new(
            Ipv4Addr::new(224, 0, 1, 129),
            Some(Ipv4Addr::new(0, 0, 0, 0)),
        );
        setsockopt(socket, IpAddMembership, &multicast_req).unwrap();

        // Setup timestamping if needed
        if timestamping {
            setsockopt(socket, Timestamping, &TimestampingFlag::all()).unwrap();
        }

        let recv_thread = std::thread::Builder::new()
            .name(format!("ptp {}", port))
            .spawn(move || NetworkPort::recv_thread(socket, tx))
            .unwrap();

        let addr = SockAddr::new_inet(InetAddr::new(IpAddr::new_v4(224, 0, 1, 129), port));

        NetworkPort {
            socket,
            _recv_thread: recv_thread,
            addr,
        }
    }

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
                addr: recv.address.unwrap(),
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
