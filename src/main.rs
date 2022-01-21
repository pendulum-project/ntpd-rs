use std::{
    net::{IpAddr, SocketAddr},
    os::unix::prelude::RawFd,
    str::FromStr,
    sync::mpsc::{channel, Receiver, Sender},
    thread::JoinHandle,
};

use nix::{
    cmsg_space,
    sys::{
        socket::{
            recvmsg, send, setsockopt, socket,
            sockopt::{IpAddMembership, Timestamping},
            AddressFamily, ControlMessageOwned, InetAddr, IpMembershipRequest, Ipv4Addr, MsgFlags,
            SockAddr, SockFlag, SockType, TimestampingFlag, Timestamps,
        },
        time::TimeSpec,
        uio::IoVec,
    },
};
use ptp::datastructures::{
    messages::{Message, MessageContent},
    WireFormat,
};
use time::OffsetDateTime;

fn to_datetime(spec: &TimeSpec) -> OffsetDateTime {
    let time_nanos = spec.tv_nsec() as i128 + (spec.tv_sec() as i128) * 1_000_000_000i128;
    OffsetDateTime::from_unix_timestamp_nanos(time_nanos).unwrap()
}

struct NetworkPacket {
    data: Vec<u8>,
    addr: SockAddr,
    timestamp: Option<time::OffsetDateTime>,
}

struct NetworkPort {
    socket: RawFd,
    recv_thread: JoinHandle<()>,
}

impl NetworkPort {
    pub fn new(port: u16, tx: Sender<NetworkPacket>) -> Self {
        let socket_addr = SocketAddr::new(IpAddr::from_str("0.0.0.0").unwrap(), port);
        let sock_addr = SockAddr::new_inet(InetAddr::from_std(&socket_addr));
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
        setsockopt(socket, Timestamping, &TimestampingFlag::all()).unwrap();

        let recv_thread = std::thread::Builder::new()
            .name(format!("ptp {}", port))
            .spawn(move || NetworkPort::recv_thread(socket, tx))
            .unwrap();

        NetworkPort {
            socket,
            recv_thread,
        }
    }

    pub fn send(&self, data: &[u8]) {
        send(self.socket, data, MsgFlags::empty()).unwrap();
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
                    ts = Some(to_datetime(&timestamps.system));
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

fn main() {
    let (tx, rx) = channel();
    let port319 = NetworkPort::new(319, tx.clone());
    let port320 = NetworkPort::new(320, tx);

    // let tx_320 = tx.clone();
    // std::thread::spawn(move || {
    //     let socket = UdpSocket::bind("0.0.0.0:320").unwrap();
    //     socket.join_multicast_v4(&"224.0.1.129".parse().unwrap(), &"0.0.0.0".parse().unwrap()).unwrap();
    //     let mut buf = [0;511];
    //     loop {
    //         let (amt, src) = socket.recv_from(&mut buf).unwrap();
    //         tx_320.send((src, None, buf[..amt].to_vec())).unwrap();
    //     }
    // });

    loop {
        let packet = rx.recv().unwrap();
        let message = Message::deserialize(&packet.data).unwrap();
        if let Some(ts) = packet.timestamp {
            if let MessageContent::Sync(syncmessage) = message.content() {
                let send_time_nanos = (syncmessage.origin_timestamp().seconds as i128)
                    * 1_000_000_000i128
                    + (syncmessage.origin_timestamp().nanos as i128);
                let send_ts = OffsetDateTime::from_unix_timestamp_nanos(send_time_nanos).unwrap();
                println!("Sync offset incl transmission delay: {:?}", ts - send_ts);
            } else {
                println!("Received {:?} from {} at {}", message, packet.addr, ts);
            }
        } else {
            println!("Received {:?} from {}", message, packet.addr);
        }
    }
}
