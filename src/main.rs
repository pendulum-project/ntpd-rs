use std::{
    net::{IpAddr, SocketAddr},
    str::FromStr,
    sync::mpsc::{channel, Sender},
};

use nix::{
    cmsg_space,
    sys::{
        socket::{
            recvmsg, setsockopt, socket,
            sockopt::{IpAddMembership, Timestamping},
            AddressFamily, ControlMessageOwned, InetAddr, IpMembershipRequest, Ipv4Addr, MsgFlags,
            SockAddr, SockFlag, SockType, TimestampingFlag, Timestamps,
        },
        time::TimeSpec,
        uio::IoVec,
    },
};
use ptp::datastructures::{messages::Message, WireFormat};
use time::OffsetDateTime;

fn to_datetime(spec: &TimeSpec) -> OffsetDateTime {
    let time_nanos = spec.tv_nsec() as i128 + (spec.tv_sec() as i128) * 1_000_000_000i128;
    OffsetDateTime::from_unix_timestamp_nanos(time_nanos).unwrap()
}

fn spawn(tx: Sender<(SockAddr, Option<OffsetDateTime>, Vec<u8>)>, port: u16) {
    std::thread::Builder::new()
        .name(format!("ptp {}", port))
        .spawn(move || {
            // set up datagram socket
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
                tx.send((
                    recv.address.unwrap(),
                    ts,
                    io_vec[0].as_slice()[0..recv.bytes].to_vec(),
                ))
                .unwrap();
            }
        })
        .unwrap();
}

fn main() {
    let (tx, rx) = channel();

    spawn(tx.clone(), 319);
    spawn(tx.clone(), 320);

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
        let (src, ts, data) = rx.recv().unwrap();
        let message = Message::deserialize(&data).unwrap();
        if let Some(ts) = ts {
            println!("Received {:?} from {} at {}", message, src, ts);
        } else {
            println!("Received {:?} from {}", message, src);
        }
    }
}
