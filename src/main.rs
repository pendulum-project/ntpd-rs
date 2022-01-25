use std::{
    os::unix::prelude::RawFd,
    sync::mpsc::{channel, Sender},
    thread::JoinHandle, time::SystemTime,
};

use fixed::{types::{I112F16}, traits::ToFixed, traits::LosslessTryInto};
use nix::{
    cmsg_space,
    sys::{
        socket::{
            recvmsg, setsockopt, socket,
            sockopt::{IpAddMembership, Timestamping},
            AddressFamily, ControlMessageOwned, InetAddr, IpMembershipRequest, Ipv4Addr, MsgFlags,
            SockAddr, SockFlag, SockType, TimestampingFlag, Timestamps, sendmsg, IpAddr,
        },
        time::TimeSpec,
        uio::IoVec,
    }, ifaddrs::getifaddrs,
};
use ptp::datastructures::{
    messages::{Message, MessageContent, MessageBuilder, FlagField},
    WireFormat, common::{TimeInterval, PortIdentity, Timestamp},
};

type OffsetTime = I112F16;

#[derive(Clone, Debug)]
struct RangeError {}

trait TimeType {
    fn now() -> Self;
    fn from_timespec(spec: &TimeSpec) -> Self;
    fn from_timestamp(ts: &Timestamp) -> Self;
    fn from_interval(interval: &TimeInterval) -> Self;
    fn to_timestamp(&self) -> Result<Timestamp, RangeError>;
    fn to_interval(&self) -> Result<TimeInterval, RangeError>;
    fn secs(&self) -> i128;
    fn sub_nanos(&self) -> u32;
}

impl TimeType for OffsetTime {
    fn now() -> Self {
        let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap();
        now.as_nanos().to_fixed()
    }

    fn from_timespec(spec: &TimeSpec) -> Self {
        (spec.tv_sec() as i128 * 1_000_000_000i128 + spec.tv_nsec() as i128).to_fixed()
    }

    fn from_timestamp(ts: &Timestamp) -> Self {
        (ts.seconds as i128 * 1_000_000_000i128 + ts.nanos as i128).to_fixed()
    }

    fn from_interval(interval: &TimeInterval) -> Self {
        interval.0.into()
    }

    fn to_timestamp(&self) -> Result<Timestamp, RangeError> {
        let seconds: u64 = self.checked_to_num().ok_or(RangeError{})?;
        Ok(Timestamp {
            seconds,
            nanos: self.sub_nanos(),
        })
    }

    fn to_interval(&self) -> Result<TimeInterval, RangeError> {
        let val = (*self).lossless_try_into().ok_or(RangeError{})?;
        Ok(TimeInterval(val))
    }

    fn secs(&self) -> i128 {
        self.to_num::<i128>() / 1000000000i128
    }

    fn sub_nanos(&self) -> u32 {
        (self.to_num::<i128>() % 1000000000i128) as u32
    }
}

struct NetworkPacket {
    data: Vec<u8>,
    addr: SockAddr,
    timestamp: Option<OffsetTime>,
}

struct NetworkPort {
    socket: RawFd,
    recv_thread: JoinHandle<()>,
    addr: SockAddr,
}

impl NetworkPort {
    pub fn new(port: u16, tx: Sender<NetworkPacket>) -> Self {
        let sock_addr = SockAddr::new_inet(InetAddr::new(IpAddr::new_v4(0,0,0,0), port));
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

        let addr = SockAddr::new_inet(InetAddr::new(IpAddr::new_v4(224,0,1,129), port));
        
        NetworkPort {
            socket,
            recv_thread,
            addr,
        }
    }

    pub fn send(&self, data: &[u8]) {
        let io_vec = [IoVec::from_slice(data)];
        sendmsg(self.socket, &io_vec, &[], MsgFlags::empty(), Some(&self.addr)).unwrap();
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

fn get_clock_id() -> Option<[u8;8]> {
    let candidates = getifaddrs().unwrap();
    for candidate in candidates {
        if let Some(address) = candidate.address {
            if let SockAddr::Link(mac) = address {
                // Ignore multicast and locally administered mac addresses
                if mac.addr()[0] & 0x3 == 0 && mac.addr().iter().any(|x| *x != 0) {
                    let mut result: [u8;8] = [0;8];
                    for (i,v) in mac.addr().iter().enumerate() {
                        result[i] = *v;
                    }
                    return Some(result);
                }
            }
        }
    }
    None
}

fn main() {
    let (tx, rx) = channel();
    let port319 = NetworkPort::new(319, tx.clone());
    let port320 = NetworkPort::new(320, tx);

    let clock_identity = get_clock_id().unwrap();

    let mut delay_req_seq_id: u16 = 0;

    let mut last_sync_correction: Option<OffsetTime> = None;
    let mut last_sync_send_time: Option<OffsetTime> = None;
    let mut last_sync_recv_time: Option<OffsetTime> = None;
    let mut last_delayreq_send_time: Option<OffsetTime> = None;

    loop {
        let packet = rx.recv().unwrap();
        let message = Message::deserialize(&packet.data).unwrap();
        if let Some(ts) = packet.timestamp {
            if let MessageContent::Sync(syncmessage) = message.content() {
                last_sync_send_time = None;
                last_sync_correction = None;
                last_delayreq_send_time = None;
                last_sync_recv_time = Some(ts);
                if message.header().flag_field().two_step_flag {
                    last_sync_correction = Some(OffsetTime::from_interval(&message.header().correction_field()));
                } else {
                    send_delay_request(clock_identity, delay_req_seq_id, &port319);
                    delay_req_seq_id += 1;
                    last_sync_send_time = Some(OffsetTime::from_timestamp(&syncmessage.origin_timestamp()) + OffsetTime::from_interval(&message.header().correction_field()));
                }
            } else if let MessageContent::FollowUp(followup) = message.content() {
                if let Some(sync_correction) = last_sync_correction {
                    send_delay_request(clock_identity, delay_req_seq_id, &port319);
                    delay_req_seq_id += 1;
                    last_sync_correction = None;
                    last_sync_send_time = Some(OffsetTime::from_timestamp(&followup.precise_origin_timestamp()) + OffsetTime::from_interval(&message.header().correction_field()) + sync_correction);
                } else {
                    println!("Warning: Ignored followup, missing sync");
                }
            } else if let MessageContent::DelayReq(delayreq) = message.content() {
                last_delayreq_send_time = Some(ts);
            } else if let MessageContent::DelayResp(delayresp) = message.content() {
                // TODO: Filter to only use our responses
                if let Some(delay_send) = last_delayreq_send_time {
                    if let Some(sync_send) = last_sync_send_time {
                        if let Some(sync_recv) = last_sync_recv_time {
                            let delay_recv = OffsetTime::from_timestamp(&delayresp.receive_timestamp()) - OffsetTime::from_interval(&message.header().correction_field());
                            let mean_delay = (sync_recv - delay_send + delay_recv - sync_send)/2;
                            println!("Mean delay: {}", mean_delay);
                            let offset_from_master = sync_recv - sync_send - mean_delay;
                            println!("Master offset: {}", offset_from_master);
                        }
                    }
                }
            } else {
                println!("Received {:?} from {} at {}", message, packet.addr, ts);
            }
        } else {
            println!("Received {:?} from {}", message, packet.addr);
        }
    }
}

fn send_delay_request(clock_identity: [u8; 8], delay_req_seq_id: u16, port319: &NetworkPort) {
    let ts = OffsetTime::now();
    let delay_req = MessageBuilder::new().header(
        0,
        0,
        2,
        0,
        0,
        FlagField::default(),
        TimeInterval::default(),
        [0,0,0,0],
        PortIdentity{ clock_identity: ptp::datastructures::common::ClockIdentity(clock_identity), port_number: 0 },
        delay_req_seq_id,
        0x7F)
        .unwrap()
        .delay_req_message(ts.to_timestamp().unwrap())
        .finish();
    let delay_req_encode = delay_req.serialize_vec().unwrap();
    port319.send(&delay_req_encode);
}
