use std::sync::mpsc::channel;

use ptp::{
    datastructures::{
        common::{PortIdentity, TimeInterval},
        messages::{FlagField, Message, MessageBuilder, MessageContent},
        WireFormat,
    },
    network::{get_clock_id, NetworkPort},
    time::{OffsetTime, TimeType},
};

fn main() {
    let (tx, rx) = channel();
    let port319 = NetworkPort::new(319, tx.clone(), true);
    let _port320 = NetworkPort::new(320, tx, false);

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
                    last_sync_correction = Some(OffsetTime::from_interval(
                        &message.header().correction_field(),
                    ));
                } else {
                    send_delay_request(clock_identity, delay_req_seq_id, &port319);
                    delay_req_seq_id += 1;
                    last_sync_send_time = Some(
                        OffsetTime::from_timestamp(&syncmessage.origin_timestamp())
                            + OffsetTime::from_interval(&message.header().correction_field()),
                    );
                }
            } else if let MessageContent::DelayReq(_delayreq) = message.content() {
                last_delayreq_send_time = Some(ts);
            } else {
                println!("Received {:?} from {} at {}", message, packet.addr, ts);
            }
        } else {
            if let MessageContent::FollowUp(followup) = message.content() {
                if let Some(sync_correction) = last_sync_correction {
                    send_delay_request(clock_identity, delay_req_seq_id, &port319);
                    delay_req_seq_id += 1;
                    last_sync_correction = None;
                    last_sync_send_time = Some(
                        OffsetTime::from_timestamp(&followup.precise_origin_timestamp())
                            + OffsetTime::from_interval(&message.header().correction_field())
                            + sync_correction,
                    );
                } else {
                    println!("Warning: Ignored followup, missing sync");
                }
            } else if let MessageContent::DelayResp(delayresp) = message.content() {
                // TODO: Filter to only use our responses
                if let Some(delay_send) = last_delayreq_send_time {
                    if let Some(sync_send) = last_sync_send_time {
                        if let Some(sync_recv) = last_sync_recv_time {
                            let delay_recv =
                                OffsetTime::from_timestamp(&delayresp.receive_timestamp())
                                    - OffsetTime::from_interval(
                                        &message.header().correction_field(),
                                    );
                            let mean_delay = (sync_recv - delay_send + delay_recv - sync_send) / 2;
                            println!("Mean delay: {}", mean_delay);
                            let offset_from_master = sync_recv - sync_send - mean_delay;
                            println!("Master offset: {}", offset_from_master);
                        }
                    }
                }
            } else {
                println!("Received {:?} from {}", message, packet.addr);
            }
        }
    }
}

fn send_delay_request(clock_identity: [u8; 8], delay_req_seq_id: u16, port319: &NetworkPort) {
    let ts = OffsetTime::now();
    let delay_req = MessageBuilder::new()
        .header(
            0,
            0,
            2,
            0,
            0,
            FlagField::default(),
            TimeInterval::default(),
            [0, 0, 0, 0],
            PortIdentity {
                clock_identity: ptp::datastructures::common::ClockIdentity(clock_identity),
                port_number: 0,
            },
            delay_req_seq_id,
            0x7F,
        )
        .unwrap()
        .delay_req_message(ts.to_timestamp().unwrap())
        .finish();
    let delay_req_encode = delay_req.serialize_vec().unwrap();
    port319.send(&delay_req_encode);
}
