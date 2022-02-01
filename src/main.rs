use std::sync::mpsc::channel;

use statime::{
    datastructures::{
        common::{PortIdentity, TimeInterval},
        messages::{FlagField, Message, MessageBuilder, MessageContent},
        WireFormat,
    },
    network::{get_clock_id, NetworkPort},
    time::{OffsetTime, TimeType},
};

#[derive(Debug, Clone, Default)]
struct IdSequencer {
    cur_id: u16,
}

impl IdSequencer {
    pub fn get(&mut self) -> u16 {
        let result = self.cur_id;
        self.cur_id += 1;
        result
    }
}

#[derive(Debug, Clone, Default)]
struct SyncState {
    sync_id: Option<u16>,
    delay_id: Option<u16>,
    sync_correction: Option<OffsetTime>,
    sync_send_time: Option<OffsetTime>,
    sync_recv_time: Option<OffsetTime>,
    delay_send_time: Option<OffsetTime>,
    delay_recv_time: Option<OffsetTime>,
}

#[derive(Debug, Clone)]
struct TimeMeasurement {
    offset_master: OffsetTime,
    mean_delay: OffsetTime,
}

impl SyncState {
    pub fn handle_sync(&mut self, message: Message, recv_time: OffsetTime, delay_id: u16) {
        // TODO: Improve message datastructures to better be able to pass around messages of known type
        let content = match message.content() {
            MessageContent::Sync(content) => content,
            _ => panic!("wrong message type"),
        };

        self.sync_id = Some(message.header().sequence_id());
        self.delay_id = Some(delay_id);
        self.sync_recv_time = Some(recv_time);
        self.delay_send_time = None;
        self.delay_recv_time = None;
        if message.header().flag_field().two_step_flag {
            self.sync_correction = Some(OffsetTime::from_interval(
                &message.header().correction_field(),
            ));
            self.sync_send_time = None;
        } else {
            self.sync_correction = None;
            self.sync_send_time = Some(
                OffsetTime::from_timestamp(&content.origin_timestamp())
                    + OffsetTime::from_interval(&message.header().correction_field()),
            );
        }
    }

    pub fn handle_followup(&mut self, message: Message) {
        // TODO: Improve message datastructures to better be able to pass around messages of known type
        let content = match message.content() {
            MessageContent::FollowUp(content) => content,
            _ => panic!("wrong message type"),
        };

        // Ignore messages not belonging to currently processing sync
        let expected_seq_id = match self.sync_id {
            Some(id) => id,
            None => return,
        };
        if expected_seq_id != message.header().sequence_id() {
            return;
        }
        let sync_correction = match self.sync_correction {
            Some(correction) => correction,
            None => return,
        };

        // Absorb into state
        self.sync_correction = None;
        self.sync_send_time = Some(
            OffsetTime::from_timestamp(&content.precise_origin_timestamp())
                + OffsetTime::from_interval(&message.header().correction_field())
                + sync_correction,
        );
    }

    pub fn handle_delayreq(&mut self, message: Message, recv_time: OffsetTime) {
        // Ignore messages not belonging to currently processing sync
        let expected_seq_id = match self.delay_id {
            Some(id) => id,
            None => return,
        };
        if expected_seq_id != message.header().sequence_id() {
            return;
        }

        // Absorb into state
        self.delay_send_time = Some(recv_time);
    }

    pub fn handle_delayresp(&mut self, message: Message) {
        // TODO: Improve message datastructures to better be able to pass around messages of known type
        let content = match message.content() {
            MessageContent::DelayResp(content) => content,
            _ => panic!("wrong message type"),
        };

        // Ignore messages not belonging to currently processing sync
        let expected_seq_id = match self.delay_id {
            Some(id) => id,
            None => return,
        };
        if expected_seq_id != message.header().sequence_id() {
            return;
        }

        // Absorb into state
        self.delay_recv_time = Some(
            OffsetTime::from_timestamp(&content.receive_timestamp())
                - OffsetTime::from_interval(&message.header().correction_field()),
        );
    }

    pub fn extract_measurement(&mut self) -> Option<TimeMeasurement> {
        let sync_send_time = self.sync_send_time?;
        let sync_recv_time = self.sync_recv_time?;
        let delay_send_time = self.delay_send_time?;
        let delay_recv_time = self.delay_recv_time?;

        // Calculate measurement results
        let mean_delay = (sync_recv_time - sync_send_time + delay_recv_time - delay_send_time) / 2;
        let offset_master = sync_recv_time - sync_send_time - mean_delay;

        // Reset state
        self.sync_id = None;
        self.delay_id = None;
        self.sync_correction = None;
        self.sync_recv_time = None;
        self.sync_send_time = None;
        self.delay_recv_time = None;
        self.delay_send_time = None;

        Some(TimeMeasurement {
            mean_delay,
            offset_master,
        })
    }
}

fn main() {
    let (tx, rx) = channel();
    let port319 = NetworkPort::new(319, tx.clone(), true);
    let _port320 = NetworkPort::new(320, tx, false);

    let clock_identity = get_clock_id().unwrap();

    let mut delay_sequencer = IdSequencer::default();
    let mut sync_state = SyncState::default();

    loop {
        let packet = rx.recv().unwrap();
        let message = Message::deserialize(&packet.data).unwrap();
        match message.content() {
            MessageContent::Sync(_) => {
                let delay_id = delay_sequencer.get();
                send_delay_request(clock_identity, delay_id, &port319);
                sync_state.handle_sync(message, packet.timestamp.unwrap(), delay_id);
            }
            MessageContent::FollowUp(_) => {
                sync_state.handle_followup(message);
            }
            MessageContent::DelayReq(_) => {
                sync_state.handle_delayreq(message, packet.timestamp.unwrap());
            }
            MessageContent::DelayResp(_) => {
                sync_state.handle_delayresp(message);
            }
            _ => {
                if let Some(ts) = packet.timestamp {
                    println!("Received {:?} from {} at {}", message, packet.addr, ts);
                } else {
                    println!("Received {:?} from {}", message, packet.addr);
                }
            }
        }

        // See if we have a measurement
        if let Some(measurement) = sync_state.extract_measurement() {
            println!("Measurement {:?}", measurement);
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
            FlagField::default(),
            TimeInterval::default(),
            [0, 0, 0, 0],
            PortIdentity {
                clock_identity: statime::datastructures::common::ClockIdentity(clock_identity),
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
