use fixed::traits::ToFixed;

use crate::datastructures::common::Timestamp;
use crate::datastructures::messages::{
    DelayRespMessage, FollowUpMessage, MessageBuilder, SyncMessage,
};
use crate::datastructures::{
    common::{ClockIdentity, PortIdentity},
    messages::Message,
};
use crate::network::{NetworkPacket, NetworkPort, NetworkRuntime};
use crate::time::{OffsetTime, TimeType};

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

pub struct PortData<NR: NetworkRuntime> {
    _runtime: NR,
    tc_port: NR::PortType,
    _nc_port: NR::PortType,

    delay_req_ids: IdSequencer,

    identity: PortIdentity,
    sdo: u16,
    domain: u8,
}

pub struct Port<NR: NetworkRuntime> {
    portdata: PortData<NR>,

    state: State,
}

#[derive(Debug, Default)]
struct StateSlave {
    remote_master: PortIdentity,
    mean_delay: Option<OffsetTime>,
    sync_id: Option<u16>,
    delay_id: Option<u16>,
    delay_send_id: Option<usize>,
    sync_correction: Option<OffsetTime>,
    sync_send_time: Option<OffsetTime>,
    sync_recv_time: Option<OffsetTime>,
    delay_send_time: Option<OffsetTime>,
    delay_recv_time: Option<OffsetTime>,
    next_delay_measurement: Option<OffsetTime>,
    pending_followup: Option<FollowUpMessage>,
}

impl StateSlave {
    fn handle_sync<NR: NetworkRuntime>(
        &mut self,
        port: &mut PortData<NR>,
        message: SyncMessage,
        timestamp: OffsetTime,
    ) -> Option<()> {
        self.sync_id = Some(message.header().sequence_id());
        self.sync_recv_time = Some(timestamp);
        self.delay_send_time = None;
        self.delay_recv_time = None;
        if message.header().two_step_flag() {
            self.sync_correction = Some(OffsetTime::from_interval(
                &message.header().correction_field(),
            ));
            self.sync_send_time = None;
        } else {
            self.sync_correction = None;
            self.sync_send_time = Some(
                OffsetTime::from_timestamp(&message.origin_timestamp())
                    + OffsetTime::from_interval(&message.header().correction_field()),
            );
        }
        if self.mean_delay == None || self.next_delay_measurement.unwrap_or_default() < timestamp {
            let delay_id = port.delay_req_ids.get();
            let delay_req = MessageBuilder::new()
                .source_port_identity(port.identity)
                .sequence_id(delay_id)
                .log_message_interval(0x7F)
                .delay_req_message(Timestamp::default());
            let delay_req_encode = delay_req.serialize_vec().unwrap();
            self.delay_send_id = Some(
                port.tc_port
                    .send(&delay_req_encode)
                    .expect("Program error: missing timestamp id"),
            );
            self.delay_id = Some(delay_id);
            self.mean_delay = None;
        } else {
            self.delay_id = None;
        }

        if let Some(follow_up) = self.pending_followup {
            self.handle_followup(follow_up);
        }

        Some(())
    }

    fn handle_followup(&mut self, message: FollowUpMessage) -> Option<()> {
        // Ignore messages not belonging to currently processing sync
        if self.sync_id != Some(message.header().sequence_id()) {
            self.pending_followup = Some(message); // Store it for a potentially coming sync
            return None;
        }

        // Remove any previous pending messages, they are no longer current
        self.pending_followup = None;

        // Absorb into state
        self.sync_send_time = Some(
            OffsetTime::from_timestamp(&message.precise_origin_timestamp())
                + OffsetTime::from_interval(&message.header().correction_field())
                + self.sync_correction?,
        );
        self.sync_correction = None;

        Some(())
    }

    fn handle_delayresp(&mut self, message: DelayRespMessage) -> Option<()> {
        // Ignore messages not belonging to currently processing sync
        if self.delay_id? != message.header().sequence_id() {
            return None;
        }

        // Absorb into state
        self.delay_recv_time = Some(
            OffsetTime::from_timestamp(&message.receive_timestamp())
                - OffsetTime::from_interval(&message.header().correction_field()),
        );

        // Calculate when we should next measure delay
        //  note that sync_recv_time should always be set here, but if it isn't,
        //  taking the default (0) is safe for recovery.
        self.next_delay_measurement = Some(
            self.sync_recv_time.unwrap_or_default()
                + (1 << message.header().log_message_interval()).to_fixed::<OffsetTime>()
                - 0.1.to_fixed::<OffsetTime>(),
        );

        self.finish_delay_measurement();

        Some(())
    }

    fn handle_message<NR: NetworkRuntime>(
        &mut self,
        port: &mut PortData<NR>,
        message: Message,
        timestamp: Option<OffsetTime>,
    ) -> Option<()> {
        if message.header().source_port_identity() != self.remote_master {
            return None;
        }

        match message {
            Message::Sync(message) => self.handle_sync(port, message, timestamp?),
            Message::FollowUp(message) => self.handle_followup(message),
            Message::DelayResp(message) => self.handle_delayresp(message),
            _ => None,
        }
    }

    fn handle_send_timestamp(&mut self, id: usize, timestamp: OffsetTime) -> Option<()> {
        if self.delay_send_id? == id {
            self.delay_send_time = Some(timestamp);
            self.delay_send_id = None;
            self.finish_delay_measurement();
            Some(())
        } else {
            None
        }
    }

    fn finish_delay_measurement(&mut self) -> Option<()> {
        self.mean_delay = Some(
            (self.sync_recv_time? - self.sync_send_time? + self.delay_recv_time?
                - self.delay_send_time?)
                / 2,
        );

        self.delay_send_time = None;
        self.delay_recv_time = None;
        self.delay_id = None;

        Some(())
    }

    fn extract_measurement(&mut self) -> Option<OffsetTime> {
        let result = self.sync_recv_time? - self.sync_send_time? - self.mean_delay?;

        self.sync_recv_time = None;
        self.sync_send_time = None;
        self.sync_id = None;

        Some(result)
    }
}

#[allow(clippy::large_enum_variant)]
enum State {
    Listening,
    Slave(StateSlave),
}

impl State {
    fn handle_message<NR: NetworkRuntime>(
        &mut self,
        port: &mut PortData<NR>,
        message: Message,
        timestamp: Option<OffsetTime>,
    ) -> Option<()> {
        match self {
            State::Slave(state) => state.handle_message(port, message, timestamp),
            _ => None,
        }
    }

    fn handle_send_timestamp(&mut self, id: usize, timestamp: OffsetTime) -> Option<()> {
        match self {
            State::Slave(state) => state.handle_send_timestamp(id, timestamp),
            _ => None,
        }
    }
}

impl<NR: NetworkRuntime> Port<NR> {
    pub fn new(
        clock_identity: ClockIdentity,
        port_number: u16,
        sdo: u16,
        domain: u8,
        runtime: NR,
        interface: NR::InterfaceDescriptor,
    ) -> Self {
        let tc_port = runtime
            .open(interface.clone(), true)
            .expect("Could not create time critical port");
        let nc_port = runtime
            .open(interface, false)
            .expect("Could not create non time critical port");
        Port {
            portdata: PortData {
                _runtime: runtime,

                tc_port,
                _nc_port: nc_port,

                delay_req_ids: IdSequencer::default(),

                identity: PortIdentity {
                    clock_identity,
                    port_number,
                },
                sdo,
                domain,
            },
            state: State::Listening,
        }
    }

    pub fn handle_network(&mut self, packet: NetworkPacket) {
        self.process_message(packet);
    }

    pub fn handle_send_timestamp(&mut self, id: usize, timestamp: OffsetTime) {
        self.state.handle_send_timestamp(id, timestamp);
    }

    fn process_message(&mut self, packet: NetworkPacket) -> Option<()> {
        let message = Message::deserialize(&packet.data).ok()?;
        if message.header().sdo_id() != self.portdata.sdo
            || message.header().domain_number() != self.portdata.domain
        {
            return None;
        }

        self.state
            .handle_message(&mut self.portdata, message, packet.timestamp);

        match message {
            Message::Announce(announce) => {
                if let State::Slave(inner) = &mut self.state {
                    inner.remote_master = announce.header().source_port_identity();
                } else {
                    self.state = State::Slave(StateSlave {
                        remote_master: announce.header().source_port_identity(),
                        ..Default::default()
                    })
                }
            }
            _ => {}
        };

        None
    }

    pub fn extract_measurement(&mut self) -> Option<OffsetTime> {
        match &mut self.state {
            State::Slave(state) => state.extract_measurement(),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use fixed::traits::ToFixed;

    use crate::datastructures::common::{PortIdentity, TimeInterval, Timestamp};
    use crate::datastructures::messages::MessageBuilder;
    use crate::network::test::TestRuntime;
    use crate::network::NetworkRuntime;

    use super::{IdSequencer, PortData, StateSlave};

    #[test]
    fn test_measurement_flow() {
        let network_runtime = TestRuntime::default();

        let master_id = PortIdentity::default();
        let mut test_id = PortIdentity::default();
        test_id.clock_identity.0[0] += 1;

        let mut test_state = StateSlave {
            remote_master: master_id,
            ..Default::default()
        };

        let mut test_port_data = PortData {
            _runtime: network_runtime.clone(),
            tc_port: network_runtime.open("".to_owned(), true).unwrap(),
            _nc_port: network_runtime.open("".to_owned(), false).unwrap(),
            delay_req_ids: IdSequencer::default(),
            identity: test_id,
            sdo: 0,
            domain: 0,
        };

        test_state.handle_message(
            &mut test_port_data,
            MessageBuilder::new()
                .sdo_id(0)
                .unwrap()
                .domain_number(0)
                .correction_field(TimeInterval((1 as i16).to_fixed()))
                .sync_message(Timestamp {
                    seconds: 0,
                    nanos: 0,
                }),
            Some((5 as i16).to_fixed()),
        );

        assert_eq!(test_state.extract_measurement(), None);

        let delay_req = network_runtime.get_sent().unwrap();
        test_state.handle_send_timestamp(delay_req.index, (7 as i16).to_fixed());

        assert_eq!(test_state.extract_measurement(), None);

        test_state.handle_message(
            &mut test_port_data,
            MessageBuilder::new()
                .sdo_id(0)
                .unwrap()
                .domain_number(0)
                .correction_field(TimeInterval((2 as i16).to_fixed()))
                .delay_resp_message(
                    Timestamp {
                        seconds: 0,
                        nanos: 11,
                    },
                    test_id,
                ),
            None,
        );

        assert_eq!(
            test_state.extract_measurement(),
            Some((1 as i16).to_fixed())
        );
    }

    #[test]
    fn test_measurement_flow_timestamps_out_of_order() {
        let network_runtime = TestRuntime::default();

        let master_id = PortIdentity::default();
        let mut test_id = PortIdentity::default();
        test_id.clock_identity.0[0] += 1;

        let mut test_state = StateSlave {
            remote_master: master_id,
            ..Default::default()
        };

        let mut test_port_data = PortData {
            _runtime: network_runtime.clone(),
            tc_port: network_runtime.open("".to_owned(), true).unwrap(),
            _nc_port: network_runtime.open("".to_owned(), false).unwrap(),
            delay_req_ids: IdSequencer::default(),
            identity: test_id,
            sdo: 0,
            domain: 0,
        };

        test_state.handle_message(
            &mut test_port_data,
            MessageBuilder::new()
                .sdo_id(0)
                .unwrap()
                .domain_number(0)
                .correction_field(TimeInterval((1 as i16).to_fixed()))
                .sync_message(Timestamp {
                    seconds: 0,
                    nanos: 0,
                }),
            Some((5 as i16).to_fixed()),
        );

        assert_eq!(test_state.extract_measurement(), None);

        let delay_req = network_runtime.get_sent().unwrap();

        test_state.handle_message(
            &mut test_port_data,
            MessageBuilder::new()
                .sdo_id(0)
                .unwrap()
                .domain_number(0)
                .correction_field(TimeInterval((2 as i16).to_fixed()))
                .delay_resp_message(
                    Timestamp {
                        seconds: 0,
                        nanos: 11,
                    },
                    test_id,
                ),
            None,
        );

        assert_eq!(test_state.extract_measurement(), None);

        test_state.handle_send_timestamp(delay_req.index, (7 as i16).to_fixed());

        assert_eq!(
            test_state.extract_measurement(),
            Some((1 as i16).to_fixed())
        );
    }

    #[test]
    fn test_measurement_flow_followup() {
        let network_runtime = TestRuntime::default();

        let master_id = PortIdentity::default();
        let mut test_id = PortIdentity::default();
        test_id.clock_identity.0[0] += 1;

        let mut test_state = StateSlave {
            remote_master: master_id,
            ..Default::default()
        };

        let mut test_port_data = PortData {
            _runtime: network_runtime.clone(),
            tc_port: network_runtime.open("".to_owned(), true).unwrap(),
            _nc_port: network_runtime.open("".to_owned(), false).unwrap(),
            delay_req_ids: IdSequencer::default(),
            identity: test_id,
            sdo: 0,
            domain: 0,
        };

        test_state.handle_message(
            &mut test_port_data,
            MessageBuilder::new()
                .sdo_id(0)
                .unwrap()
                .domain_number(0)
                .two_step_flag(true)
                .correction_field(TimeInterval((1 as i16).to_fixed()))
                .sync_message(Timestamp {
                    seconds: 0,
                    nanos: 0,
                }),
            Some((5 as i16).to_fixed()),
        );

        assert_eq!(test_state.extract_measurement(), None);

        test_state.handle_message(
            &mut test_port_data,
            MessageBuilder::new()
                .sdo_id(0)
                .unwrap()
                .domain_number(0)
                .two_step_flag(true)
                .correction_field(TimeInterval((1 as i16).to_fixed()))
                .follow_up_message(Timestamp {
                    seconds: 0,
                    nanos: 1,
                }),
            None,
        );

        assert_eq!(test_state.extract_measurement(), None);

        let delay_req = network_runtime.get_sent().unwrap();
        test_state.handle_send_timestamp(delay_req.index, (7 as i16).to_fixed());

        assert_eq!(test_state.extract_measurement(), None);

        test_state.handle_message(
            &mut test_port_data,
            MessageBuilder::new()
                .sdo_id(0)
                .unwrap()
                .domain_number(0)
                .correction_field(TimeInterval((2 as i16).to_fixed()))
                .delay_resp_message(
                    Timestamp {
                        seconds: 0,
                        nanos: 11,
                    },
                    test_id,
                ),
            None,
        );

        assert_eq!(
            test_state.extract_measurement(),
            Some((0 as i16).to_fixed())
        );
    }

    #[test]
    fn test_measurement_flow_followup_out_of_order() {
        let network_runtime = TestRuntime::default();

        let master_id = PortIdentity::default();
        let mut test_id = PortIdentity::default();
        test_id.clock_identity.0[0] += 1;

        let mut test_state = StateSlave {
            remote_master: master_id,
            ..Default::default()
        };

        let mut test_port_data = PortData {
            _runtime: network_runtime.clone(),
            tc_port: network_runtime.open("".to_owned(), true).unwrap(),
            _nc_port: network_runtime.open("".to_owned(), false).unwrap(),
            delay_req_ids: IdSequencer::default(),
            identity: test_id,
            sdo: 0,
            domain: 0,
        };

        test_state.handle_message(
            &mut test_port_data,
            MessageBuilder::new()
                .sdo_id(0)
                .unwrap()
                .domain_number(0)
                .two_step_flag(true)
                .correction_field(TimeInterval((1 as i16).to_fixed()))
                .follow_up_message(Timestamp {
                    seconds: 0,
                    nanos: 1,
                }),
            None,
        );

        assert_eq!(test_state.extract_measurement(), None);

        test_state.handle_message(
            &mut test_port_data,
            MessageBuilder::new()
                .sdo_id(0)
                .unwrap()
                .domain_number(0)
                .two_step_flag(true)
                .correction_field(TimeInterval((1 as i16).to_fixed()))
                .sync_message(Timestamp {
                    seconds: 0,
                    nanos: 0,
                }),
            Some((5 as i16).to_fixed()),
        );

        assert_eq!(test_state.extract_measurement(), None);

        let delay_req = network_runtime.get_sent().unwrap();
        test_state.handle_send_timestamp(delay_req.index, (7 as i16).to_fixed());

        assert_eq!(test_state.extract_measurement(), None);

        test_state.handle_message(
            &mut test_port_data,
            MessageBuilder::new()
                .sdo_id(0)
                .unwrap()
                .domain_number(0)
                .correction_field(TimeInterval((2 as i16).to_fixed()))
                .delay_resp_message(
                    Timestamp {
                        seconds: 0,
                        nanos: 11,
                    },
                    test_id,
                ),
            None,
        );

        assert_eq!(
            test_state.extract_measurement(),
            Some((0 as i16).to_fixed())
        );
    }
}
