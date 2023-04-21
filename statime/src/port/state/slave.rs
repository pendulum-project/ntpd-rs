use crate::datastructures::common::{PortIdentity, Timestamp};
use crate::datastructures::datasets::DefaultDS;
use crate::datastructures::messages::{
    DelayRespMessage, FollowUpMessage, Message, MessageBuilder, SyncMessage,
};
use crate::network::NetworkPort;
use crate::port::sequence_id::SequenceIdGenerator;
use crate::port::Measurement;
use crate::time::{Duration, Instant};
use thiserror::Error;

type Result<T, E = SlaveError> = core::result::Result<T, E>;

#[derive(Debug)]
pub struct SlaveState {
    remote_master: PortIdentity,

    sync_state: SyncState,
    delay_state: DelayState,

    delay_req_ids: SequenceIdGenerator,

    next_delay_measurement: Option<Instant>,
    pending_followup: Option<FollowUpMessage>,
}

impl SlaveState {
    pub fn remote_master(&self) -> PortIdentity {
        self.remote_master
    }
}

#[derive(Debug, PartialEq, Eq)]
enum SyncState {
    Initial,
    AfterSync {
        sync_id: u16,
        sync_recv_time: Instant,
        sync_correction: Duration,
    },
    AfterFollowUp {
        sync_recv_time: Instant,
        sync_send_time: Instant,
    },
}

#[derive(Debug, PartialEq, Eq)]
enum DelayState {
    Initial,
    AfterSync {
        delay_id: u16,
        delay_send_time: Instant,
    },
    AfterDelayResp {
        mean_delay: Duration,
    },
}

impl DelayState {
    pub fn finished(&self) -> bool {
        match self {
            DelayState::Initial | DelayState::AfterSync { .. } => false,
            DelayState::AfterDelayResp { .. } => true,
        }
    }
}

impl SlaveState {
    pub fn new(remote_master: PortIdentity) -> Self {
        SlaveState {
            remote_master,
            sync_state: SyncState::Initial,
            delay_state: DelayState::Initial,
            delay_req_ids: SequenceIdGenerator::new(),
            next_delay_measurement: None,
            pending_followup: None,
        }
    }

    pub(crate) async fn handle_message<P: NetworkPort>(
        &mut self,
        message: Message,
        current_time: Instant,
        network_port: &mut P,
        port_identity: PortIdentity,
        default_ds: &DefaultDS,
    ) -> Result<()> {
        // Only listen to master
        if message.header().source_port_identity() == self.remote_master {
            match message {
                Message::Sync(message) => {
                    self.handle_sync(
                        message,
                        current_time,
                        network_port,
                        port_identity,
                        default_ds,
                    )
                    .await
                }
                Message::FollowUp(message) => self.handle_follow_up(message),
                Message::DelayResp(message) => self.handle_delay_resp(message, port_identity),
                _ => Err(SlaveError::UnexpectedMessage),
            }
        } else {
            Ok(())
        }
    }

    async fn handle_sync<P: NetworkPort>(
        &mut self,
        message: SyncMessage,
        current_time: Instant,
        network_port: &mut P,
        port_identity: PortIdentity,
        default_ds: &DefaultDS,
    ) -> Result<()> {
        log::debug!("Received sync {:?}", message.header().sequence_id());
        self.sync_state = if message.header().two_step_flag() {
            SyncState::AfterSync {
                sync_id: message.header().sequence_id(),
                sync_recv_time: current_time,
                sync_correction: Duration::from(message.header().correction_field()),
            }
        } else {
            SyncState::AfterFollowUp {
                sync_recv_time: current_time,
                sync_send_time: Instant::from(message.origin_timestamp())
                    + Duration::from(message.header().correction_field()),
            }
        };

        if !self.delay_state.finished()
            || self.next_delay_measurement.unwrap_or_default() < current_time
        {
            log::debug!("Starting new delay measurement");
            let delay_id = self.delay_req_ids.generate();
            let delay_req = MessageBuilder::new()
                .sdo_id(default_ds.sdo_id)
                .domain_number(default_ds.domain_number)
                .source_port_identity(port_identity)
                .sequence_id(delay_id)
                .log_message_interval(0x7F)
                .delay_req_message(Timestamp::default());
            let delay_req_encode = delay_req.serialize_vec().unwrap();
            let delay_send_time = network_port
                .send_time_critical(&delay_req_encode)
                .await
                .expect("Program error: missing timestamp id");
            self.delay_state = DelayState::AfterSync {
                delay_id,
                delay_send_time,
            };
        }

        if let Some(follow_up) = self.pending_followup {
            log::debug!("Trying previously received followup");
            self.handle_follow_up(follow_up)?;
        }

        Ok(())
    }

    fn handle_follow_up(&mut self, message: FollowUpMessage) -> Result<()> {
        log::debug!("Received FollowUp {:?}", message.header().sequence_id());
        match self.sync_state {
            SyncState::AfterSync {
                sync_id,
                sync_recv_time,
                sync_correction,
            } => {
                // Ignore messages not belonging to currently processing sync
                if sync_id == message.header().sequence_id() {
                    // Remove any previous pending messages, they are no longer current
                    self.pending_followup = None;

                    // Absorb into state
                    let sync_send_time = Instant::from(message.precise_origin_timestamp())
                        + Duration::from(message.header().correction_field())
                        + sync_correction;
                    self.sync_state = SyncState::AfterFollowUp {
                        sync_recv_time,
                        sync_send_time,
                    };

                    Ok(())
                } else {
                    // Store it for a potentially coming sync
                    self.pending_followup = Some(message);
                    Ok(())
                }
            }
            // Wrong state
            SyncState::Initial | SyncState::AfterFollowUp { .. } => {
                // Store it for a potentially coming sync
                log::debug!("FollowUp with no sync yet matching");
                self.pending_followup = Some(message);
                Ok(())
            }
        }
    }

    fn handle_delay_resp(
        &mut self,
        message: DelayRespMessage,
        port_identity: PortIdentity,
    ) -> Result<()> {
        log::debug!("Received DelayResp");
        match self.sync_state {
            SyncState::AfterFollowUp {
                sync_recv_time,
                sync_send_time,
            } => {
                match self.delay_state {
                    DelayState::AfterSync {
                        delay_id,
                        delay_send_time,
                    } => {
                        // Ignore responses not aimed at us
                        if port_identity != message.requesting_port_identity() {
                            return Ok(());
                        }

                        // Ignore messages not belonging to currently processing sync
                        if delay_id != message.header().sequence_id() {
                            log::warn!("Received delay response for different message");
                            return Ok(());
                        }

                        // Absorb into state
                        let delay_recv_time = Instant::from(message.receive_timestamp())
                            - Duration::from(message.header().correction_field());

                        // Calculate when we should next measure delay
                        //  note that sync_recv_time should always be set here, but if it isn't,
                        //  taking the default (0) is safe for recovery.
                        self.next_delay_measurement = Some(
                            sync_recv_time
                                + Duration::from_log_interval(
                                    message.header().log_message_interval(),
                                )
                                - Duration::from_fixed_nanos(0.1f64),
                        );

                        let mean_delay = (sync_recv_time - sync_send_time
                            + (delay_recv_time - delay_send_time))
                            / 2;

                        self.delay_state = DelayState::AfterDelayResp { mean_delay };

                        Ok(())
                    }
                    // Wrong state
                    DelayState::Initial | DelayState::AfterDelayResp { .. } => {
                        log::debug!("Unexpected DelayResponse");
                        Err(SlaveError::OutOfSequence)
                    }
                }
            }
            // Wrong state
            SyncState::Initial | SyncState::AfterSync { .. } => Err(SlaveError::OutOfSequence),
        }
    }

    pub(crate) fn extract_measurement(&mut self) -> Option<Measurement> {
        match self.sync_state {
            SyncState::AfterFollowUp {
                sync_recv_time,
                sync_send_time,
                ..
            } => {
                match self.delay_state {
                    DelayState::AfterDelayResp { mean_delay } => {
                        let result = Measurement {
                            master_offset: sync_recv_time - sync_send_time - mean_delay,
                            event_time: sync_recv_time,
                        };

                        self.sync_state = SyncState::Initial;

                        log::debug!("Extracted measurement {:?}", result);

                        Some(result)
                    }
                    // Wrong state
                    DelayState::Initial | DelayState::AfterSync { .. } => None,
                }
            }
            // Wrong state
            SyncState::Initial | SyncState::AfterSync { .. } => None,
        }
    }
}

#[derive(Debug, Error)]
pub enum SlaveError {
    #[error("received a message that a port in the slave state can never process")]
    UnexpectedMessage,
    #[error("received a message that can usually be processed, but not right now")]
    OutOfSequence,
}

#[cfg(test)]
mod tests {
    use std::vec::Vec;

    use crate::datastructures::{
        common::{ClockIdentity, TimeInterval},
        messages::{Header, SdoId},
    };

    use super::*;

    #[derive(Debug, Default)]
    struct TestNetworkPort {
        normal: Vec<Vec<u8>>,
        time: Vec<Vec<u8>>,

        current_time: Instant,
    }

    impl NetworkPort for TestNetworkPort {
        type Error = std::convert::Infallible;

        async fn send(&mut self, data: &[u8]) -> core::result::Result<(), Self::Error> {
            self.normal.push(Vec::from(data));
            Ok(())
        }

        async fn send_time_critical(
            &mut self,
            data: &[u8],
        ) -> core::result::Result<Instant, Self::Error> {
            self.time.push(Vec::from(data));
            Ok(self.current_time)
        }

        async fn recv(
            &mut self,
        ) -> core::result::Result<crate::network::NetworkPacket, Self::Error> {
            panic!("Recv shouldn't be called by state");
        }
    }

    #[test]
    fn test_sync_without_delay_msg() {
        let mut port = TestNetworkPort::default();

        let mut state = SlaveState::new(Default::default());
        state.delay_state = DelayState::AfterDelayResp {
            mean_delay: Duration::from_micros(100),
        };
        state.next_delay_measurement = Some(Instant::from_secs(10));

        let defaultds =
            DefaultDS::new_ordinary_clock(ClockIdentity::default(), 15, 128, 0, false, SdoId::default());

        embassy_futures::block_on(state.handle_message(
            Message::Sync(SyncMessage {
                header: Header {
                    two_step_flag: false,
                    correction_field: TimeInterval(1000.into()),
                    ..Default::default()
                },
                origin_timestamp: Instant::from_micros(0).into(),
            }),
            Instant::from_micros(50),
            &mut port,
            PortIdentity::default(),
            &defaultds,
        ))
        .unwrap();

        assert_eq!(port.normal.len(), 0);
        assert_eq!(port.time.len(), 0);
        assert_eq!(
            state.extract_measurement(),
            Some(Measurement {
                event_time: Instant::from_micros(50),
                master_offset: Duration::from_micros(-51)
            })
        );

        embassy_futures::block_on(state.handle_message(
            Message::Sync(SyncMessage {
                header: Header {
                    two_step_flag: true,
                    sequence_id: 15,
                    correction_field: TimeInterval(1000.into()),
                    ..Default::default()
                },
                origin_timestamp: Instant::from_micros(0).into(),
            }),
            Instant::from_micros(1050),
            &mut port,
            PortIdentity::default(),
            &defaultds,
        ))
        .unwrap();

        assert_eq!(port.normal.len(), 0);
        assert_eq!(port.time.len(), 0);
        assert_eq!(state.extract_measurement(), None);

        embassy_futures::block_on(state.handle_message(
            Message::FollowUp(FollowUpMessage {
                header: Header {
                    sequence_id: 15,
                    correction_field: TimeInterval(2000.into()),
                    ..Default::default()
                },
                precise_origin_timestamp: Instant::from_micros(1000).into(),
            }),
            Instant::from_micros(1100),
            &mut port,
            PortIdentity::default(),
            &defaultds,
        ))
        .unwrap();

        assert_eq!(port.normal.len(), 0);
        assert_eq!(port.time.len(), 0);
        assert_eq!(
            state.extract_measurement(),
            Some(Measurement {
                event_time: Instant::from_micros(1050),
                master_offset: Duration::from_micros(-53)
            })
        );
    }

    #[test]
    fn test_sync_with_delay() {
        let mut port = TestNetworkPort::default();

        let mut state = SlaveState::new(Default::default());

        let defaultds =
            DefaultDS::new_ordinary_clock(ClockIdentity::default(), 15, 128, 0, false, SdoId::default());

        port.current_time = Instant::from_micros(100);
        embassy_futures::block_on(state.handle_message(
            Message::Sync(SyncMessage {
                header: Header {
                    two_step_flag: false,
                    correction_field: TimeInterval(1000.into()),
                    ..Default::default()
                },
                origin_timestamp: Instant::from_micros(0).into(),
            }),
            Instant::from_micros(50),
            &mut port,
            PortIdentity::default(),
            &defaultds,
        ))
        .unwrap();

        assert_eq!(port.normal.len(), 0);
        assert_eq!(port.time.len(), 1);
        assert_eq!(state.extract_measurement(), None);

        let req = match Message::deserialize(&port.time.pop().unwrap()).unwrap() {
            Message::DelayReq(msg) => msg,
            _ => panic!("Incorrect message type"),
        };
        embassy_futures::block_on(state.handle_message(
            Message::DelayResp(DelayRespMessage {
                header: Header {
                    correction_field: TimeInterval(2000.into()),
                    sequence_id: req.header.sequence_id,
                    ..Default::default()
                },
                receive_timestamp: Instant::from_micros(253).into(),
                requesting_port_identity: req.header.source_port_identity(),
            }),
            Instant::from_micros(50),
            &mut port,
            PortIdentity::default(),
            &defaultds,
        ))
        .unwrap();

        assert_eq!(port.normal.len(), 0);
        assert_eq!(port.time.len(), 0);
        assert_eq!(
            state.delay_state,
            DelayState::AfterDelayResp {
                mean_delay: Duration::from_micros(100)
            }
        );
        assert_eq!(
            state.extract_measurement(),
            Some(Measurement {
                event_time: Instant::from_micros(50),
                master_offset: Duration::from_micros(-51)
            })
        );

        state.delay_state = DelayState::Initial;

        port.current_time = Instant::from_micros(1100);
        embassy_futures::block_on(state.handle_message(
            Message::Sync(SyncMessage {
                header: Header {
                    two_step_flag: true,
                    correction_field: TimeInterval(1000.into()),
                    ..Default::default()
                },
                origin_timestamp: Instant::from_micros(0).into(),
            }),
            Instant::from_micros(1050),
            &mut port,
            PortIdentity::default(),
            &defaultds,
        ))
        .unwrap();

        assert_eq!(port.normal.len(), 0);
        assert_eq!(port.time.len(), 1);
        assert_eq!(state.extract_measurement(), None);

        embassy_futures::block_on(state.handle_message(
            Message::FollowUp(FollowUpMessage {
                header: Header {
                    correction_field: TimeInterval(2000.into()),
                    ..Default::default()
                },
                precise_origin_timestamp: Instant::from_micros(1000).into(),
            }),
            Instant::from_micros(1150),
            &mut port,
            PortIdentity::default(),
            &defaultds,
        ))
        .unwrap();

        let req = match Message::deserialize(&port.time.pop().unwrap()).unwrap() {
            Message::DelayReq(msg) => msg,
            _ => panic!("Incorrect message type"),
        };
        embassy_futures::block_on(state.handle_message(
            Message::DelayResp(DelayRespMessage {
                header: Header {
                    correction_field: TimeInterval(2000.into()),
                    sequence_id: req.header.sequence_id,
                    ..Default::default()
                },
                receive_timestamp: Instant::from_micros(1255).into(),
                requesting_port_identity: req.header.source_port_identity(),
            }),
            Instant::from_micros(50),
            &mut port,
            PortIdentity::default(),
            &defaultds,
        ))
        .unwrap();

        assert_eq!(port.normal.len(), 0);
        assert_eq!(port.time.len(), 0);
        assert_eq!(
            state.delay_state,
            DelayState::AfterDelayResp {
                mean_delay: Duration::from_micros(100)
            }
        );
        assert_eq!(
            state.extract_measurement(),
            Some(Measurement {
                event_time: Instant::from_micros(1050),
                master_offset: Duration::from_micros(-53)
            })
        );
    }

    #[test]
    fn test_follow_up_before_sync() {
        let mut port = TestNetworkPort::default();

        let mut state = SlaveState::new(Default::default());
        state.delay_state = DelayState::AfterDelayResp {
            mean_delay: Duration::from_micros(100),
        };
        state.next_delay_measurement = Some(Instant::from_secs(10));

        let defaultds =
            DefaultDS::new_ordinary_clock(ClockIdentity::default(), 15, 128, 0, false, SdoId::default());

        embassy_futures::block_on(state.handle_message(
            Message::FollowUp(FollowUpMessage {
                header: Header {
                    sequence_id: 15,
                    correction_field: TimeInterval(2000.into()),
                    ..Default::default()
                },
                precise_origin_timestamp: Instant::from_micros(10).into(),
            }),
            Instant::from_micros(100),
            &mut port,
            PortIdentity::default(),
            &defaultds,
        ))
        .unwrap();

        assert_eq!(port.normal.len(), 0);
        assert_eq!(port.time.len(), 0);
        assert_eq!(state.extract_measurement(), None);

        embassy_futures::block_on(state.handle_message(
            Message::Sync(SyncMessage {
                header: Header {
                    two_step_flag: true,
                    sequence_id: 15,
                    correction_field: TimeInterval(1000.into()),
                    ..Default::default()
                },
                origin_timestamp: Instant::from_micros(0).into(),
            }),
            Instant::from_micros(50),
            &mut port,
            PortIdentity::default(),
            &defaultds,
        ))
        .unwrap();

        assert_eq!(port.normal.len(), 0);
        assert_eq!(port.time.len(), 0);
        assert_eq!(
            state.extract_measurement(),
            Some(Measurement {
                event_time: Instant::from_micros(50),
                master_offset: Duration::from_micros(-63)
            })
        );
    }

    #[test]
    fn test_old_followup_during() {
        let mut port = TestNetworkPort::default();

        let mut state = SlaveState::new(Default::default());
        state.delay_state = DelayState::AfterDelayResp {
            mean_delay: Duration::from_micros(100),
        };
        state.next_delay_measurement = Some(Instant::from_secs(10));

        let defaultds =
            DefaultDS::new_ordinary_clock(ClockIdentity::default(), 15, 128, 0, false, SdoId::default());

        embassy_futures::block_on(state.handle_message(
            Message::Sync(SyncMessage {
                header: Header {
                    two_step_flag: true,
                    sequence_id: 15,
                    correction_field: TimeInterval(1000.into()),
                    ..Default::default()
                },
                origin_timestamp: Instant::from_micros(0).into(),
            }),
            Instant::from_micros(50),
            &mut port,
            PortIdentity::default(),
            &defaultds,
        ))
        .unwrap();

        assert_eq!(port.normal.len(), 0);
        assert_eq!(port.time.len(), 0);
        assert_eq!(state.extract_measurement(), None);

        embassy_futures::block_on(state.handle_message(
            Message::FollowUp(FollowUpMessage {
                header: Header {
                    sequence_id: 14,
                    correction_field: TimeInterval(2000.into()),
                    ..Default::default()
                },
                precise_origin_timestamp: Instant::from_micros(10).into(),
            }),
            Instant::from_micros(100),
            &mut port,
            PortIdentity::default(),
            &defaultds,
        ))
        .unwrap();

        assert_eq!(port.normal.len(), 0);
        assert_eq!(port.time.len(), 0);
        assert_eq!(state.extract_measurement(), None);

        embassy_futures::block_on(state.handle_message(
            Message::FollowUp(FollowUpMessage {
                header: Header {
                    sequence_id: 15,
                    correction_field: TimeInterval(2000.into()),
                    ..Default::default()
                },
                precise_origin_timestamp: Instant::from_micros(10).into(),
            }),
            Instant::from_micros(100),
            &mut port,
            PortIdentity::default(),
            &defaultds,
        ))
        .unwrap();

        assert_eq!(port.normal.len(), 0);
        assert_eq!(port.time.len(), 0);
        assert_eq!(
            state.extract_measurement(),
            Some(Measurement {
                event_time: Instant::from_micros(50),
                master_offset: Duration::from_micros(-63)
            })
        );
    }

    #[test]
    fn test_reset_after_missing_followup() {
        let mut port = TestNetworkPort::default();

        let mut state = SlaveState::new(Default::default());
        state.delay_state = DelayState::AfterDelayResp {
            mean_delay: Duration::from_micros(100),
        };
        state.next_delay_measurement = Some(Instant::from_secs(10));

        let defaultds =
            DefaultDS::new_ordinary_clock(ClockIdentity::default(), 15, 128, 0, false, SdoId::default());

        embassy_futures::block_on(state.handle_message(
            Message::Sync(SyncMessage {
                header: Header {
                    two_step_flag: true,
                    sequence_id: 14,
                    correction_field: TimeInterval(1000.into()),
                    ..Default::default()
                },
                origin_timestamp: Instant::from_micros(0).into(),
            }),
            Instant::from_micros(50),
            &mut port,
            PortIdentity::default(),
            &defaultds,
        ))
        .unwrap();

        assert_eq!(port.normal.len(), 0);
        assert_eq!(port.time.len(), 0);
        assert_eq!(state.extract_measurement(), None);

        embassy_futures::block_on(state.handle_message(
            Message::Sync(SyncMessage {
                header: Header {
                    two_step_flag: true,
                    sequence_id: 15,
                    correction_field: TimeInterval(1000.into()),
                    ..Default::default()
                },
                origin_timestamp: Instant::from_micros(0).into(),
            }),
            Instant::from_micros(1050),
            &mut port,
            PortIdentity::default(),
            &defaultds,
        ))
        .unwrap();

        assert_eq!(port.normal.len(), 0);
        assert_eq!(port.time.len(), 0);
        assert_eq!(state.extract_measurement(), None);

        embassy_futures::block_on(state.handle_message(
            Message::FollowUp(FollowUpMessage {
                header: Header {
                    sequence_id: 15,
                    correction_field: TimeInterval(2000.into()),
                    ..Default::default()
                },
                precise_origin_timestamp: Instant::from_micros(1000).into(),
            }),
            Instant::from_micros(1100),
            &mut port,
            PortIdentity::default(),
            &defaultds,
        ))
        .unwrap();

        assert_eq!(port.normal.len(), 0);
        assert_eq!(port.time.len(), 0);
        assert_eq!(
            state.extract_measurement(),
            Some(Measurement {
                event_time: Instant::from_micros(1050),
                master_offset: Duration::from_micros(-53)
            })
        );
    }

    #[test]
    fn test_ignore_unrelated_delayresp() {
        let mut port = TestNetworkPort::default();

        let mut state = SlaveState::new(Default::default());

        let defaultds =
            DefaultDS::new_ordinary_clock(ClockIdentity::default(), 15, 128, 0, false, SdoId::default());

        port.current_time = Instant::from_micros(100);
        embassy_futures::block_on(state.handle_message(
            Message::Sync(SyncMessage {
                header: Header {
                    two_step_flag: false,
                    correction_field: TimeInterval(1000.into()),
                    ..Default::default()
                },
                origin_timestamp: Instant::from_micros(0).into(),
            }),
            Instant::from_micros(50),
            &mut port,
            PortIdentity::default(),
            &defaultds,
        ))
        .unwrap();

        assert_eq!(port.normal.len(), 0);
        assert_eq!(port.time.len(), 1);
        assert_eq!(state.extract_measurement(), None);

        let req = match Message::deserialize(&port.time.pop().unwrap()).unwrap() {
            Message::DelayReq(msg) => msg,
            _ => panic!("Incorrect message type"),
        };

        embassy_futures::block_on(state.handle_message(
            Message::DelayResp(DelayRespMessage {
                header: Header {
                    correction_field: TimeInterval(2000.into()),
                    sequence_id: req.header.sequence_id,
                    ..Default::default()
                },
                receive_timestamp: Instant::from_micros(353).into(),
                requesting_port_identity: PortIdentity {
                    port_number: 83,
                    ..Default::default()
                },
            }),
            Instant::from_micros(40),
            &mut port,
            PortIdentity::default(),
            &defaultds,
        ))
        .unwrap();

        assert_eq!(port.normal.len(), 0);
        assert_eq!(port.time.len(), 0);
        assert_eq!(state.extract_measurement(), None);

        embassy_futures::block_on(state.handle_message(
            Message::DelayResp(DelayRespMessage {
                header: Header {
                    correction_field: TimeInterval(2000.into()),
                    sequence_id: req.header.sequence_id.wrapping_sub(1),
                    ..Default::default()
                },
                receive_timestamp: Instant::from_micros(353).into(),
                requesting_port_identity: req.header.source_port_identity(),
            }),
            Instant::from_micros(40),
            &mut port,
            PortIdentity::default(),
            &defaultds,
        ))
        .unwrap();

        assert_eq!(port.normal.len(), 0);
        assert_eq!(port.time.len(), 0);
        assert_eq!(state.extract_measurement(), None);

        embassy_futures::block_on(state.handle_message(
            Message::DelayResp(DelayRespMessage {
                header: Header {
                    correction_field: TimeInterval(2000.into()),
                    sequence_id: req.header.sequence_id,
                    ..Default::default()
                },
                receive_timestamp: Instant::from_micros(253).into(),
                requesting_port_identity: req.header.source_port_identity(),
            }),
            Instant::from_micros(50),
            &mut port,
            PortIdentity::default(),
            &defaultds,
        ))
        .unwrap();

        assert_eq!(port.normal.len(), 0);
        assert_eq!(port.time.len(), 0);
        assert_eq!(
            state.delay_state,
            DelayState::AfterDelayResp {
                mean_delay: Duration::from_micros(100)
            }
        );
        assert_eq!(
            state.extract_measurement(),
            Some(Measurement {
                event_time: Instant::from_micros(50),
                master_offset: Duration::from_micros(-51)
            })
        );
    }
}
