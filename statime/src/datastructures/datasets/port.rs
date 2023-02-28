use crate::bmc::bmca::RecommendedState;
use crate::datastructures::common::PortIdentity;
use crate::port::state::{MasterState, PortState, SlaveState};
use crate::time::Duration;

#[derive(Debug)]
pub struct PortDS {
    pub(crate) port_identity: PortIdentity,
    pub(crate) port_state: PortState,
    log_min_delay_req_interval: i8,
    mean_link_delay: Duration,
    log_announce_interval: i8,
    pub(crate) announce_receipt_timeout: u8,
    log_sync_interval: i8,
    delay_mechanism: DelayMechanism,
    log_min_p_delay_req_interval: i8,
    version_number: u8,
    minor_version_number: u8,
    delay_asymmetry: Duration,
    pub(crate) port_enable: bool,
    master_only: bool,
}

impl PortDS {
    pub fn new(
        port_identity: PortIdentity,
        log_min_delay_req_interval: i8,
        log_announce_interval: i8,
        announce_receipt_timeout: u8,
        log_sync_interval: i8,
        delay_mechanism: DelayMechanism,
        log_min_p_delay_req_interval: i8,
        version_number: u8,
        minor_version_number: u8,
    ) -> Self {
        let mean_link_delay = match delay_mechanism {
            DelayMechanism::E2E | DelayMechanism::NoMechanism | DelayMechanism::Special => {
                Duration::ZERO
            }
            DelayMechanism::P2P => todo!(),
            DelayMechanism::CommonP2p => todo!(),
        };

        PortDS {
            port_identity,
            port_state: PortState::Listening,
            log_min_delay_req_interval,
            mean_link_delay,
            log_announce_interval,
            announce_receipt_timeout,
            log_sync_interval,
            delay_mechanism,
            log_min_p_delay_req_interval,
            version_number,
            minor_version_number,
            delay_asymmetry: Duration::ZERO,
            port_enable: true,
            master_only: false,
        }
    }

    pub fn min_delay_req_interval(&self) -> Duration {
        Duration::from_log_interval(self.log_min_delay_req_interval)
    }

    pub fn announce_interval(&self) -> Duration {
        Duration::from_log_interval(self.log_announce_interval)
    }

    pub fn sync_interval(&self) -> Duration {
        Duration::from_log_interval(self.log_sync_interval)
    }

    pub fn min_p_delay_req_interval(&self) -> Duration {
        Duration::from_log_interval(self.log_min_p_delay_req_interval)
    }

    // TODO: Count the actual number of passed announce intervals, rather than this approximation
    pub fn announce_receipt_interval(&self) -> Duration {
        Duration::from_log_interval(
            self.announce_receipt_timeout as i8 * self.log_announce_interval,
        )
    }

    pub fn set_forced_port_state(&mut self, state: PortState) {
        log::info!("new state for port: {} -> {}", self.port_state, state);
        self.port_state = state;
    }

    pub fn set_recommended_port_state(&mut self, recommended_state: &RecommendedState) {
        match recommended_state {
            // TODO set things like steps_removed once they are added
            // TODO make sure states are complete
            RecommendedState::S1(announce_message) => {
                let slave = SlaveState::new(announce_message.header().source_port_identity());
                let state = PortState::Slave(slave);

                match &self.port_state {
                    PortState::Listening
                    | PortState::Uncalibrated
                    | PortState::PreMaster
                    | PortState::Master(_)
                    | PortState::Passive => self.set_forced_port_state(state),
                    PortState::Slave(slave_state) => {
                        if slave_state.remote_master() != remote_master {
                            self.set_forced_port_state(state)
                        }
                    }
                    PortState::Initializing | PortState::Faulty | PortState::Disabled => {
                        unimplemented!()
                    }
                }
            }
            RecommendedState::M1(_) | RecommendedState::M2(_) | RecommendedState::M3(_) => {
                match self.port_state {
                    PortState::Listening
                    | PortState::Uncalibrated
                    | PortState::Slave(_)
                    | PortState::Passive => {
                        self.set_forced_port_state(PortState::Master(MasterState::new()))
                    }
                    PortState::PreMaster | PortState::Master(_) => (),
                    PortState::Initializing | PortState::Faulty | PortState::Disabled => {
                        unimplemented!()
                    }
                }
            }
            RecommendedState::P1(announce_message) | RecommendedState::P2(_) => {
                match self.port_state {
                    PortState::Listening
                    | PortState::Uncalibrated
                    | PortState::Slave(_)
                    | PortState::PreMaster
                    | PortState::Master(_) => self.set_forced_port_state(PortState::Passive),
                    PortState::Passive => (),
                    PortState::Initializing | PortState::Faulty | PortState::Disabled => {
                        unimplemented!()
                    }
                }
            }
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum DelayMechanism {
    E2E = 0x01,
    P2P = 0x02,
    NoMechanism = 0xFE,
    CommonP2p = 0x03,
    Special = 0x04,
}
