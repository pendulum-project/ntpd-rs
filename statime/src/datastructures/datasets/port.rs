use crate::datastructures::common::PortIdentity;
use crate::time::Duration;

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct PortDS {
    pub(crate) port_identity: PortIdentity,
    pub(crate) port_state: PortState,
    log_min_delay_req_interval: i8,
    mean_link_delay: Duration,
    pub(crate) log_announce_interval: i8,
    pub(crate) announce_receipt_timeout: u8,
    pub(crate) log_sync_interval: i8,
    delay_mechanism: DelayMechanism,
    log_min_p_delay_req_interval: i8,
    // TODO: u4
    version_number: u8,
    // TODO: u4
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
            port_state: PortState::Initializing,
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
}

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum PortState {
    #[default]
    Initializing = 0x01,
    Faulty = 0x02,
    Disabled = 0x03,
    Listening = 0x04,
    PreMaster = 0x05,
    Master = 0x06,
    Passive = 0x07,
    Uncalibrated = 0x08,
    Slave = 0x09,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum DelayMechanism {
    E2E = 0x01,
    P2P = 0x02,
    NoMechanism = 0xFE,
    CommonP2p = 0x03,
    Special = 0x04,
}
