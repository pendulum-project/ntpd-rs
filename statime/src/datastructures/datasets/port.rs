use crate::datastructures::common::PortIdentity;
use crate::time::Duration;

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct PortDS {
    port_identity: PortIdentity,
    pub(crate) port_state: PortState,
    log_min_delay_req_interval: i8,
    mean_link_delay: Duration,
    log_announce_interval: i8,
    announce_receipt_timeout: u8,
    log_sync_interval: i8,
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
