use crate::datastructures::common::PortIdentity;
use crate::time::Duration;

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct PortDS {
    pub port_identity: PortIdentity,
    pub port_state: PortState,
    pub log_min_delay_req_interval: i8,
    pub mean_link_delay: Duration,
    pub log_announce_interval: i8,
    pub announce_receipt_timeout: u8,
    pub log_sync_interval: i8,
    pub delay_mechanism: DelayMechanism,
    pub log_min_p_delay_req_interval: i8,
    // TODO: u4
    pub version_number: u8,
    // TODO: u4
    pub minor_version_number: u8,
    pub delay_asymmetry: Duration,
    pub port_enable: bool,
    pub master_only: bool,
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
