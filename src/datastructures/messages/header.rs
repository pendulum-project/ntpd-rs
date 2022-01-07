use super::{flag_field::FlagField, MessageType};

pub struct Header {
    pub major_sdo_id: u8,
    pub message_type: MessageType,
    pub minor_version_ptp: u8,
    pub version_ptp: u8,
    pub message_length: u16,
    pub domain_number: u8,
    pub minor_sdo_id: u8,
    pub flag_field: FlagField,
    pub correction_field: u64,          // TODO
    pub message_type_specific: u32,     // TODO
    pub source_port_identity: [u8; 10], // TODO
    pub sequence_id: u16,
    pub control_field: u8,        // TODO
    pub log_message_interval: u8, // TODO
}
