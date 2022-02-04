use super::MessageType;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlField {
    Sync,
    DelayReq,
    FollowUp,
    DelayResp,
    Management,
    AllOthers,
    Reserved,
}

impl ControlField {
    pub fn to_primitive(&self) -> u8 {
        match self {
            ControlField::Sync => 0x00,
            ControlField::DelayReq => 0x01,
            ControlField::FollowUp => 0x02,
            ControlField::DelayResp => 0x03,
            ControlField::Management => 0x04,
            ControlField::AllOthers => 0x05,
            ControlField::Reserved => 0xFF,
        }
    }

    pub fn from_primitive(value: u8) -> Self {
        match value {
            0x00 => ControlField::Sync,
            0x01 => ControlField::DelayReq,
            0x02 => ControlField::FollowUp,
            0x03 => ControlField::DelayResp,
            0x04 => ControlField::Management,
            0x05 => ControlField::AllOthers,
            0x06..=0xFF => ControlField::Reserved,
        }
    }
}

impl From<MessageType> for ControlField {
    fn from(message_type: MessageType) -> Self {
        match message_type {
            MessageType::Sync => ControlField::Sync,
            MessageType::DelayReq => ControlField::DelayReq,
            MessageType::FollowUp => ControlField::FollowUp,
            MessageType::DelayResp => ControlField::DelayResp,
            MessageType::Management => ControlField::Management,
            _ => ControlField::AllOthers,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_protocol_values() {
        for i in 0..u8::MAX {
            let protocol = ControlField::from_primitive(i);
            if !matches!(protocol, ControlField::Reserved) {
                assert_eq!(protocol.to_primitive(), i);
            }
        }
    }
}
