use super::MessageType;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ControlField {
    Sync,
    DelayReq,
    FollowUp,
    DelayResp,
    Management,
    AllOthers,
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
