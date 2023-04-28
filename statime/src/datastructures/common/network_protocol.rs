#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkProtocol {
    Reserved,
    UdpIPv4,
    UdpIPv6,
    IEEE802_3,
    DeviceNet,
    ControlNet,
    Profinet,
    ProfileSpecific(u16),
    #[default]
    Unknown,
}

impl NetworkProtocol {
    pub fn to_primitive(&self) -> u16 {
        match self {
            NetworkProtocol::Reserved => 0x0000,
            NetworkProtocol::UdpIPv4 => 0x0001,
            NetworkProtocol::UdpIPv6 => 0x0002,
            NetworkProtocol::IEEE802_3 => 0x0003,
            NetworkProtocol::DeviceNet => 0x0004,
            NetworkProtocol::ControlNet => 0x0005,
            NetworkProtocol::Profinet => 0x0006,
            NetworkProtocol::ProfileSpecific(value) => 0xf000 + value,
            NetworkProtocol::Unknown => 0xfffe,
        }
    }

    pub fn from_primitive(value: u16) -> Self {
        match value {
            0x0000 | 0x0007..=0xefff | 0xffff => Self::Reserved,
            0x0001 => Self::UdpIPv4,
            0x0002 => Self::UdpIPv6,
            0x0003 => Self::IEEE802_3,
            0x0004 => Self::DeviceNet,
            0x0005 => Self::ControlNet,
            0x0006 => Self::Profinet,
            0xf000..=0xfffd => Self::ProfileSpecific(value - 0xf000),
            0xfffe => NetworkProtocol::Unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_protocol_values() {
        for i in 0..u16::MAX {
            let protocol = NetworkProtocol::from_primitive(i);
            if !matches!(protocol, NetworkProtocol::Reserved) {
                assert_eq!(protocol.to_primitive(), i);
            }
        }

        assert_eq!(NetworkProtocol::ProfileSpecific(5).to_primitive(), 0xf005);
    }
}
