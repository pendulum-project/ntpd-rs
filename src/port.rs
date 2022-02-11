use std::sync::mpsc::Sender;

use crate::{
    datastructures::{common::{ClockIdentity, PortIdentity}, messages::Message},
    network::{NetworkPacket, NetworkPort},
};



pub struct Port {
    port319: NetworkPort,
    port320: NetworkPort,

    identity: PortIdentity,
    sdo: u16,
    domain: u8,
}

impl Port {
    pub fn new(
        clock_identity: ClockIdentity,
        port_number: u16,
        sdo: u16,
        domain: u8,
        network_channel: &Sender<NetworkPacket>,
    ) -> Self {
        Port {
            port319: NetworkPort::new(319, network_channel.clone(), true),
            port320: NetworkPort::new(320, network_channel.clone(), false),

            identity: PortIdentity {
                clock_identity,
                port_number,
            },
            sdo,
            domain,
        }
    }

    pub fn handle_network(&self, packet: NetworkPacket) {
        self.process_message(packet);
    }

    fn process_message(&self, packet: NetworkPacket) ->  Option<()> {
        let message = Message::deserialize(&packet.data).ok()?;
        if message.header().sdo_id() != self.sdo || message.header().domain_number() != self.domain {
            return None
        }

        match message {
            _ => return None,
        }

        Some(())
    }
}
