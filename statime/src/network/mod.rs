//! Definitions and implementations of the abstract network types

use crate::time::Instant;

use alloc::vec::Vec;

#[cfg(test)]
pub mod test;

/// Abstraction for the network
///
/// With it the network ports can be opened
pub trait NetworkRuntime: Clone {
    /// A descriptor type for the interface to be used.
    /// Can be useful to select between e.g. ethernet and wifi if both are present on the machine
    /// or to select between IPv4 and IPv6.
    type InterfaceDescriptor: Clone;
    type PortType: NetworkPort;
    type Error: core::error::Error + core::fmt::Display;

    /// Open a port on the given network interface.
    ///
    /// It is only given whether or not this should be the time critical port.
    /// It is up to the implementation to use the right network setup.
    ///
    /// For example, when using IPv4, the socket should connect to the multicast address 244.0.1.129.
    /// If time_critical is true, then port 319 must be used. If not, then port 320 is to be used.
    fn open(
        &mut self,
        interface: Self::InterfaceDescriptor,
        time_critical: bool,
    ) -> Result<Self::PortType, Self::Error>;

    fn recv(&mut self) -> Result<NetworkPacket, Self::Error>;
}

/// The representation of a network packet
#[derive(Debug, Clone)]
pub struct NetworkPacket {
    /// The received data of a network port
    pub data: Vec<u8>,
    /// The timestamp at which the packet was received. This is preferrably a timestamp
    /// that has been reported by the network hardware.
    ///
    /// The timestamp must be Some when the packet comes from a time-critical port.
    /// The timestamp will be ignored when it comes from a non-time-critical port, so it may as well be None.
    pub timestamp: Option<Instant>,
}

/// Abstraction for a port or socket
///
/// This object only has to be able to send a message because if a message is received, it must be
/// reported to the instance using the [PtpInstance::handle_network](crate::ptp_instance::PtpInstance::handle_network) function.
pub trait NetworkPort {
    /// Send the given data.
    ///
    /// If this is on a time-critical port, then the function must return an id and the TX timestamp must be
    /// reported to the instance using the [PtpInstance::handle_send_timestamp](crate::ptp_instance::PtpInstance::handle_send_timestamp) function using the same id that was returned.
    fn send(&mut self, data: &[u8]) -> Option<usize>;
}
