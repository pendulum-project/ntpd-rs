//! Definitions and implementations of the abstract network types

use arrayvec::ArrayVec;

use crate::{datastructures::messages::MAX_DATA_LEN, time::Instant};

/// Abstraction for the network
///
/// With it the network ports can be opened
pub trait NetworkRuntime {
    /// A descriptor type for the interface to be used.
    /// Can be useful to select between e.g. ethernet and wifi if both are
    /// present on the machine or to select between IPv4 and IPv6.
    type InterfaceDescriptor: Clone;
    type NetworkPort: NetworkPort;
    type Error: core::fmt::Debug;

    /// Open a port on the given network interface.
    ///
    /// This port has a time-critical and non-time-critical component.
    ///
    /// For example, when using IPv4, there must be a connection to the
    /// multicast address 244.0.1.129. It needs two sockets. For the
    /// time-critical component port 319 must be used. For the other one port
    /// 320 is to be used.
    async fn open(
        &mut self,
        interface: Self::InterfaceDescriptor,
    ) -> Result<Self::NetworkPort, Self::Error>;
}

/// The representation of a network packet
#[derive(Debug, Clone)]
pub struct NetworkPacket {
    /// The received data of a network port
    pub data: ArrayVec<u8, MAX_DATA_LEN>,
    /// The timestamp at which the packet was received. This is preferrably a
    /// timestamp that has been reported by the network hardware.
    ///
    /// If the packet was received by a non-time-critical port, then this
    /// instant doesn't have to be very precise. Just requesting the
    /// timestamp in software is good enough.
    pub timestamp: Instant,
}

/// Abstraction for a port or socket
///
/// This object only has to be able to send a message because if a message is
/// received, it must be reported to the instance using the
/// [PtpInstance::handle_network](crate::ptp_instance::PtpInstance::handle_network)
/// function.
pub trait NetworkPort {
    type Error: core::fmt::Debug;

    /// Send the given non-time-critical data.
    async fn send(&mut self, data: &[u8]) -> Result<(), Self::Error>;

    /// Send the given time-critical data.
    ///
    /// If this is on a time-critical port, then the function must return an id
    /// and the TX timestamp must be reported to the instance using the
    /// [PtpInstance::handle_send_timestamp](crate::ptp_instance::PtpInstance::handle_send_timestamp)
    /// function using the same id that was returned.
    async fn send_time_critical(&mut self, data: &[u8]) -> Result<Option<Instant>, Self::Error>;

    /// Wait until a message is received
    ///
    /// # Cancel safety
    ///
    /// This method **MUST BE** cancel safe. Otherwise, if recv is used as the
    /// event in a select statement and some other branch completes first,
    /// it is not guaranteed that no messages were received on this socket.
    async fn recv(&mut self) -> Result<NetworkPacket, Self::Error>;
}
