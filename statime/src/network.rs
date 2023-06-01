//! Definitions and implementations of the abstract network types

use arrayvec::ArrayVec;

use crate::{datastructures::messages::MAX_DATA_LEN, time::Instant};

/// Abstract interface for interacting with the network.
///
/// Statime makes little assumption on how the network runs, and this trait is
/// the primary way it interacts with the network. Users of the library need to
/// provide this to enable the ptp stack to talk to the network. For linux,
/// the `statime-linux` crate provides an implementation of this trait.
pub trait NetworkRuntime {
    /// A descriptor type for the interface to be used.
    /// Can be useful to select between e.g. ethernet and wifi if both are
    /// present on the machine or to select between IPv4 and IPv6.
    type InterfaceDescriptor: Clone;

    /// An individual network interface connection. Note that this manages both
    /// the time critical and non-time critical parts of the network
    /// connection for ptp. For a typical setup, these will be bound to udp
    /// ports 319 and 320 of the ip address of the network interface requested
    /// by [open](NetworkRuntime::open).
    type NetworkPort: NetworkPort;

    /// Error type for the [open function](NetworkRuntime::open)
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

/// A single packet as received from the network.
///
/// The PTP stack uses this to track both the data and the time it was received
/// throughout processing.
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

/// Abstract representation of a single port's network connection
///
/// Network ports are obtained by the PTP stack from the [`NetworkRuntime`].
/// They provide for the actual sending and receiving of data from the network.
/// For PTP run over UDP, all time critical data should be sent over port 319,
/// and non time critical data over port 320. Only port 319 needs accurate
/// timestamps. Receives are for both network ports simultaneously.
pub trait NetworkPort {
    type Error: core::fmt::Debug;

    /// Send the given non-time-critical data.
    async fn send(&mut self, data: &[u8]) -> Result<(), Self::Error>;

    /// Send the given time-critical data.
    ///
    /// This function should send the given packet data out over the time
    /// critical part of the network connection. The returned instant should be
    /// its best estimate of when the data was actually sent out over the
    /// network. Note that the precision of this timestamp is one of the main
    /// limiting factors for synchronization precision, the other being
    /// stability of the system clock.
    async fn send_time_critical(&mut self, data: &[u8]) -> Result<Option<Instant>, Self::Error>;

    /// Wait until a message is received
    ///
    /// This future should wait until a network packet is received from either
    /// of the two network channels managed by this port.
    ///
    /// # Cancel safety
    ///
    /// This method **MUST BE** cancel safe. Otherwise, if recv is used as the
    /// event in a select statement and some other branch completes first,
    /// it is not guaranteed that no messages were received on this socket.
    async fn recv(&mut self) -> Result<NetworkPacket, Self::Error>;
}
