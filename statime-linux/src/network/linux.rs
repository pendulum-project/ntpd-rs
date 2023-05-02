//! Implementation of the abstract network types for the linux platform

use std::{
    io,
    io::{ErrorKind, IoSliceMut},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    os::fd::AsRawFd,
    str::FromStr,
};

use nix::sys::socket::{setsockopt, sockopt::ReuseAddr};
use set_timestamping_options::set_timestamping_options;
use statime::{
    clock::Clock,
    network::{NetworkPacket, NetworkPort, NetworkRuntime},
    time::Instant,
};
use tokio::io::{unix::AsyncFd, Interest};

use crate::{
    clock::{libc_timespec_into_instant, LinuxClock},
    network::control_message::control_message_space,
};

/// The time-critical port
const TC_PORT: u16 = 319;
/// The non-time-critical port
const NTC_PORT: u16 = 320;

#[derive(Debug, Clone, Copy)]
pub enum TimestampingMode {
    Hardware(InterfaceName),
    Software,
}

#[derive(Clone)]
pub struct LinuxRuntime {
    timestamping_mode: TimestampingMode,
    clock: LinuxClock,
}

impl LinuxRuntime {
    pub fn new(timestamping_mode: TimestampingMode, clock: &LinuxClock) -> Self {
        LinuxRuntime {
            timestamping_mode,
            clock: clock.clone(),
        }
    }

    const IPV6_PRIMARY_MULTICAST: Ipv6Addr = Ipv6Addr::new(0xff, 0x0e, 0, 0, 0, 0, 0x01, 0x81);
    const IPV6_PDELAY_MULTICAST: Ipv6Addr = Ipv6Addr::new(0xff, 0x02, 0, 0, 0, 0, 0, 0x6b);

    const IPV4_PRIMARY_MULTICAST: Ipv4Addr = Ipv4Addr::new(224, 0, 1, 129);
    const IPV4_PDELAY_MULTICAST: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 107);

    async fn bind_socket(
        interface_name: Option<InterfaceName>,
        addr: SocketAddr,
    ) -> Result<AsyncFd<std::net::UdpSocket>, NetworkError> {
        let socket = tokio::net::UdpSocket::bind(addr).await?;

        // We want to allow multiple listening sockets, as we bind to a specific
        // interface later
        setsockopt(socket.as_raw_fd(), ReuseAddr, &true).map_err(|_| NetworkError::UnknownError)?;

        // Bind device to specified interface
        if let Some(interface_name) = interface_name.as_ref() {
            let name = interface_name.as_str().as_bytes();

            // empty string does not work, `bind_device` should be skipped instead
            debug_assert!(!name.is_empty());

            socket.bind_device(Some(name))?;
        }

        Ok(AsyncFd::new(socket.into_std()?)?)
    }

    fn join_multicast(
        interface: &LinuxInterfaceDescriptor,
        socket: &std::net::UdpSocket,
    ) -> Result<SocketAddr, NetworkError> {
        let port = socket.local_addr()?.port();

        match interface.get_address()? {
            IpAddr::V4(ip) => {
                // TODO: multicast ttl limit for ipv4

                socket.join_multicast_v4(&Self::IPV4_PRIMARY_MULTICAST, &ip)?;
                socket.join_multicast_v4(&Self::IPV4_PDELAY_MULTICAST, &ip)?;

                Ok((Self::IPV4_PRIMARY_MULTICAST, port).into())
            }
            IpAddr::V6(_ip) => {
                // TODO: multicast hops limit for ipv6

                // 0 indicates any interface, though it is likely this interface does not
                // support multicast
                let if_index = interface.get_index().unwrap_or(0);

                socket.join_multicast_v6(&Self::IPV6_PRIMARY_MULTICAST, if_index)?;
                socket.join_multicast_v6(&Self::IPV6_PDELAY_MULTICAST, if_index)?;

                Ok((Self::IPV6_PRIMARY_MULTICAST, port).into())
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct LinuxInterfaceDescriptor {
    pub interface_name: Option<InterfaceName>,
    mode: LinuxNetworkMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxNetworkMode {
    Ipv4,
    Ipv6,
}

impl LinuxNetworkMode {
    fn unspecified_ip_addr(&self) -> IpAddr {
        match self {
            LinuxNetworkMode::Ipv4 => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            LinuxNetworkMode::Ipv6 => IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum NetworkError {
    #[error("Unknown error")]
    UnknownError,
    #[error("Not allowed to bind to port {0}")]
    NoBindPermission(u16),
    #[error("Socket bind port {0} already in use")]
    AddressInUse(u16),
    #[error("Could not bind socket to a specific device")]
    BindToDeviceFailed,
    #[error("Could not iterate over interfaces")]
    CannotIterateInterfaces,
    #[error("The specified interface does not exist")]
    InterfaceDoesNotExist,
    #[error("No more packets")]
    NoMorePackets,
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

impl LinuxInterfaceDescriptor {
    fn get_index(&self) -> Option<u32> {
        let name = self.interface_name.as_ref()?;

        // # SAFETY
        //
        // The pointer is valid and null-terminated
        match unsafe { libc::if_nametoindex(name.as_cstr().as_ptr()) } {
            0 => None,
            n => Some(n),
        }
    }

    fn get_address(&self) -> Result<IpAddr, NetworkError> {
        if let Some(name) = self.interface_name {
            let interfaces =
                InterfaceIterator::new().map_err(|_| NetworkError::CannotIterateInterfaces)?;

            interfaces
                .filter(|i| name == i.name)
                .filter_map(|i| i.socket_addr)
                .map(|socket_addr| socket_addr.ip())
                .find(|ip| match self.mode {
                    LinuxNetworkMode::Ipv4 => ip.is_ipv4(),
                    LinuxNetworkMode::Ipv6 => ip.is_ipv6(),
                })
                .ok_or(NetworkError::InterfaceDoesNotExist)
        } else {
            Ok(self.mode.unspecified_ip_addr())
        }
    }
}

impl FromStr for LinuxInterfaceDescriptor {
    type Err = NetworkError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut interfaces = match InterfaceIterator::new() {
            Ok(a) => a,
            Err(_) => return Err(NetworkError::CannotIterateInterfaces),
        };

        match std::net::IpAddr::from_str(s) {
            Ok(addr) => {
                if addr.is_unspecified() {
                    return Ok(LinuxInterfaceDescriptor {
                        interface_name: None,
                        mode: match addr {
                            IpAddr::V4(_) => LinuxNetworkMode::Ipv4,
                            IpAddr::V6(_) => LinuxNetworkMode::Ipv6,
                        },
                    });
                }

                interfaces
                    .find(|data| data.has_ip_addr(addr))
                    .map(|data| LinuxInterfaceDescriptor {
                        interface_name: Some(data.name),
                        mode: LinuxNetworkMode::Ipv4,
                    })
                    .ok_or(NetworkError::InterfaceDoesNotExist)
            }
            Err(_) => {
                if interfaces.any(|if_data| if_data.name.as_str() == s) {
                    // the interface name came straight from the OS, so it must be valid
                    let interface_name = InterfaceName::from_str(s).unwrap();

                    Ok(LinuxInterfaceDescriptor {
                        interface_name: Some(interface_name),
                        mode: LinuxNetworkMode::Ipv4,
                    })
                } else {
                    Err(NetworkError::InterfaceDoesNotExist)
                }
            }
        }
    }
}

impl NetworkRuntime for LinuxRuntime {
    type InterfaceDescriptor = LinuxInterfaceDescriptor;
    type NetworkPort = LinuxNetworkPort;
    type Error = NetworkError;

    async fn open(
        &mut self,
        interface: Self::InterfaceDescriptor,
    ) -> Result<<LinuxRuntime as NetworkRuntime>::NetworkPort, NetworkError> {
        log::info!(
            "Opening network port on '{}'",
            interface
                .interface_name
                .as_ref()
                .map(|if_name| if_name.as_str())
                .unwrap_or("Unknown")
        );

        let bind_ip = interface.mode.unspecified_ip_addr();
        let tc_addr = SocketAddr::new(bind_ip, TC_PORT);
        let ntc_addr = SocketAddr::new(bind_ip, NTC_PORT);

        log::info!("Binding time critical socket on {tc_addr}");
        log::info!("Binding non time critical socket on {ntc_addr}");

        let tc_socket = Self::bind_socket(interface.interface_name, tc_addr).await?;
        let ntc_socket = Self::bind_socket(interface.interface_name, ntc_addr).await?;

        let tc_address = Self::join_multicast(&interface, tc_socket.get_ref())?;
        let ntc_address = Self::join_multicast(&interface, ntc_socket.get_ref())?;

        // Setup timestamping

        set_timestamping_options(tc_socket.get_ref(), self.timestamping_mode)?;

        let tc_socket = TcUdpSocket::from_async_udp_socket(tc_socket).await?;

        Ok(LinuxNetworkPort {
            tc_socket,
            ntc_socket,
            tc_address,
            ntc_address,
            clock: self.clock.clone(),
        })
    }
}

mod set_timestamping_options {
    use std::os::unix::prelude::AsRawFd;

    use super::{cerr, TimestampingMode};
    use crate::network::linux_syscall::driver_enable_hardware_timestamping;

    fn configure_timestamping_socket(
        udp_socket: &std::net::UdpSocket,
        options: u32,
    ) -> std::io::Result<libc::c_int> {
        // Documentation on the timestamping calls:
        //
        // - linux: https://www.kernel.org/doc/Documentation/networking/timestamping.txt
        // - freebsd: https://man.freebsd.org/cgi/man.cgi?setsockopt
        //
        // SAFETY:
        //
        // - the socket is provided by (safe) rust, and will outlive the call
        // - method is guaranteed to be a valid "name" argument
        // - the options pointer outlives the call
        // - the `option_len` corresponds with the options pointer
        //
        // Only some bits are valid to set in `options`, but setting invalid bits is
        // perfectly safe
        //
        // > Setting other bit returns EINVAL and does not change the current state.
        unsafe {
            cerr(libc::setsockopt(
                udp_socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_TIMESTAMPING,
                &options as *const _ as *const libc::c_void,
                std::mem::size_of_val(&options) as libc::socklen_t,
            ))
        }
    }

    pub(crate) fn set_timestamping_options(
        udp_socket: &std::net::UdpSocket,
        timestamping_mode: TimestampingMode,
    ) -> std::io::Result<()> {
        // Setup timestamping
        let options = match timestamping_mode {
            TimestampingMode::Hardware(interface_name) => {
                // must explicitly enable hardware timestamping
                driver_enable_hardware_timestamping(udp_socket.as_raw_fd(), interface_name);

                libc::SOF_TIMESTAMPING_RAW_HARDWARE
                    | libc::SOF_TIMESTAMPING_RX_HARDWARE
                    | libc::SOF_TIMESTAMPING_TX_HARDWARE
                    | libc::SOF_TIMESTAMPING_OPT_TSONLY
                    | libc::SOF_TIMESTAMPING_OPT_ID
            }
            TimestampingMode::Software => {
                libc::SOF_TIMESTAMPING_SOFTWARE
                    | libc::SOF_TIMESTAMPING_RX_SOFTWARE
                    | libc::SOF_TIMESTAMPING_TX_SOFTWARE
                    | libc::SOF_TIMESTAMPING_OPT_TSONLY
                    | libc::SOF_TIMESTAMPING_OPT_ID
            }
        };

        configure_timestamping_socket(udp_socket, options)?;

        Ok(())
    }
}

mod exceptional_condition_fd {
    use std::os::unix::prelude::{AsRawFd, RawFd};

    use tokio::io::unix::AsyncFd;

    use super::cerr;

    // Tokio does not natively support polling for readiness of queues
    // other than the normal read queue (see also https://github.com/tokio-rs/tokio/issues/4885)
    // this works around that by creating a epoll fd that becomes
    // ready to read when the underlying fd has an event on its error queue.
    pub(crate) fn exceptional_condition_fd(
        socket_of_interest: &std::net::UdpSocket,
    ) -> std::io::Result<AsyncFd<RawFd>> {
        // Safety:
        // epoll_create1 is safe to call without flags
        let fd = cerr(unsafe { libc::epoll_create1(0) })?;

        let mut event = libc::epoll_event {
            events: libc::EPOLLERR as u32,
            u64: 0u64,
        };

        // Safety:
        // fd is a valid epoll fd from epoll_create1 in combination with the cerr check
        // since we have a reference to the socket_of_interest, its raw fd
        // is valid for the duration of this call, which is all that is
        // required for epoll (closing the fd later is safe!)
        // &mut event is a pointer to a memory region which we own for the duration
        // of the call, and thus ok to use.
        cerr(unsafe {
            libc::epoll_ctl(
                fd,
                libc::EPOLL_CTL_ADD,
                socket_of_interest.as_raw_fd(),
                &mut event,
            )
        })?;

        AsyncFd::new(fd)
    }
}

use std::os::unix::prelude::RawFd;

use exceptional_condition_fd::exceptional_condition_fd;

use super::{
    control_message::{
        empty_msghdr, zeroed_sockaddr_storage, ControlMessage, ControlMessageIterator, MessageQueue,
    },
    interface::{sockaddr_storage_to_socket_addr, InterfaceIterator, InterfaceName},
};

struct TcUdpSocket {
    io: AsyncFd<std::net::UdpSocket>,
    exceptional_condition: AsyncFd<RawFd>,
    send_counter: u32,
}

impl TcUdpSocket {
    async fn from_async_udp_socket(io: AsyncFd<std::net::UdpSocket>) -> std::io::Result<Self> {
        Ok(Self {
            exceptional_condition: exceptional_condition_fd(io.get_ref())?,
            io,
            send_counter: 0,
        })
    }

    async fn send(&mut self, data: &[u8], address: SocketAddr) -> std::io::Result<Option<Instant>> {
        self.send_to(data, address).await?;

        let expected_counter = self.send_counter;
        self.send_counter = self.send_counter.wrapping_add(1);

        self.fetch_send_timestamp(expected_counter).await
    }

    async fn send_to(&self, data: &[u8], address: SocketAddr) -> std::io::Result<usize> {
        let sender = |inner: &std::net::UdpSocket| inner.send_to(data, address);
        self.io.async_io(Interest::WRITABLE, sender).await
    }

    async fn fetch_send_timestamp(
        &self,
        expected_counter: u32,
    ) -> std::io::Result<Option<Instant>> {
        // the send timestamp may never come set a very short timeout to prevent hanging
        // forever. We automatically fall back to a less accurate timestamp when
        // this function returns None
        let timeout = std::time::Duration::from_millis(10);

        let fetch = self.fetch_send_timestamp_help(expected_counter);
        if let Ok(send_timestamp) = tokio::time::timeout(timeout, fetch).await {
            Ok(Some(send_timestamp?))
        } else {
            log::warn!("Packet without timestamp (waiting for timestamp timed out)");
            Ok(None)
        }
    }

    async fn fetch_send_timestamp_help(&self, expected_counter: u32) -> std::io::Result<Instant> {
        log::trace!("waiting for timestamp socket to become readable to fetch a send timestamp");

        // Send timestamps are sent to the udp socket's error queue. Sadly, tokio does
        // not currently support awaiting whether there is something in the
        // error queue see https://github.com/tokio-rs/tokio/issues/4885.
        //
        // Therefore, we manually configure an extra file descriptor to listen for
        // POLLPRI on the main udp socket. This `exceptional_condition` file
        // descriptor becomes readable when there is something in the error
        // queue.

        loop {
            let result = self
                .exceptional_condition
                .async_io(Interest::READABLE, |_| {
                    fetch_send_timestamp_help(self.io.get_ref(), expected_counter)
                })
                .await;

            match result {
                Ok(Some(send_timestamp)) => {
                    return Ok(send_timestamp);
                }
                Ok(None) => {
                    continue;
                }
                Err(e) => {
                    log::warn!("Error fetching timestamp: {e:?}");
                    return Err(e);
                }
            }
        }
    }
}

fn fetch_send_timestamp_help(
    socket: &std::net::UdpSocket,
    expected_counter: u32,
) -> io::Result<Option<Instant>> {
    // we get back two control messages: one with the timestamp (just like a receive
    // timestamp), and one error message with no error reason. The payload for
    // this second message is kind of undocumented.
    //
    // section 2.1.1 of https://www.kernel.org/doc/Documentation/networking/timestamping.txt says that
    // a `sock_extended_err` is returned, but in practice we also see a socket
    // address. The linux kernel also has this https://github.com/torvalds/linux/blob/master/tools/testing/selftests/net/so_txtime.c#L153=
    //
    // sockaddr_storage is bigger than we need, but sockaddr is too small for ipv6
    const CONTROL_SIZE: usize = control_message_space::<[libc::timespec; 3]>()
        + control_message_space::<(libc::sock_extended_err, libc::sockaddr_storage)>();

    let mut control_buf = [0; CONTROL_SIZE];

    let (_, control_messages, _) =
        receive_message(socket, &mut [], &mut control_buf, MessageQueue::Error)?;

    let mut send_ts = None;
    for msg in control_messages {
        match msg {
            ControlMessage::Timestamping(timestamp) => {
                send_ts = Some(timestamp);
            }

            ControlMessage::ReceiveError(error) => {
                // the timestamping does not set a message; if there is a message, that means
                // something else is wrong, and we want to know about it.
                if error.ee_errno as libc::c_int != libc::ENOMSG {
                    log::warn!(
                        "error message on the MSG_ERRQUEUE: expected message {}, it has error \
                         code {}",
                        expected_counter,
                        error.ee_data,
                    );
                }

                // Check that this message belongs to the send we are interested in
                if error.ee_data != expected_counter {
                    log::warn!(
                        "Timestamp for unrelated packet (expected = {}, actual = {})",
                        expected_counter,
                        error.ee_data,
                    );
                    return Ok(None);
                }
            }

            ControlMessage::Other(msg) => {
                log::warn!(
                    "unexpected message on the MSG_ERRQUEUE (level = {}, type = {})",
                    msg.cmsg_level,
                    msg.cmsg_type,
                );
            }
        }
    }

    Ok(send_ts.map(|ts| libc_timespec_into_instant(ts)))
}

pub struct LinuxNetworkPort {
    tc_socket: TcUdpSocket,
    ntc_socket: AsyncFd<std::net::UdpSocket>,
    tc_address: SocketAddr,
    ntc_address: SocketAddr,
    clock: LinuxClock,
}

impl NetworkPort for LinuxNetworkPort {
    type Error = std::io::Error;

    async fn send(&mut self, data: &[u8]) -> Result<(), <LinuxNetworkPort as NetworkPort>::Error> {
        log::trace!("Send NTC");

        let sender = |inner: &std::net::UdpSocket| inner.send_to(data, self.ntc_address);
        self.ntc_socket.async_io(Interest::WRITABLE, sender).await?;

        Ok(())
    }

    async fn send_time_critical(
        &mut self,
        data: &[u8],
    ) -> Result<statime::time::Instant, <LinuxNetworkPort as NetworkPort>::Error> {
        log::trace!("Send TC");

        let opt_instant = self.tc_socket.send(data, self.tc_address).await?;

        // TODO get a backup send timestamp from somewhere (it must be the same clock
        // used for timestamps!)
        Ok(opt_instant.unwrap())
    }

    async fn recv(&mut self) -> Result<NetworkPacket, <LinuxNetworkPort as NetworkPort>::Error> {
        let time_critical_future = self.tc_socket.io.async_io(Interest::READABLE, |inner| {
            let timestamp = Self::try_recv_message_with_timestamp(inner, &self.clock)?;

            log::trace!("Recv TC");

            Ok(timestamp)
        });

        let non_time_critical_future = async {
            let mut buffer = [0; 2048];
            let (received_len, _) = self
                .ntc_socket
                .async_io(Interest::READABLE, |inner| inner.recv_from(&mut buffer))
                .await?;
            log::trace!("Recv NTC");

            let data_too_long = |_| io::Error::new(ErrorKind::InvalidData, "too long");
            let data = buffer[..received_len].try_into().map_err(data_too_long)?;

            Ok(NetworkPacket {
                data,
                timestamp: self.clock.now(),
            })
        };

        tokio::select! {
            packet = time_critical_future => { packet }
            packet = non_time_critical_future => { packet }
        }
    }
}

pub(crate) fn receive_message<'a>(
    socket: &std::net::UdpSocket,
    packet_buf: &mut [u8],
    control_buf: &'a mut [u8],
    queue: MessageQueue,
) -> std::io::Result<(
    libc::c_int,
    impl Iterator<Item = ControlMessage> + 'a,
    Option<SocketAddr>,
)> {
    let mut buf_slice = IoSliceMut::new(packet_buf);
    let mut addr = zeroed_sockaddr_storage();

    let mut mhdr = empty_msghdr();

    mhdr.msg_control = control_buf.as_mut_ptr().cast::<libc::c_void>();
    mhdr.msg_controllen = control_buf.len() as _;
    mhdr.msg_iov = (&mut buf_slice as *mut IoSliceMut).cast::<libc::iovec>();
    mhdr.msg_iovlen = 1;
    mhdr.msg_flags = 0;
    mhdr.msg_name = (&mut addr as *mut libc::sockaddr_storage).cast::<libc::c_void>();
    mhdr.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as u32;

    let receive_flags = match queue {
        MessageQueue::Normal => 0,
        MessageQueue::Error => libc::MSG_ERRQUEUE,
    };

    // Safety:
    // We have a mutable reference to the control buffer for the duration of the
    // call, and controllen is also set to it's length.
    // IoSliceMut is ABI compatible with iovec, and we only have 1 which matches
    // iovlen msg_name is initialized to point to an owned sockaddr_storage and
    // msg_namelen is the size of sockaddr_storage
    // If one of the buffers is too small, recvmsg cuts off data at appropriate
    // boundary
    let sent_bytes = loop {
        match cerr(unsafe { libc::recvmsg(socket.as_raw_fd(), &mut mhdr, receive_flags) } as _) {
            Err(e) if std::io::ErrorKind::Interrupted == e.kind() => {
                // retry when the recv was interrupted
                continue;
            }
            Err(e) => return Err(e),
            Ok(sent) => break sent,
        }
    };

    if mhdr.msg_flags & libc::MSG_TRUNC > 0 {
        log::warn!(
            "truncated packet because it was larger than expected: {} bytes",
            packet_buf.len(),
        );
    }

    if mhdr.msg_flags & libc::MSG_CTRUNC > 0 {
        log::warn!("truncated control messages");
    }

    // Clear out the fields for which we are giving up the reference
    mhdr.msg_iov = std::ptr::null_mut();
    mhdr.msg_iovlen = 0;
    mhdr.msg_name = std::ptr::null_mut();
    mhdr.msg_namelen = 0;

    // Safety:
    // recvmsg ensures that the control buffer contains
    // a set of valid control messages and that controllen is
    // the length these take up in the buffer.
    Ok((
        sent_bytes,
        unsafe { ControlMessageIterator::new(mhdr) },
        sockaddr_storage_to_socket_addr(&addr),
    ))
}

impl LinuxNetworkPort {
    /// Do a manual receive on the time critical socket so we can get the
    /// hardware timestamps. Tokio doesn't have the capability to get the
    /// timestamp.
    ///
    /// This returns an option because there may not be a message
    fn try_recv_message_with_timestamp(
        tc_socket: &std::net::UdpSocket,
        clock: &LinuxClock,
    ) -> std::io::Result<NetworkPacket> {
        let mut read_buf = [0u8; 2048];
        let mut control_buf = [0; control_message_space::<[libc::timespec; 3]>()];

        // loops for when we receive an interrupt during the recv
        let (bytes_read, control_messages, _) = receive_message(
            tc_socket,
            &mut read_buf,
            &mut control_buf,
            MessageQueue::Normal,
        )?;

        let mut timestamp = clock.now();

        // Loops through the control messages, but we should only get a single message
        // in practice
        for msg in control_messages {
            match msg {
                ControlMessage::Timestamping(timespec) => {
                    timestamp = libc_timespec_into_instant(timespec);
                }

                ControlMessage::ReceiveError(_error) => {
                    log::warn!("unexpected error message on the MSG_ERRQUEUE");
                }

                ControlMessage::Other(msg) => {
                    log::warn!(
                        "unexpected message on the MSG_ERRQUEUE (level = {}, type = {})",
                        msg.cmsg_level,
                        msg.cmsg_type,
                    );
                }
            }
        }

        let data = read_buf[..bytes_read as usize]
            .try_into()
            .map_err(|_| io::Error::new(ErrorKind::InvalidData, "too long"))?;

        Ok(NetworkPacket { data, timestamp })
    }
}

pub fn get_clock_id() -> Option<[u8; 8]> {
    let candidates = InterfaceIterator::new()
        .unwrap()
        .filter_map(|data| data.mac);

    for mac in candidates {
        // Ignore multicast and locally administered mac addresses
        if mac[0] & 0x3 == 0 && mac.iter().any(|x| *x != 0) {
            let f = |i| mac.get(i).copied().unwrap_or_default();
            return Some(std::array::from_fn(f));
        }
    }

    None
}

/// Turn a C failure (-1 is returned) into a rust Result
pub(crate) fn cerr(t: libc::c_int) -> std::io::Result<libc::c_int> {
    match t {
        -1 => Err(std::io::Error::last_os_error()),
        _ => Ok(t),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn port_setup_ipv4() -> Result<(), Box<dyn std::error::Error>> {
        let port = 8000;

        let interface = LinuxInterfaceDescriptor {
            interface_name: None,
            mode: LinuxNetworkMode::Ipv4,
        };

        let addr = SocketAddr::new(interface.mode.unspecified_ip_addr(), port);

        let socket = LinuxRuntime::bind_socket(interface.interface_name, addr).await?;
        let address = LinuxRuntime::join_multicast(&interface, socket.get_ref())?;

        assert_ne!(address.ip(), interface.mode.unspecified_ip_addr());
        assert_eq!(address.port(), port);

        Ok(())
    }

    #[tokio::test]
    #[ignore = "gives an `invalid argument` OS error"]
    async fn port_setup_ipv6() -> Result<(), Box<dyn std::error::Error>> {
        let port = 8001;

        let interface = LinuxInterfaceDescriptor {
            interface_name: None,
            mode: LinuxNetworkMode::Ipv6,
        };

        let addr = SocketAddr::new(interface.mode.unspecified_ip_addr(), port);

        let socket = LinuxRuntime::bind_socket(interface.interface_name, addr).await?;
        let address = LinuxRuntime::join_multicast(&interface, socket.get_ref()).unwrap();

        assert_ne!(address.ip(), interface.mode.unspecified_ip_addr());
        assert_eq!(address.port(), port);

        Ok(())
    }

    #[tokio::test]
    async fn interface_index_ipv4() -> std::io::Result<()> {
        let interface = LinuxInterfaceDescriptor {
            interface_name: Some(InterfaceName::LOOPBACK),
            mode: LinuxNetworkMode::Ipv4,
        };

        assert!(interface.get_index().is_some());

        Ok(())
    }

    #[tokio::test]
    async fn interface_index_ipv6() -> std::io::Result<()> {
        let interface = LinuxInterfaceDescriptor {
            interface_name: Some(InterfaceName::LOOPBACK),
            mode: LinuxNetworkMode::Ipv6,
        };

        assert!(interface.get_index().is_some());

        Ok(())
    }

    #[tokio::test]
    async fn interface_index_invalid() -> std::io::Result<()> {
        let interface = LinuxInterfaceDescriptor {
            interface_name: Some(InterfaceName::INVALID),
            mode: LinuxNetworkMode::Ipv4,
        };

        assert!(interface.get_index().is_none());

        Ok(())
    }

    #[tokio::test]
    async fn get_address_ipv4_valid() -> Result<(), Box<dyn std::error::Error>> {
        let interface = LinuxInterfaceDescriptor {
            interface_name: Some(InterfaceName::LOOPBACK),
            mode: LinuxNetworkMode::Ipv4,
        };

        assert_eq!(interface.get_address()?, Ipv4Addr::LOCALHOST);

        Ok(())
    }

    #[tokio::test]
    async fn get_address_ipv6_valid() -> Result<(), Box<dyn std::error::Error>> {
        let interface = LinuxInterfaceDescriptor {
            interface_name: Some(InterfaceName::LOOPBACK),
            mode: LinuxNetworkMode::Ipv6,
        };

        assert_eq!(interface.get_address()?, Ipv6Addr::LOCALHOST);

        Ok(())
    }

    #[tokio::test]
    async fn get_address_ipv4_invalid() {
        let interface = LinuxInterfaceDescriptor {
            interface_name: Some(InterfaceName::from_str("invalid").unwrap()),
            mode: LinuxNetworkMode::Ipv4,
        };

        assert!(matches!(
            interface.get_address().unwrap_err(),
            NetworkError::InterfaceDoesNotExist
        ));
    }

    #[tokio::test]
    async fn get_address_ipv6_invalid() {
        let interface = LinuxInterfaceDescriptor {
            interface_name: Some(InterfaceName::from_str("invalid").unwrap()),
            mode: LinuxNetworkMode::Ipv6,
        };

        assert!(matches!(
            interface.get_address().unwrap_err(),
            NetworkError::InterfaceDoesNotExist
        ));
    }

    #[test]
    fn test_interface_from_str() {
        let interface = LinuxInterfaceDescriptor::from_str("0.0.0.0").unwrap();

        assert!(matches!(interface.mode, LinuxNetworkMode::Ipv4));
        assert!(interface.interface_name.is_none());

        let interface = LinuxInterfaceDescriptor::from_str("::").unwrap();

        assert!(matches!(interface.mode, LinuxNetworkMode::Ipv6));
        assert!(interface.interface_name.is_none());

        let interface = LinuxInterfaceDescriptor::from_str("lo").unwrap();

        assert!(matches!(interface.mode, LinuxNetworkMode::Ipv4));
        assert_eq!(interface.interface_name.unwrap(), InterfaceName::LOOPBACK);

        let error = LinuxInterfaceDescriptor::from_str("xxx").unwrap_err();

        assert!(matches!(error, NetworkError::InterfaceDoesNotExist));
    }
}
