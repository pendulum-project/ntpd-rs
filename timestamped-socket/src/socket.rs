use std::{
    marker::PhantomData,
    net::{SocketAddr, SocketAddrV4, SocketAddrV6},
    os::fd::AsRawFd,
    sync::Arc,
};

use statime_base::{Timestamp, UniversalTimestamp, TAI, UTC};
use tokio::io::{unix::AsyncFd, Interest};

use crate::{
    control_message::{ControlMessage, MessageQueue, EXPECTED_MAX_CMSG_SIZE},
    interface::InterfaceName,
    networkaddress::{sealed::PrivateToken, MulticastJoinable, NetworkAddress},
    raw_socket::RawSocket,
};

#[cfg(not(any(target_os = "linux", target_os = "freebsd", target_os = "macos")))]
mod fallback;
#[cfg(target_os = "freebsd")]
mod freebsd;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;

#[cfg(not(any(target_os = "linux", target_os = "freebsd", target_os = "macos")))]
use self::fallback::configure_timestamping;
#[cfg(target_os = "freebsd")]
use self::freebsd::configure_timestamping;
#[cfg(target_os = "linux")]
pub use self::linux::*;
#[cfg(target_os = "macos")]
use self::macos::configure_timestamping;

/// Timestamps on a message returned by a socket.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Default)]
pub struct TimestampData {
    /// The timestamping mode requested by the user when creating the socket.
    ///
    /// If this was not available, this is set to `None`.
    pub timestamp_mode: InterfaceTimestampMode,
    /// The hardware based timestamp returned by the OS
    pub hardware: Option<Timestamp<TAI>>,
    /// The software based timestamp returned by the OS
    pub software: Option<Timestamp<UTC>>,
}

impl TimestampData {
    /// Creates a new `TimestampData` with the given requested timestamping mode, but no timestamps.
    fn empty(timestamp_mode: InterfaceTimestampMode) -> Self {
        Self::default().with_timestamp_mode(timestamp_mode)
    }

    /// Returns the timestamp type selected by the requested timestamping mode.
    ///
    /// If the requested timestamping mode is `None` or if the requested timestamp
    /// is not available, this function will return `None`.
    #[must_use]
    pub fn selected_timestamp(self) -> Option<UniversalTimestamp> {
        match self.timestamp_mode {
            InterfaceTimestampMode::SoftwareAll | InterfaceTimestampMode::SoftwareRecv => {
                self.software.map(UniversalTimestamp::from)
            }
            InterfaceTimestampMode::HardwareAll
            | InterfaceTimestampMode::HardwareRecv
            | InterfaceTimestampMode::HardwarePTPAll
            | InterfaceTimestampMode::HardwarePTPRecv => {
                self.hardware.map(UniversalTimestamp::from)
            }
            InterfaceTimestampMode::None => Option::None,
        }
    }

    /// Create a new `TimestampData` with the given requested timestamping mode.
    fn with_timestamp_mode(self, timestamp_mode: InterfaceTimestampMode) -> Self {
        Self {
            timestamp_mode,
            ..self
        }
    }
}

/// A timestamp mode usable on all sockets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum GeneralTimestampMode {
    /// Get kernel timestamps for both sending and receiving.
    SoftwareAll,
    /// Get kernel timestamps only for receiving.
    SoftwareRecv,
    /// Don't request any timestamps.
    #[default]
    None,
}

/// A timestamp mode for a specific hardware interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum InterfaceTimestampMode {
    /// Hardware timestamps for both sending and receiving of all messages.
    HardwareAll,
    /// Hardware timestamps for receiving of all messages.
    HardwareRecv,
    /// Hardware timestamps for both sending and receiving PTP messages.
    HardwarePTPAll,
    /// Hardware timestamps for receiving PTP Messages.
    HardwarePTPRecv,
    /// Kernel timestamps for sending and receiving.
    SoftwareAll,
    /// Kernel timestamps for receving.
    SoftwareRecv,
    /// Don't request any timestamps.
    #[default]
    None,
}

impl From<GeneralTimestampMode> for InterfaceTimestampMode {
    fn from(value: GeneralTimestampMode) -> Self {
        match value {
            GeneralTimestampMode::SoftwareAll => InterfaceTimestampMode::SoftwareAll,
            GeneralTimestampMode::SoftwareRecv => InterfaceTimestampMode::SoftwareRecv,
            GeneralTimestampMode::None => InterfaceTimestampMode::None,
        }
    }
}

/// Results from a receive operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RecvResult<A> {
    /// Number of bytes written to the provided buffer.
    pub bytes_read: usize,
    /// Address of the sender of the message.
    pub remote_addr: A,
    /// Address at which the message was received.
    pub local_addr: A,
    /// Timestamps for the message.
    pub timestamp_data: TimestampData,
}

/// A UDP network socket.
#[derive(Debug)]
pub struct Socket<A, S> {
    timestamp_mode: InterfaceTimestampMode,
    // FIXME: Remove the arc once tokio also allows polling asyncfds for the Error interest
    raw: Arc<AsyncFd<RawSocket>>,
    #[cfg(target_os = "linux")]
    send_counter: std::sync::Mutex<u32>,
    local_addr: A,
    _state: PhantomData<S>,
}

/// Marker type for sockets not bound to a specific remote.
#[non_exhaustive]
pub struct Open;
/// Marker type for sockets bound to a specific remote.
#[non_exhaustive]
pub struct Connected;

/// Token used to recognize the corresponding send timestamp for a split send operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SendTimestampToken(u32);

impl<A: NetworkAddress, S> Socket<A, S> {
    /// The local address at which the socket is listening.
    pub fn local_addr(&self) -> A {
        self.local_addr
    }

    fn inner_recv(&self, buf: &mut [u8], socket: &RawSocket) -> std::io::Result<RecvResult<A>> {
        let mut control_buf = [0; EXPECTED_MAX_CMSG_SIZE];

        // loops for when we receive an interrupt during the recv
        let (bytes_read, control_messages, remote_address) =
            socket.receive_message(buf, &mut control_buf, MessageQueue::Normal)?;

        let mut timestamp_data = TimestampData::empty(self.timestamp_mode);
        let mut local_addr = self.local_addr;

        // Loops through the control messages, but we should only get a single message
        // in practice
        for msg in control_messages {
            match msg {
                ControlMessage::Timestamping { software, hardware } => {
                    tracing::trace!("Timestamps: {:?} {:?}", software, hardware);

                    // Keep the first timestamp of each kind
                    timestamp_data.software = timestamp_data.software.or(software);
                    timestamp_data.hardware = timestamp_data.hardware.or(hardware);
                }

                #[cfg(target_os = "linux")]
                ControlMessage::ReceiveError(error) => {
                    tracing::debug!(
                        "unexpected error control message on receive: {}",
                        error.ee_errno
                    );
                }

                ControlMessage::DestinationIp(addr) => {
                    if let Some(addr) = A::from_ip_and_port(addr, self.local_addr.port()) {
                        local_addr = addr;
                    }
                }

                ControlMessage::Other(msg) => {
                    tracing::debug!(
                        "unexpected control message on receive: {} {}",
                        msg.cmsg_level,
                        msg.cmsg_type,
                    );
                }
            }
        }

        let remote_addr =
            A::from_sockaddr(remote_address, PrivateToken).ok_or(std::io::ErrorKind::Other)?;

        Ok(RecvResult {
            bytes_read,
            remote_addr,
            local_addr,
            timestamp_data,
        })
    }

    /// Poll to receive a packet on the socket.
    ///
    /// Note that on multiple calls to [`poll_recv`](Socket::poll_recv), only
    /// the [`Waker`](std::task::Waker) from the [`Context`](std::task::Context)
    /// on the most recent call is scheduled to receive a wakeup.
    pub fn poll_recv(
        &self,
        buf: &mut [u8],
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<RecvResult<A>>> {
        match self.raw.poll_read_ready(cx) {
            std::task::Poll::Ready(Ok(mut guard)) => {
                match guard.try_io(|inner| self.inner_recv(buf, inner.get_ref())) {
                    Ok(result) => std::task::Poll::Ready(result),
                    Err(_) => std::task::Poll::Pending,
                }
            }
            std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(e)),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }

    /// Receive a datagram.
    ///
    /// # Errors
    /// May return errors for previous send operations, or if it is no longer
    /// possible to receive on the given socket.
    pub async fn recv(&self, buf: &mut [u8]) -> std::io::Result<RecvResult<A>> {
        self.raw
            .async_io(Interest::READABLE, |socket| self.inner_recv(buf, socket))
            .await
    }

    fn send_inner(
        &self,
        send_call: impl FnOnce() -> std::io::Result<()>,
    ) -> std::io::Result<Option<SendTimestampToken>> {
        if matches!(
            self.timestamp_mode,
            InterfaceTimestampMode::HardwarePTPAll | InterfaceTimestampMode::SoftwareAll
        ) {
            #[cfg(target_os = "linux")]
            {
                let mut counter = self.send_counter.lock().unwrap();
                send_call()?;
                let token = SendTimestampToken(*counter);
                *counter = counter.wrapping_add(1);
                Ok(Some(token))
            }

            #[cfg(not(target_os = "linux"))]
            {
                unreachable!("Should not be able to create send timestamping sockets on platforms other than linux")
            }
        } else {
            send_call()?;
            Ok(None)
        }
    }

    /// Wait for the next send timestamp to be returned.
    ///
    /// Note: There is no poll variant for this function, as that is currently
    /// impossible to implement with the tools tokio provides. To compensate,
    /// the future returned here is independent of the self reference and can
    /// be stored to simulate the existence of a poll function.
    ///
    /// # Errors
    /// May fail if the timestamp is not available, or if the network had
    /// issues sending the message.
    pub fn get_send_timestamp(
        &self,
    ) -> impl std::future::Future<Output = std::io::Result<(SendTimestampToken, TimestampData)>>
           + Send
           + Sync
           + 'static {
        let timestamp_mode = self.timestamp_mode;
        let socket = self.raw.clone();
        async move {
            if matches!(
                timestamp_mode,
                InterfaceTimestampMode::HardwarePTPAll | InterfaceTimestampMode::SoftwareAll
            ) {
                #[cfg(target_os = "linux")]
                {
                    let (counter, timestamp) = Self::fetch_send_timestamp(socket).await?;
                    Ok((
                        SendTimestampToken(counter),
                        timestamp.with_timestamp_mode(timestamp_mode),
                    ))
                }

                #[cfg(not(target_os = "linux"))]
                {
                    let _ = socket;
                    unreachable!("Should not be able to create send timestamping sockets on platforms other than linux")
                }
            } else {
                Err(std::io::ErrorKind::Unsupported.into())
            }
        }
    }

    /// Retrieves the timestamp for a given [`SendTimestampToken`].
    ///
    /// If multiple tokens are still pending for a send timestamp, this function may
    /// drop the timestamps for those tokens . Therefore, this should not be used in
    /// contexts where the socket may also be polled or there may otherwise be multiple
    /// tokens in use.
    async fn send_timestamp_for_transmit(
        &mut self,
        token: SendTimestampToken,
    ) -> std::io::Result<TimestampData> {
        use std::time::Duration;

        const TIMEOUT: Duration = Duration::from_millis(200);

        tokio::time::timeout(TIMEOUT, async {
            loop {
                let (cur_token, timestamp_data) = self.get_send_timestamp().await?;
                if cur_token == token {
                    return Ok(timestamp_data.with_timestamp_mode(self.timestamp_mode));
                }
            }
        })
        .await
        .unwrap_or(Ok(TimestampData::empty(self.timestamp_mode)))
    }
}

impl<A: NetworkAddress> Socket<A, Open> {
    /// Send a packet to a given receiver on the socket.
    ///
    /// Note that on multiple calls to `poll_send_*`, only
    /// the [`Waker`](std::task::Waker) from the [`Context`](std::task::Context)
    /// on the most recent call is scheduled to receive a wakeup.
    pub fn poll_send_to(
        &self,
        buf: &[u8],
        addr: A,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<Option<SendTimestampToken>>> {
        let addr = addr.to_sockaddr(PrivateToken);

        match self.raw.poll_write_ready(cx) {
            std::task::Poll::Ready(Ok(mut guard)) => {
                match guard.try_io(|inner| self.send_inner(|| inner.get_ref().send_to(buf, addr))) {
                    Ok(result) => std::task::Poll::Ready(result),
                    Err(_) => std::task::Poll::Pending,
                }
            }
            std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(e)),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }

    /// Send a packet to a given receiver on the socket.
    ///
    /// When used in combination with the polling send functions, if there are timestamps
    /// pending for some `SendTimestampToken`, these may be skipped and become unavailable
    /// when calling this function.
    ///
    /// # Errors
    /// May fail if the remote cannot be reached.
    pub async fn send_to(&mut self, buf: &[u8], addr: A) -> std::io::Result<TimestampData> {
        let addr = addr.to_sockaddr(PrivateToken);

        if let Some(token) = self
            .raw
            .async_io(Interest::WRITABLE, |socket| {
                self.send_inner(|| socket.send_to(buf, addr))
            })
            .await?
        {
            self.send_timestamp_for_transmit(token).await
        } else {
            Ok(TimestampData::empty(self.timestamp_mode))
        }
    }

    /// Send a packet to a given receiver on the socket, using the specified origin address.
    ///
    /// Note that on multiple calls to `poll_send_*`, only
    /// the [`Waker`](std::task::Waker) from the [`Context`](std::task::Context)
    /// on the most recent call is scheduled to receive a wakeup.
    pub fn poll_send_from_to(
        &self,
        buf: &[u8],
        from: A,
        to: A,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<Option<SendTimestampToken>>> {
        let from = from.to_sockaddr(PrivateToken);
        let to = to.to_sockaddr(PrivateToken);

        match self.raw.poll_write_ready(cx) {
            std::task::Poll::Ready(Ok(mut guard)) => match guard
                .try_io(|inner| self.send_inner(|| inner.get_ref().send_from_to(buf, from, to)))
            {
                Ok(result) => std::task::Poll::Ready(result),
                Err(_) => std::task::Poll::Pending,
            },
            std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(e)),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }

    /// Send a packet to a given receiver on the socket, using the specified origin address.
    ///
    /// When used in combination with the polling send functions, if there are timestamps
    /// pending for some `SendTimestampToken`, these may be skipped and become unavailable
    /// when calling this function.
    ///
    /// # Errors
    /// May fail if the from or to address is not available or reachable.
    pub async fn send_from_to(
        &mut self,
        buf: &[u8],
        from: A,
        to: A,
    ) -> std::io::Result<TimestampData> {
        let from = from.to_sockaddr(PrivateToken);
        let to = to.to_sockaddr(PrivateToken);

        if let Some(token) = self
            .raw
            .async_io(Interest::WRITABLE, |socket| {
                self.send_inner(|| socket.send_from_to(buf, from, to))
            })
            .await?
        {
            self.send_timestamp_for_transmit(token).await
        } else {
            Ok(TimestampData::empty(self.timestamp_mode))
        }
    }

    /// Connect the socket to a specific remote.
    ///
    /// # Errors
    /// May fail if the remote is not reachable, or the network the
    /// socket is attached to is no longer available.
    pub fn connect(self, addr: A) -> std::io::Result<Socket<A, Connected>> {
        let addr = addr.to_sockaddr(PrivateToken);
        self.raw.get_ref().connect(addr)?;
        Ok(Socket {
            timestamp_mode: self.timestamp_mode,
            raw: self.raw,
            #[cfg(target_os = "linux")]
            send_counter: self.send_counter,
            local_addr: self.local_addr,
            _state: PhantomData,
        })
    }
}

impl<A: NetworkAddress> Socket<A, Connected> {
    /// Address of the remote to which this socket is connected.
    ///
    /// # Errors
    /// May error if the operating system cannot provide the addres
    /// of the peer.
    pub fn peer_addr(&self) -> std::io::Result<A> {
        let addr = self.raw.get_ref().getpeername()?;
        A::from_sockaddr(addr, PrivateToken).ok_or_else(|| std::io::ErrorKind::Other.into())
    }

    /// Send a packet on the socket.
    ///
    /// Note that on multiple calls to `poll_send_*`, only
    /// the [`Waker`](std::task::Waker) from the [`Context`](std::task::Context)
    /// on the most recent call is scheduled to receive a wakeup.
    pub fn poll_send(
        &self,
        buf: &[u8],
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<Option<SendTimestampToken>>> {
        match self.raw.poll_write_ready(cx) {
            std::task::Poll::Ready(Ok(mut guard)) => {
                match guard.try_io(|inner| self.send_inner(|| inner.get_ref().send(buf))) {
                    Ok(result) => std::task::Poll::Ready(result),
                    Err(_) => std::task::Poll::Pending,
                }
            }
            std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(e)),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }

    /// Send a packet on the socket.
    ///
    /// When used in combination with the polling send functions, if there are timestamps
    /// pending for some `SendTimestampToken`, these may be skipped and become unavailable
    /// when calling this function.
    ///
    /// # Errors
    /// May fail if the remote or network this socket is attached to is no longer available,
    /// or if the timestamp for the operation cannot be obtained.
    pub async fn send(&mut self, buf: &[u8]) -> std::io::Result<TimestampData> {
        if let Some(token) = self
            .raw
            .async_io(Interest::WRITABLE, |socket| {
                self.send_inner(|| socket.send(buf))
            })
            .await?
        {
            self.send_timestamp_for_transmit(token).await
        } else {
            Ok(TimestampData::empty(self.timestamp_mode))
        }
    }

    /// Send a packet on the socket.
    ///
    /// Note that on multiple calls to `poll_send_*`, only
    /// the [`Waker`](std::task::Waker) from the [`Context`](std::task::Context)
    /// on the most recent call is scheduled to receive a wakeup.
    pub fn poll_send_from(
        &self,
        buf: &[u8],
        from: A,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<Option<SendTimestampToken>>> {
        let from = from.to_sockaddr(PrivateToken);

        match self.raw.poll_write_ready(cx) {
            std::task::Poll::Ready(Ok(mut guard)) => match guard
                .try_io(|inner| self.send_inner(|| inner.get_ref().send_from(buf, from)))
            {
                Ok(result) => std::task::Poll::Ready(result),
                Err(_) => std::task::Poll::Pending,
            },
            std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(e)),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }

    /// Send a packet on the socket, with the given local address.
    ///
    /// When used in combination with the polling send functions, if there are timestamps
    /// pending for some `SendTimestampToken`, these may be skipped and become unavailable
    /// when calling this function.
    ///
    /// # Errors
    /// May error if the remote cannot be reached, or if the network the socket is attached
    /// to is no longer available.
    pub async fn send_from(&mut self, buf: &[u8], from: A) -> std::io::Result<TimestampData> {
        let from = from.to_sockaddr(PrivateToken);

        if let Some(token) = self
            .raw
            .async_io(Interest::WRITABLE, |socket| {
                self.send_inner(|| socket.send_from(buf, from))
            })
            .await?
        {
            self.send_timestamp_for_transmit(token).await
        } else {
            Ok(TimestampData::empty(self.timestamp_mode))
        }
    }
}

impl<A: MulticastJoinable, S> Socket<A, S> {
    /// Indicate that you want to receive messages for a specific multicast address on the socket.
    ///
    /// # Errors
    /// May error if it is not possible to unsubscribe from the given address.
    pub fn join_multicast(&self, addr: A, interface: InterfaceName) -> std::io::Result<()> {
        addr.join_multicast(self.raw.get_ref().as_raw_fd(), interface, PrivateToken)
    }

    /// Indicate that you no longer want to receive messages for a specific multicast address on the socket.
    ///
    /// # Errors
    /// May error if it is not possible to unsubscribe from the given address.
    pub fn leave_multicast(&self, addr: A, interface: InterfaceName) -> std::io::Result<()> {
        addr.leave_multicast(self.raw.get_ref().as_raw_fd(), interface, PrivateToken)
    }
}

/// Open a socket listening to a given ip address.
///
/// # Errors
/// May error if the requested timestamp mode is not possible, or if the requested addres is unavailable.
pub fn open_ip(
    addr: SocketAddr,
    timestamping: GeneralTimestampMode,
    #[cfg_attr(not(target_os = "linux"), expect(unused))] reuse_addr: bool,
) -> std::io::Result<Socket<SocketAddr, Open>> {
    // Setup the socket
    let socket = match addr {
        SocketAddr::V4(_) => RawSocket::open(libc::PF_INET, libc::SOCK_DGRAM, libc::IPPROTO_UDP),
        SocketAddr::V6(_) => RawSocket::open(libc::PF_INET6, libc::SOCK_DGRAM, libc::IPPROTO_UDP),
    }?;
    match addr {
        SocketAddr::V4(_) => socket.enable_destination_ipv4()?,
        SocketAddr::V6(_) => socket.enable_destination_ipv6()?,
    }
    #[cfg(target_os = "linux")]
    if reuse_addr {
        socket.reuse_addr()?;
    }
    socket.bind(addr.to_sockaddr(PrivateToken))?;
    socket.set_nonblocking(true)?;
    configure_timestamping(&socket, None, timestamping.into(), None)?;

    let local_addr = SocketAddr::from_sockaddr(socket.getsockname()?, PrivateToken)
        .ok_or::<std::io::Error>(std::io::ErrorKind::Other.into())?;

    Ok(Socket {
        timestamp_mode: timestamping.into(),
        raw: Arc::new(AsyncFd::new(socket)?),
        #[cfg(target_os = "linux")]
        send_counter: std::sync::Mutex::new(0),
        local_addr,
        _state: PhantomData,
    })
}

/// Open an ipv4 specific socket listening to a given ip address.
///
/// # Errors
/// May error if the requested timestamp mode is not possible, or if the requested addres is unavailable.
pub fn open_ipv4(
    addr: SocketAddrV4,
    timestamping: GeneralTimestampMode,
    #[cfg_attr(not(target_os = "linux"), expect(unused))] reuse_addr: bool,
) -> std::io::Result<Socket<SocketAddrV4, Open>> {
    // Setup the socket
    let socket = RawSocket::open(libc::PF_INET, libc::SOCK_DGRAM, libc::IPPROTO_UDP)?;
    socket.enable_destination_ipv4()?;
    #[cfg(target_os = "linux")]
    if reuse_addr {
        socket.reuse_addr()?;
    }
    socket.bind(addr.to_sockaddr(PrivateToken))?;
    socket.set_nonblocking(true)?;
    configure_timestamping(&socket, None, timestamping.into(), None)?;

    let local_addr = SocketAddrV4::from_sockaddr(socket.getsockname()?, PrivateToken)
        .ok_or::<std::io::Error>(std::io::ErrorKind::Other.into())?;

    Ok(Socket {
        timestamp_mode: timestamping.into(),
        raw: Arc::new(AsyncFd::new(socket)?),
        #[cfg(target_os = "linux")]
        send_counter: std::sync::Mutex::new(0),
        local_addr,
        _state: PhantomData,
    })
}

/// Open an ipv6 specific socket listening to a given ip address.
///
/// # Errors
/// May error if the requested timestamp mode is not possible, or if the requested addres is unavailable.
pub fn open_ipv6(
    addr: SocketAddrV6,
    timestamping: GeneralTimestampMode,
    #[cfg_attr(not(target_os = "linux"), expect(unused))] reuse_addr: bool,
) -> std::io::Result<Socket<SocketAddrV6, Open>> {
    // Setup the socket
    let socket = RawSocket::open(libc::PF_INET6, libc::SOCK_DGRAM, libc::IPPROTO_UDP)?;
    socket.ipv6_only()?;
    socket.enable_destination_ipv6()?;
    #[cfg(target_os = "linux")]
    if reuse_addr {
        socket.reuse_addr()?;
    }
    socket.bind(addr.to_sockaddr(PrivateToken))?;
    socket.set_nonblocking(true)?;
    configure_timestamping(&socket, None, timestamping.into(), None)?;

    let local_addr = SocketAddrV6::from_sockaddr(socket.getsockname()?, PrivateToken)
        .ok_or::<std::io::Error>(std::io::ErrorKind::Other.into())?;

    Ok(Socket {
        timestamp_mode: timestamping.into(),
        raw: Arc::new(AsyncFd::new(socket)?),
        #[cfg(target_os = "linux")]
        send_counter: std::sync::Mutex::new(0),
        local_addr,
        _state: PhantomData,
    })
}

/// Open a socket connected to the given remote address.
///
/// # Errors
/// Errors if it is not possible to setup the connection to the remote.
pub fn connect_address(
    addr: SocketAddr,
    timestamping: GeneralTimestampMode,
) -> std::io::Result<Socket<SocketAddr, Connected>> {
    // Setup the socket
    let socket = match addr {
        SocketAddr::V4(_) => RawSocket::open(libc::PF_INET, libc::SOCK_DGRAM, libc::IPPROTO_UDP),
        SocketAddr::V6(_) => RawSocket::open(libc::PF_INET6, libc::SOCK_DGRAM, libc::IPPROTO_UDP),
    }?;
    match addr {
        SocketAddr::V4(_) => socket.enable_destination_ipv4()?,
        SocketAddr::V6(_) => socket.enable_destination_ipv6()?,
    }
    socket.connect(addr.to_sockaddr(PrivateToken))?;
    socket.set_nonblocking(true)?;
    configure_timestamping(&socket, None, timestamping.into(), None)?;

    let local_addr = SocketAddr::from_sockaddr(socket.getsockname()?, PrivateToken)
        .ok_or::<std::io::Error>(std::io::ErrorKind::Other.into())?;

    Ok(Socket {
        timestamp_mode: timestamping.into(),
        raw: Arc::new(AsyncFd::new(socket)?),
        #[cfg(target_os = "linux")]
        send_counter: std::sync::Mutex::new(0),
        local_addr,
        _state: PhantomData,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[tokio::test]
    async fn test_open_ip() {
        let mut a = open_ip(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5125),
            GeneralTimestampMode::None,
            false,
        )
        .unwrap();
        let mut b = connect_address(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5125),
            GeneralTimestampMode::None,
        )
        .unwrap();
        assert!(b.send(&[1, 2, 3]).await.is_ok());
        let mut buf = [0; 4];
        let recv_result = a.recv(&mut buf).await.unwrap();
        assert_eq!(recv_result.bytes_read, 3);
        assert_eq!(&buf[0..3], &[1, 2, 3]);
        assert!(a.send_to(&[4, 5, 6], recv_result.remote_addr).await.is_ok());
        let recv_result = b.recv(&mut buf).await.unwrap();
        assert_eq!(recv_result.bytes_read, 3);
        assert_eq!(&buf[0..3], &[4, 5, 6]);
    }

    #[tokio::test]
    async fn test_open_ip_dest_addr() {
        let a = open_ip(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 5127),
            GeneralTimestampMode::None,
            false,
        )
        .unwrap();
        let mut b = connect_address(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5127),
            GeneralTimestampMode::None,
        )
        .unwrap();
        assert!(b.send(&[1, 2, 3]).await.is_ok());
        let mut buf = [0; 4];
        let recv_result = a.recv(&mut buf).await.unwrap();
        assert_eq!(recv_result.bytes_read, 3);
        assert_eq!(&buf[0..3], &[1, 2, 3]);
        assert_eq!(
            recv_result.local_addr,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5127)
        );
        assert_ne!(a.local_addr().ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));

        let a = open_ip(
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 5129),
            GeneralTimestampMode::None,
            false,
        )
        .unwrap();
        let mut b = connect_address(
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 5129),
            GeneralTimestampMode::None,
        )
        .unwrap();
        assert!(b.send(&[1, 2, 3]).await.is_ok());
        let mut buf = [0; 4];
        let recv_result = a.recv(&mut buf).await.unwrap();
        assert_eq!(recv_result.bytes_read, 3);
        assert_eq!(&buf[0..3], &[1, 2, 3]);
        assert_eq!(
            recv_result.local_addr,
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 5129)
        );
        assert_ne!(a.local_addr().ip(), IpAddr::V6(Ipv6Addr::LOCALHOST));
    }

    #[tokio::test]
    async fn test_send_from() {
        let mut a = open_ip(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 5130),
            GeneralTimestampMode::None,
            false,
        )
        .unwrap();
        let mut b = connect_address(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5130),
            GeneralTimestampMode::None,
        )
        .unwrap();
        b.send_from(
            &[1, 2, 3],
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        )
        .await
        .unwrap();
        let mut buf = [0; 4];
        let recv_result = a.recv(&mut buf).await.unwrap();
        assert_eq!(recv_result.bytes_read, 3);
        assert_eq!(&buf[0..3], &[1, 2, 3]);
        assert_eq!(
            recv_result.remote_addr.ip(),
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        );

        a.send_from_to(
            &[1, 2, 3],
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            dbg!(b.local_addr()),
        )
        .await
        .unwrap();
        let mut buf = [0; 4];
        let recv_result = b.recv(&mut buf).await.unwrap();
        assert_eq!(recv_result.bytes_read, 3);
        assert_eq!(&buf[0..3], &[1, 2, 3]);
        assert_eq!(
            recv_result.remote_addr.ip(),
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        );
    }

    #[tokio::test]
    async fn test_send_from_v6() {
        let mut a = open_ip(
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 5131),
            GeneralTimestampMode::None,
            false,
        )
        .unwrap();
        let mut b = connect_address(
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 5131),
            GeneralTimestampMode::None,
        )
        .unwrap();
        b.send_from(
            &[1, 2, 3],
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0),
        )
        .await
        .unwrap();
        let mut buf = [0; 4];
        let recv_result = a.recv(&mut buf).await.unwrap();
        assert_eq!(recv_result.bytes_read, 3);
        assert_eq!(&buf[0..3], &[1, 2, 3]);
        assert_eq!(
            recv_result.remote_addr.ip(),
            IpAddr::V6(Ipv6Addr::LOCALHOST)
        );

        a.send_from_to(
            &[1, 2, 3],
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0),
            dbg!(b.local_addr()),
        )
        .await
        .unwrap();
        let mut buf = [0; 4];
        let recv_result = b.recv(&mut buf).await.unwrap();
        assert_eq!(recv_result.bytes_read, 3);
        assert_eq!(&buf[0..3], &[1, 2, 3]);
        assert_eq!(
            recv_result.remote_addr.ip(),
            IpAddr::V6(Ipv6Addr::LOCALHOST)
        );
    }
}
