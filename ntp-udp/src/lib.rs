mod interface_name;

use std::{
    io,
    io::{ErrorKind, IoSliceMut},
    mem::{size_of, MaybeUninit},
    net::{Ipv4Addr, SocketAddr},
    os::unix::prelude::AsRawFd,
};

use ntp_proto::NtpTimestamp;
use tokio::io::unix::AsyncFd;
use tracing::{debug, instrument, trace, warn};

enum Timestamping {
    Configure(TimestampingConfig),
    #[allow(dead_code)]
    AllSupported,
}

pub struct UdpSocket {
    io: AsyncFd<std::net::UdpSocket>,
    send_counter: u32,
    timestamping: TimestampingConfig,
}

impl UdpSocket {
    #[instrument(level = "debug", skip(peer_addr))]
    pub async fn client(listen_addr: SocketAddr, peer_addr: SocketAddr) -> io::Result<UdpSocket> {
        // disable tx timestamping for now (outside of tests)
        let timestamping = TimestampingConfig {
            rx_software: true,
            tx_software: false,
        };

        Self::client_with_timestamping(
            listen_addr,
            peer_addr,
            Timestamping::Configure(timestamping),
        )
        .await
    }

    async fn client_with_timestamping(
        listen_addr: SocketAddr,
        peer_addr: SocketAddr,
        timestamping: Timestamping,
    ) -> io::Result<UdpSocket> {
        let socket = tokio::net::UdpSocket::bind(listen_addr).await?;
        debug!(
            local_addr = debug(socket.local_addr().unwrap()),
            "client socket bound"
        );

        socket.connect(peer_addr).await?;
        debug!(
            local_addr = debug(socket.local_addr().unwrap()),
            peer_addr = debug(socket.peer_addr().unwrap()),
            "client socket connected"
        );

        let socket = socket.into_std()?;

        let timestamping = match timestamping {
            Timestamping::Configure(config) => config,
            Timestamping::AllSupported => TimestampingConfig::all_supported(&socket)?,
        };

        set_timestamping_options(&socket, timestamping)?;

        Ok(UdpSocket {
            io: AsyncFd::new(socket)?,
            send_counter: 0,
            timestamping,
        })
    }

    #[instrument(level = "debug")]
    pub async fn server(listen_addr: SocketAddr) -> io::Result<UdpSocket> {
        let socket = tokio::net::UdpSocket::bind(listen_addr).await?;
        debug!(
            local_addr = debug(socket.local_addr().unwrap()),
            "server socket bound"
        );

        let socket = socket.into_std()?;

        // our supported kernel versions always have receive timestamping. Send timestamping for a
        // server connection is not relevant, so we don't even bother with checking if it is supported
        let timestamping = TimestampingConfig {
            rx_software: true,
            tx_software: false,
        };

        set_timestamping_options(&socket, timestamping)?;

        Ok(UdpSocket {
            io: AsyncFd::new(socket)?,
            send_counter: 0,
            timestamping,
        })
    }

    #[instrument(level = "trace", skip(self, buf), fields(
        local_addr = debug(self.as_ref().local_addr().unwrap()),
        peer_addr = debug(self.as_ref().peer_addr()),
        buf_size = buf.len(),
    ))]
    pub async fn send(&mut self, buf: &[u8]) -> io::Result<(usize, Option<NtpTimestamp>)> {
        let send_size = self.send_help(buf).await?;
        let expected_counter = self.send_counter;
        self.send_counter = self.send_counter.wrapping_add(1);

        if self.timestamping.tx_software {
            // the send timestamp may never come set a very short timeout to prevent hanging forever.
            // We automatically fall back to a less accurate timestamp when this function returns None
            let timeout = std::time::Duration::from_millis(10);

            match tokio::time::timeout(timeout, self.fetch_send_timestamp(expected_counter)).await {
                Err(_) => {
                    warn!("Packet without timestamp");
                    Ok((send_size, None))
                }
                Ok(send_timestamp) => Ok((send_size, Some(send_timestamp?))),
            }
        } else {
            trace!("send timestamping not supported");
            Ok((send_size, None))
        }
    }

    async fn send_help(&self, buf: &[u8]) -> io::Result<usize> {
        trace!(size = buf.len(), "sending bytes");
        loop {
            let mut guard = self.io.writable().await?;
            match guard.try_io(|inner| inner.get_ref().send(buf)) {
                Ok(result) => match result {
                    Err(e) => {
                        debug!(error = debug(&e), "error sending data");
                        return Err(e);
                    }
                    Ok(size) => {
                        trace!(sent = size, "sent bytes");
                        return Ok(size);
                    }
                },
                Err(_would_block) => {
                    trace!("blocked after becoming writable, retrying");
                    continue;
                }
            }
        }
    }

    async fn fetch_send_timestamp(&self, expected_counter: u32) -> io::Result<NtpTimestamp> {
        trace!("waiting for timestamp socket to become readable to fetch a send timestamp");
        loop {
            // here we wait for the socket to become writable again, even though what we want to do
            // is read from the error queue.
            //
            // We found that waiting for `readable()` is unreliable, and does not seem to actually
            // fire when the timestamping message is available. To our understanding, the socked
            // becomes `writable()` when it has sent all its packets. So in practice this is also
            // the moment when the timestamp message is available in the error queue.
            let mut guard = self.io.writable().await?;
            match guard.try_io(|inner| fetch_send_timestamp_help(inner.get_ref(), expected_counter))
            {
                Ok(Ok(Some(send_timestamp))) => {
                    return Ok(send_timestamp);
                }
                Ok(Ok(None)) => {
                    continue;
                }
                Ok(Err(e)) => {
                    warn!(error = debug(&e), "Error fetching timestamp");
                    return Err(e);
                }
                Err(_would_block) => {
                    trace!("timestamp blocked after becoming readable, retrying");
                    continue;
                }
            }
        }
    }

    #[instrument(level = "trace", skip(self, buf), fields(
        local_addr = debug(self.as_ref().local_addr().unwrap()),
        buf_size = buf.len(),
    ))]
    pub async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        trace!(size = buf.len(), ?addr, "sending bytes");
        loop {
            let mut guard = self.io.writable().await?;
            match guard.try_io(|inner| inner.get_ref().send_to(buf, &addr)) {
                Ok(result) => {
                    match &result {
                        Ok(size) => trace!(sent = size, "sent bytes"),
                        Err(e) => debug!(error = debug(e), "error sending data"),
                    }
                    return result;
                }
                Err(_would_block) => {
                    trace!("blocked after becoming writable, retrying");
                    continue;
                }
            }
        }
    }

    #[instrument(level = "trace", skip(self, buf), fields(
        local_addr = debug(self.as_ref().local_addr().unwrap()),
        peer_addr = debug(self.as_ref().peer_addr().ok()),
        buf_size = buf.len(),
    ))]
    pub async fn recv(
        &self,
        buf: &mut [u8],
    ) -> io::Result<(usize, SocketAddr, Option<NtpTimestamp>)> {
        loop {
            trace!("waiting for socket to become readable");
            let mut guard = self.io.readable().await?;
            let result = match guard.try_io(|inner| recv(inner.get_ref(), buf)) {
                Err(_would_block) => {
                    trace!("blocked after becoming readable, retrying");
                    continue;
                }
                Ok(result) => result,
            };
            match &result {
                Ok((size, addr, ts)) => {
                    trace!(size, ts = debug(ts), addr = debug(addr), "received message")
                }
                Err(e) => debug!(error = debug(e), "error receiving data"),
            }
            return result;
        }
    }
}

impl AsRef<std::net::UdpSocket> for UdpSocket {
    fn as_ref(&self) -> &std::net::UdpSocket {
        self.io.get_ref()
    }
}

/// Makes the kernel return the timestamp as a cmsg alongside an empty packet,
/// as opposed to alongside the original packet
const SOF_TIMESTAMPING_OPT_TSONLY: u32 = 1 << 11;
/// Makes the kernel return a packet id in the error cmsg.
const SOF_TIMESTAMPING_OPT_ID: u32 = 1 << 7;

fn set_timestamping_options(
    udp_socket: &std::net::UdpSocket,
    timestamping: TimestampingConfig,
) -> io::Result<()> {
    let fd = udp_socket.as_raw_fd();

    let mut options = 0;

    if timestamping.rx_software || timestamping.tx_software {
        // enable software timestamping
        options |= libc::SOF_TIMESTAMPING_SOFTWARE
    }

    if timestamping.rx_software {
        // we want receive timestamps
        options |= libc::SOF_TIMESTAMPING_RX_SOFTWARE
    }

    if timestamping.tx_software {
        // - we want send timestamps
        // - return just the timestamp, don't send the full message along
        // - tag the timestamp with an ID
        options |= libc::SOF_TIMESTAMPING_TX_SOFTWARE
            | SOF_TIMESTAMPING_OPT_TSONLY
            | SOF_TIMESTAMPING_OPT_ID;
    }

    unsafe {
        cerr(libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TIMESTAMPING,
            &options as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        ))?
    };

    Ok(())
}

/// Turn a C failure (-1 is returned) into a rust Result
pub(crate) fn cerr(t: libc::c_int) -> std::io::Result<libc::c_int> {
    match t {
        -1 => Err(std::io::Error::last_os_error()),
        _ => Ok(t),
    }
}

fn read_ntp_timestamp(timespec: libc::timespec) -> NtpTimestamp {
    // Unix uses an epoch located at 1/1/1970-00:00h (UTC) and NTP uses 1/1/1900-00:00h.
    // This leads to an offset equivalent to 70 years in seconds
    // there are 17 leap years between the two dates so the offset is
    const EPOCH_OFFSET: u32 = (70 * 365 + 17) * 86400;

    // truncates the higher bits of the i64
    let seconds = (timespec.tv_sec as u32).wrapping_add(EPOCH_OFFSET);

    // tv_nsec is always within [0, 1e10)
    let nanos = timespec.tv_nsec as u32;

    NtpTimestamp::from_seconds_nanos_since_ntp_era(seconds, nanos)
}

/// Receive a message on a socket (retry if interrupted)
fn receive_message(
    socket: &std::net::UdpSocket,
    message_header: &mut libc::msghdr,
    flags: libc::c_int,
) -> io::Result<libc::c_int> {
    loop {
        match cerr(unsafe { libc::recvmsg(socket.as_raw_fd(), message_header, flags) } as _) {
            Err(e) if ErrorKind::Interrupted == e.kind() => {
                // retry when the recv was interrupted
                continue;
            }

            other => return other,
        }
    }
}

enum ControlMessage {
    Timestamping(libc::timespec),
    ReceiveError(libc::sock_extended_err),
    Other(libc::cmsghdr),
}

fn control_messages(message_header: &libc::msghdr) -> impl Iterator<Item = ControlMessage> + '_ {
    raw_control_messages(message_header).map(|msg| match (msg.cmsg_level, msg.cmsg_type) {
        (libc::SOL_SOCKET, libc::SO_TIMESTAMPING) => {
            // Safety: SO_TIMESTAMPING always has a timespec in the data
            let cmsg_data = unsafe { libc::CMSG_DATA(msg) } as *const libc::timespec;
            let timespec = unsafe { std::ptr::read_unaligned(cmsg_data) };
            ControlMessage::Timestamping(timespec)
        }

        (libc::SOL_IP, libc::IP_RECVERR) | (libc::SOL_IPV6, libc::IPV6_RECVERR) => {
            // this is part of how timestamps are reported.
            let error = unsafe {
                let ptr = libc::CMSG_DATA(msg) as *const libc::sock_extended_err;
                std::ptr::read_unaligned(ptr)
            };

            ControlMessage::ReceiveError(error)
        }
        _ => ControlMessage::Other(*msg),
    })
}

fn raw_control_messages(message_header: &libc::msghdr) -> impl Iterator<Item = &libc::cmsghdr> {
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(message_header).as_ref() };

    std::iter::from_fn(move || match cmsg {
        None => None,
        Some(current) => {
            cmsg = unsafe { libc::CMSG_NXTHDR(message_header, current).as_ref() };

            Some(current)
        }
    })
}

/// The space used to store a control message that contains a value of type T
const fn control_message_space<T>() -> usize {
    (unsafe { libc::CMSG_SPACE((std::mem::size_of::<T>()) as _) }) as usize
}

fn recv(
    socket: &std::net::UdpSocket,
    buf: &mut [u8],
) -> io::Result<(usize, SocketAddr, Option<NtpTimestamp>)> {
    let mut buf_slice = IoSliceMut::new(buf);

    let mut control_buf = [0; control_message_space::<[libc::timespec; 3]>()];
    let mut addr = MaybeUninit::<libc::sockaddr_storage>::uninit();
    let mut mhdr = libc::msghdr {
        msg_control: control_buf.as_mut_ptr().cast::<libc::c_void>(),
        msg_controllen: control_buf.len(),
        msg_iov: (&mut buf_slice as *mut IoSliceMut).cast::<libc::iovec>(),
        msg_iovlen: 1,
        msg_flags: 0,
        msg_name: addr.as_mut_ptr().cast::<libc::c_void>(),
        msg_namelen: size_of::<libc::sockaddr_storage>() as u32,
    };

    // loops for when we receive an interrupt during the recv
    let flags = 0;
    let bytes_read = receive_message(socket, &mut mhdr, flags)? as usize;

    let addr = unsafe { addr.assume_init() };
    let sock_addr = match addr.ss_family as i32 {
        libc::AF_INET => {
            // kernel assures us this conversion is safe
            let sin = &addr as *const _ as *const libc::c_void as *const libc::sockaddr_in;
            let sin = unsafe { &*sin };
            let [a, b, c, d] = sin.sin_addr.s_addr.to_ne_bytes();

            // no direct (u32, u16) conversion is available, so we convert the address first
            let addr = Ipv4Addr::new(a, b, c, d);
            SocketAddr::from((addr, u16::from_be_bytes(sin.sin_port.to_ne_bytes())))
        }
        libc::AF_INET6 => {
            // kernel assures us this conversion is safe
            let sin = &addr as *const _ as *const libc::c_void as *const libc::sockaddr_in6;
            let sin = unsafe { &*sin };
            SocketAddr::from((
                sin.sin6_addr.s6_addr,
                u16::from_be_bytes(sin.sin6_port.to_ne_bytes()),
            ))
        }
        _ => {
            unreachable!("We never constructed a non-ip socket");
        }
    };

    if mhdr.msg_flags & libc::MSG_TRUNC > 0 {
        warn!(
            max_len = buf.len(),
            "truncated packet because it was larger than expected",
        );
    }

    if mhdr.msg_flags & libc::MSG_CTRUNC > 0 {
        warn!("truncated control messages");
    }

    // Loops through the control messages, but we should only get a single message in practice
    for msg in control_messages(&mhdr) {
        match msg {
            ControlMessage::Timestamping(timespec) => {
                let timestamp = read_ntp_timestamp(timespec);

                return Ok((bytes_read, sock_addr, Some(timestamp)));
            }

            ControlMessage::ReceiveError(_error) => {
                warn!("unexpected error message on the MSG_ERRQUEUE");
            }

            ControlMessage::Other(msg) => {
                warn!(
                    msg.cmsg_level,
                    msg.cmsg_type, "unexpected message on the MSG_ERRQUEUE",
                );
            }
        }
    }

    Ok((bytes_read, sock_addr, None))
}

fn fetch_send_timestamp_help(
    socket: &std::net::UdpSocket,
    expected_counter: u32,
) -> io::Result<Option<NtpTimestamp>> {
    // we get back two control messages: one with the timestamp (just like a receive timestamp),
    // and one error message with no error reason. The payload for this second message is kind of
    // undocumented.
    //
    // section 2.1.1 of https://www.kernel.org/doc/Documentation/networking/timestamping.txt says that
    // a `sock_extended_err` is returned, but in practice we also see a socket address. The linux
    // kernel also has this https://github.com/torvalds/linux/blob/master/tools/testing/selftests/net/so_txtime.c#L153=
    //
    // sockaddr_storage is bigger than we need, but sockaddr is too small for ipv6
    const CONTROL_SIZE: usize = control_message_space::<[libc::timespec; 3]>()
        + control_message_space::<(libc::sock_extended_err, libc::sockaddr_storage)>();

    let mut control_buf = [0; CONTROL_SIZE];
    let mut mhdr = libc::msghdr {
        msg_control: control_buf.as_mut_ptr().cast::<libc::c_void>(),
        msg_controllen: control_buf.len(),
        msg_iov: std::ptr::null_mut(),
        msg_iovlen: 0,
        msg_flags: 0,
        msg_name: std::ptr::null_mut(),
        msg_namelen: 0,
    };

    receive_message(socket, &mut mhdr, libc::MSG_ERRQUEUE)?;

    if mhdr.msg_flags & libc::MSG_TRUNC > 0 {
        warn!("truncated packet because it was larger than expected",);
    }

    if mhdr.msg_flags & libc::MSG_CTRUNC > 0 {
        warn!("truncated control messages");
    }

    let mut send_ts = None;
    for msg in control_messages(&mhdr) {
        match msg {
            ControlMessage::Timestamping(timespec) => {
                send_ts = Some(read_ntp_timestamp(timespec));
            }

            ControlMessage::ReceiveError(error) => {
                // the timestamping does not set a message; if there is a message, that means
                // something else is wrong, and we want to know about it.
                if error.ee_errno as libc::c_int != libc::ENOMSG {
                    warn!(
                        expected_counter,
                        error.ee_data, "error message on the MSG_ERRQUEUE"
                    );
                }

                // Check that this message belongs to the send we are interested in
                if error.ee_data != expected_counter {
                    warn!(
                        error.ee_data,
                        expected_counter, "Timestamp for unrelated packet"
                    );
                    return Ok(None);
                }
            }

            ControlMessage::Other(msg) => {
                warn!(
                    msg.cmsg_level,
                    msg.cmsg_type, "unexpected message on the MSG_ERRQUEUE",
                );
            }
        }
    }

    Ok(send_ts)
}

#[derive(Debug, Clone, Copy, Default)]
struct TimestampingConfig {
    rx_software: bool,
    tx_software: bool,
}

#[repr(C)]
#[allow(non_camel_case_types)]
#[derive(Default)]
struct ethtool_ts_info {
    cmd: u32,
    so_timestamping: u32,
    phc_index: u32,
    tx_types: u32,
    tx_reserved: [u32; 3],
    rx_filters: u32,
    rx_reserved: [u32; 3],
}

#[repr(C)]
#[allow(non_camel_case_types)]
struct ifreq {
    ifrn_name: [u8; 16],
    ifru_data: *mut libc::c_void,
    __empty_space: [u8; 40 - 8],
}

impl TimestampingConfig {
    /// Enable all timestamping options that are supported by this crate and the hardware/software
    /// of the device we're running on
    #[allow(dead_code)]
    fn all_supported(udp_socket: &std::net::UdpSocket) -> std::io::Result<Self> {
        // Get time stamping and PHC info
        const ETHTOOL_GET_TS_INFO: u32 = 0x00000041;

        let mut tsi: ethtool_ts_info = ethtool_ts_info {
            cmd: ETHTOOL_GET_TS_INFO,
            ..Default::default()
        };

        let fd = udp_socket.as_raw_fd();

        if let Some(ifrn_name) = interface_name::interface_name(udp_socket.local_addr()?)? {
            let ifr: ifreq = ifreq {
                ifrn_name,
                ifru_data: (&mut tsi as *mut _) as *mut libc::c_void,
                __empty_space: [0; 40 - 8],
            };

            const SIOCETHTOOL: u64 = 0x8946;
            cerr(unsafe { libc::ioctl(fd, SIOCETHTOOL, &ifr) }).unwrap();

            let support = Self {
                rx_software: tsi.so_timestamping & libc::SOF_TIMESTAMPING_RX_SOFTWARE != 0,
                tx_software: tsi.so_timestamping & libc::SOF_TIMESTAMPING_TX_SOFTWARE != 0,
            };

            // per the documentation of `SOF_TIMESTAMPING_RX_SOFTWARE`:
            //
            // > Request rx timestamps when data enters the kernel. These timestamps are generated
            // > just after a device driver hands a packet to the kernel receive stack.
            //
            // the linux kernal should always support receive software timestamping
            assert!(support.rx_software);

            Ok(support)
        } else {
            Ok(Self::default())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timestamping_reasonable() {
        tokio_test::block_on(async {
            let mut a = UdpSocket::client_with_timestamping(
                SocketAddr::from((Ipv4Addr::LOCALHOST, 8000)),
                SocketAddr::from((Ipv4Addr::LOCALHOST, 8001)),
                Timestamping::AllSupported,
            )
            .await
            .unwrap();
            let b = UdpSocket::client(
                SocketAddr::from((Ipv4Addr::LOCALHOST, 8001)),
                SocketAddr::from((Ipv4Addr::LOCALHOST, 8000)),
            )
            .await
            .unwrap();

            tokio::spawn(async move {
                a.send(&[1; 48]).await.unwrap();
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                a.send(&[2; 48]).await.unwrap();
            });

            let mut buf = [0; 48];
            let (s1, _, t1) = b.recv(&mut buf).await.unwrap();
            let (s2, _, t2) = b.recv(&mut buf).await.unwrap();
            assert_eq!(s1, 48);
            assert_eq!(s2, 48);

            let t1 = t1.unwrap();
            let t2 = t2.unwrap();
            let delta = t2 - t1;

            assert!(delta.to_seconds() > 0.15 && delta.to_seconds() < 0.25);
        });
    }

    #[test]
    fn test_send_timestamp() {
        tokio_test::block_on(async {
            let mut a = UdpSocket::client_with_timestamping(
                SocketAddr::from((Ipv4Addr::LOCALHOST, 8012)),
                SocketAddr::from((Ipv4Addr::LOCALHOST, 8013)),
                Timestamping::AllSupported,
            )
            .await
            .unwrap();
            let b = UdpSocket::client(
                SocketAddr::from((Ipv4Addr::LOCALHOST, 8013)),
                SocketAddr::from((Ipv4Addr::LOCALHOST, 8012)),
            )
            .await
            .unwrap();

            let (ssend, tsend) = a.send(&[1; 48]).await.unwrap();
            let mut buf = [0; 48];
            let (srecv, _, trecv) = b.recv(&mut buf).await.unwrap();

            assert_eq!(ssend, 48);
            assert_eq!(srecv, 48);

            let tsend = tsend.unwrap();
            let trecv = trecv.unwrap();
            let delta = trecv - tsend;
            assert!(delta.to_seconds().abs() < 0.2);
        });
    }
}
