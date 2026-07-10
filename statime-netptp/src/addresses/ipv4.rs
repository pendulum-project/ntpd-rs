use std::{
    io::Result,
    net::{Ipv4Addr, SocketAddrV4},
    pin::Pin,
    sync::Mutex,
    task::{Context, Poll},
};

use timestamped_socket::socket::{
    GeneralTimestampMode, InterfaceTimestampMode, Open, RecvResult, SendTimestampToken, Socket,
    TimestampData, open_ipv4,
};

use crate::{
    PtpAddressFamily,
    addresses::{BoundInterface, SealedPtpAddressFamily},
};

#[cfg(not(test))]
const EVENT_PORT: u16 = 319;
#[cfg(not(test))]
const GENERAL_PORT: u16 = 320;
#[cfg(test)]
const EVENT_PORT: u16 = 4319;
#[cfg(test)]
const GENERAL_PORT: u16 = 4320;

type RecvTimestampFuture =
    dyn Future<Output = Result<(SendTimestampToken, TimestampData)>> + Sync + Send + 'static;

pub(crate) struct Ipv4BoundInterface {
    general_socket: Socket<SocketAddrV4, Open>,
    event_socket: Socket<SocketAddrV4, Open>,
    recv_timestamp_future: Mutex<Pin<Box<RecvTimestampFuture>>>,
}

impl BoundInterface for Ipv4BoundInterface {
    type Addr = Ipv4Addr;

    fn open(
        interface: Option<timestamped_socket::interface::InterfaceName>,
        hardware_clock: Option<u32>,
    ) -> Result<Self> {
        let (event_socket, general_socket) = if let Some(interface) = interface {
            use timestamped_socket::socket::open_interface_udp4;

            let event_socket = open_interface_udp4(
                interface,
                EVENT_PORT,
                match hardware_clock {
                    Some(_) => InterfaceTimestampMode::SoftwareAll,
                    None => InterfaceTimestampMode::HardwarePTPAll,
                },
                hardware_clock,
            )?;
            let general_socket =
                open_interface_udp4(interface, GENERAL_PORT, InterfaceTimestampMode::None, None)?;
            (event_socket, general_socket)
        } else {
            let event_socket = open_ipv4(
                SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, EVENT_PORT),
                GeneralTimestampMode::SoftwareAll,
                true,
            )?;
            let general_socket = open_ipv4(
                SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, GENERAL_PORT),
                GeneralTimestampMode::None,
                true,
            )?;
            (event_socket, general_socket)
        };

        let recv_timestamp_future = Mutex::new(Box::into_pin(Box::new(
            event_socket.get_send_timestamp(),
        ) as Box<_>));

        Ok(Self {
            general_socket,
            event_socket,
            recv_timestamp_future,
        })
    }

    fn poll_send_event(
        &self,
        buf: &[u8],
        from: Option<Self::Addr>,
        to: Self::Addr,
        cx: &mut Context,
    ) -> Poll<Result<SendTimestampToken>> {
        if let Some(from) = from {
            self.event_socket.poll_send_from_to(
                buf,
                SocketAddrV4::new(from, EVENT_PORT),
                SocketAddrV4::new(to, EVENT_PORT),
                cx,
            )
        } else {
            self.event_socket
                .poll_send_to(buf, SocketAddrV4::new(to, EVENT_PORT), cx)
        }
        // The unwrap here will always succeed as the event socket will have timestamping enabled.
        .map_ok(Option::unwrap)
    }

    fn poll_send_general(
        &self,
        buf: &[u8],
        from: Option<Self::Addr>,
        to: Self::Addr,
        cx: &mut Context,
    ) -> Poll<Result<()>> {
        if let Some(from) = from {
            self.general_socket.poll_send_from_to(
                buf,
                SocketAddrV4::new(from, GENERAL_PORT),
                SocketAddrV4::new(to, GENERAL_PORT),
                cx,
            )
        } else {
            self.general_socket
                .poll_send_to(buf, SocketAddrV4::new(to, GENERAL_PORT), cx)
        }
        .map_ok(|_| ())
    }

    fn poll_recv(&self, buf: &mut [u8], cx: &mut Context) -> Poll<Result<RecvResult<Self::Addr>>> {
        loop {
            return if let Poll::Ready(result) = self.event_socket.poll_recv(buf, cx) {
                if let Ok(recv_result) = &result
                    && recv_result.remote_addr.port() != GENERAL_PORT
                    && recv_result.remote_addr.port() != EVENT_PORT
                {
                    // Ignore messages not sent from the PORTS we can send messages to.
                    // This avoids the potentially confusing situation of a message send
                    // from a random port triggering a response being send to port 319 or 320.
                    continue;
                }
                Poll::Ready(result)
            } else {
                self.general_socket.poll_recv(buf, cx)
            }
            .map_ok(|result| RecvResult {
                bytes_read: result.bytes_read,
                remote_addr: *result.remote_addr.ip(),
                local_addr: *result.local_addr.ip(),
                timestamp_data: result.timestamp_data,
            });
        }
    }

    fn poll_recv_timestamp(
        &self,
        cx: &mut Context,
    ) -> Poll<Result<(SendTimestampToken, TimestampData)>> {
        // The mutex can only be poisoned from an earlier panic. It is ok for
        // us to propagate that to all the threads.
        let mut recv_timestamp_future = self.recv_timestamp_future.lock().unwrap();
        let result = recv_timestamp_future.as_mut().poll(cx);
        if result.is_ready() {
            *recv_timestamp_future =
                Box::into_pin(Box::new(self.event_socket.get_send_timestamp()) as Box<_>);
        }

        result
    }
}

impl SealedPtpAddressFamily for Ipv4Addr {
    type BoundInterface = Ipv4BoundInterface;
}

impl PtpAddressFamily for Ipv4Addr {}
