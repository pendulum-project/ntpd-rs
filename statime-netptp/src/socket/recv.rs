use std::{
    collections::HashMap,
    future::poll_fn,
    io::Result,
    sync::Arc,
    task::{Context, Poll, Waker},
};

use timestamped_socket::{interface::InterfaceName, socket::Timestamp};

use crate::{
    BoundInterface, ConnectedSocket, MAX_PACKET_SIZE, NetworkManagerData, OpenSocket,
    PtpAddressFamily, SocketData, TimestampSource,
};

/// Result from a receive operation.
///
/// Asside from the message, also provides context such as who sent it, to
/// which local address it was sent, and when it arrived.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RecvResult<A> {
    /// The actual received message
    pub bytes_read: Arc<[u8]>,
    /// The address of the remote which sent the message.
    pub remote_addr: A,
    /// The local address at which the message was targeted.
    pub local_addr: A,
    /// The moment at which the message was received, if available.
    pub timestamp: Option<Timestamp>,
}

impl<A: PtpAddressFamily> NetworkManagerData<A> {
    fn recv_for_socket(&self, socket_id: usize, cx: &mut Context<'_>) -> Poll<Result<()>> {
        self.read_wakers.add_waker(cx.waker().clone());
        let mut buf = [0u8; MAX_PACKET_SIZE];
        // The mutex can only be poisoned from an earlier panic. It is ok for
        // us to propagate that to all the threads.
        let sockets = self.sockets.read().unwrap();
        // The mutex can only be poisoned from an earlier panic. It is ok for
        // us to propagate that to all the threads.
        let interfaces = self.interfaces.read().unwrap();
        // The socket state will always be present.
        if let Some(interface_name) = sockets[&socket_id].interface_filter {
            if let Poll::Ready(recv_result) = interfaces[&Some(interface_name)].interface.poll_recv(
                &mut buf,
                &mut Context::from_waker(&Waker::from(self.read_wakers.clone())),
            ) {
                Poll::Ready(handle_recv_result(
                    &buf,
                    &sockets,
                    recv_result,
                    Some(interface_name),
                ))
            } else {
                Poll::Pending
            }
        } else {
            for (&interface_name, interface) in interfaces.iter() {
                if let Poll::Ready(recv_result) = interface.interface.poll_recv(
                    &mut buf,
                    &mut Context::from_waker(&Waker::from(self.read_wakers.clone())),
                ) {
                    return Poll::Ready(handle_recv_result(
                        &buf,
                        &sockets,
                        recv_result,
                        interface_name,
                    ));
                }
            }

            Poll::Pending
        }
    }
}

fn handle_recv_result<A: PtpAddressFamily>(
    buf: &[u8],
    sockets: &HashMap<usize, SocketData<A>>,
    recv_result: Result<timestamped_socket::socket::RecvResult<A>>,
    interface_name: Option<InterfaceName>,
) -> Result<()> {
    match recv_result {
        Ok(recv_result) => {
            let bytes_read: Arc<[u8]> = buf[..recv_result.bytes_read].into();

            for socket in sockets.values() {
                if socket
                    .interface_filter
                    .is_none_or(|socket_interface| Some(socket_interface) == interface_name)
                    && socket
                        .local_filter
                        .is_none_or(|addr| addr == recv_result.local_addr)
                    && socket
                        .remote_filter
                        .is_none_or(|addr| addr == recv_result.remote_addr)
                {
                    // UDP is non-guaranteed in delivery. This is just another
                    // point where the message can be dropped if the buffers
                    // are full.
                    let _ = socket.message_channel.try_send(RecvResult {
                        bytes_read: bytes_read.clone(),
                        remote_addr: recv_result.remote_addr,
                        local_addr: recv_result.local_addr,
                        timestamp: match socket.timestamp_source {
                            TimestampSource::System => recv_result.full_timestamp_data.software,
                            TimestampSource::Hardware => recv_result.full_timestamp_data.hardware,
                        },
                    });
                }
            }

            Ok(())
        }
        Err(e) => Err(e),
    }
}

impl<A: PtpAddressFamily> OpenSocket<A> {
    /// Receive an incoming message.
    ///
    /// # Errors
    ///
    /// Returns any IO error that occured trying to receive a packet.
    pub async fn recv(&mut self) -> Result<RecvResult<A>> {
        poll_fn(|cx| {
            loop {
                if let Poll::Ready(Some(recv_packet)) = self.packet_receiver.poll_recv(cx) {
                    return Poll::Ready(Ok(recv_packet));
                }

                match self.state.recv_for_socket(self.socket_id, cx) {
                    Poll::Ready(Ok(())) => {}
                    Poll::Ready(Err(e)) => break Poll::Ready(Err(e)),
                    Poll::Pending => break Poll::Pending,
                }
            }
        })
        .await
    }
}

impl<A: PtpAddressFamily> ConnectedSocket<A> {
    /// Receive an incoming message.
    ///
    /// # Errors
    ///
    /// Returns any IO error that occured trying to receive a packet.
    pub async fn recv(&mut self) -> Result<RecvResult<A>> {
        poll_fn(|cx| {
            loop {
                if let Poll::Ready(Some(recv_packet)) = self.packet_receiver.poll_recv(cx) {
                    return Poll::Ready(Ok(recv_packet));
                }

                match self.state.recv_for_socket(self.socket_id, cx) {
                    Poll::Ready(Ok(())) => {}
                    Poll::Ready(Err(e)) => break Poll::Ready(Err(e)),
                    Poll::Pending => break Poll::Pending,
                }
            }
        })
        .await
    }
}
