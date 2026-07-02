use core::{future::poll_fn, task::Poll};

use statime_wire::Timestamp;

use crate::{
    CsptpManager,
    messages::{CsptpMessage, MAX_MESSAGE_SIZE},
    platform::StateMutex,
};

/// Serve CSPTP on the provided socket.
///
/// On completion of the shutdown future, this will finish handling the current
/// packet and then exit.
pub async fn serve(
    mut socket: impl ServerSocket,
    shutdown: impl Future<Output = ()>,
    manager: &CsptpManager<impl StateMutex>,
) {
    let mut shutdown = core::pin::pin!(shutdown);
    loop {
        let mut buf = [0u8; MAX_MESSAGE_SIZE];

        let result = {
            let mut recv = core::pin::pin!(socket.recv(&mut buf));
            poll_fn(|cx| {
                if shutdown.as_mut().poll(cx).is_ready() {
                    Poll::Ready(None)
                } else if let Poll::Ready(result) = recv.as_mut().poll(cx) {
                    Poll::Ready(Some(result))
                } else {
                    Poll::Pending
                }
            })
            .await
        };

        match result {
            Some(Ok(ServerRecvResult {
                bytes_read,
                remote_addr,
                local_addr,
                timestamp,
            })) => {
                handle_packet(
                    &mut socket,
                    manager,
                    &buf[0..bytes_read],
                    remote_addr,
                    local_addr,
                    timestamp,
                )
                .await;
            }
            Some(Err(_)) => {
                // FIXME: Optionally log the errors
            }
            None => break,
        }
    }
}

async fn handle_packet<S: ServerSocket>(
    socket: &mut S,
    manager: &CsptpManager<impl StateMutex>,
    packet: &[u8],
    remote: S::Addr,
    local: S::Addr,
    timestamp: Timestamp,
) {
    let Ok(message) = CsptpMessage::deserialize(packet) else {
        // FIXME: Optionally log the errors
        return;
    };

    if !message.is_request() {
        // FIXME: Optionally log this
        return;
    }

    let mut response_buf = [0u8; 128];
    let Ok(response) = manager.state.with_ref(|state| {
        CsptpMessage::new_response(
            &mut response_buf,
            &message,
            timestamp,
            None,
            &state.time_snapshot,
            &state.csptp_state,
        )
    }) else {
        // FIXME: Optionally log this
        return;
    };

    let mut send_buf = [0u8; MAX_MESSAGE_SIZE];
    let Ok(size) = response.serialize(&mut send_buf) else {
        // Fixme: Optionally log this
        return;
    };
    let Ok(send_timestamp) = socket.send_event(&send_buf[0..size], local, remote).await else {
        // Fixme: Optionally log this
        return;
    };

    let Ok(follow_up) = CsptpMessage::new_follow_up(&response, send_timestamp) else {
        // FIXME: Optionally log this
        return;
    };

    let mut send_buf = [0u8; MAX_MESSAGE_SIZE];
    let Ok(size) = follow_up.serialize(&mut send_buf) else {
        // Fixme: Optionally log this
        return;
    };
    socket
        .send_general(&send_buf[0..size], local, remote)
        .await
        .ok();
}

/// Result from receiving a packet from the server socket.
pub struct ServerRecvResult<Addr> {
    /// Number of bytes that were read
    pub bytes_read: usize,
    /// Address of the remote that sent the packet.
    pub remote_addr: Addr,
    /// Address to which the packet was sent.
    pub local_addr: Addr,
    /// Timestamp at which the packet arrived.
    pub timestamp: Timestamp,
}

/// A general network socket for a CSPTP server.
pub trait ServerSocket {
    /// Address type for the socket
    type Addr: Copy;
    /// Type for errors occuring during socket operations.
    type Error: core::fmt::Debug;

    /// Receive a packet from the socket.
    ///
    /// MUST be cancel safe.
    fn recv(
        &mut self,
        buf: &mut [u8],
    ) -> impl Future<Output = Result<ServerRecvResult<Self::Addr>, Self::Error>>;
    /// Send a packet on the event socket, waiting for a timestamp.
    fn send_event(
        &mut self,
        buf: &[u8],
        from: Self::Addr,
        to: Self::Addr,
    ) -> impl Future<Output = Result<Timestamp, Self::Error>>;
    /// Send a packet on the general socket.
    fn send_general(
        &mut self,
        buf: &[u8],
        from: Self::Addr,
        to: Self::Addr,
    ) -> impl Future<Output = Result<(), Self::Error>>;
}
