use std::sync::Arc;

use crate::{NetworkManagerData, PtpAddressFamily};

mod recv;
mod send;

pub use recv::RecvResult;

/// A socket not connected to a specific remote.
///
/// Can receive and send packets to any valid address of type `A`.
pub struct OpenSocket<A: PtpAddressFamily> {
    pub(crate) state: Arc<NetworkManagerData<A>>,
    pub(crate) socket_id: usize,
    pub(crate) packet_receiver: tokio::sync::mpsc::Receiver<RecvResult<A>>,
}

impl<A: PtpAddressFamily> Drop for OpenSocket<A> {
    fn drop(&mut self) {
        // The mutex can only be poisoned from an earlier panic. It is ok for
        // us to propagate that to all the threads. The socket data will always
        // be present.
        let socket_data = self
            .state
            .sockets
            .write()
            .unwrap()
            .remove(&self.socket_id)
            .unwrap();
        // The mutex can only be poisoned from an earlier panic. It is ok for
        // us to propagate that to all the threads.
        let mut interfaces = self.state.interfaces.write().unwrap();
        // The interface will always be present because of the refcounting.
        let entry = interfaces.get_mut(&socket_data.interface_filter).unwrap();
        // An underflowing refcount should never happen. If it does, something
        // is seriously wrong and aborting is the best solution.
        entry.refcount = entry.refcount.checked_sub(1).unwrap();
        if entry.refcount == 0 {
            interfaces.remove(&socket_data.interface_filter);
        }
    }
}

/// A socket that connected to a specific remote.
///
/// Will only send and receive messages to the specific remote specified when
/// opening the socket with [`Interface::connected_socket`](crate::Interface::connected_socket).
pub struct ConnectedSocket<A: PtpAddressFamily> {
    pub(crate) state: Arc<NetworkManagerData<A>>,
    pub(crate) socket_id: usize,
    pub(crate) packet_receiver: tokio::sync::mpsc::Receiver<RecvResult<A>>,
}

impl<A: PtpAddressFamily> Drop for ConnectedSocket<A> {
    fn drop(&mut self) {
        // The mutex can only be poisoned from an earlier panic. It is ok for
        // us to propagate that to all the threads. The socket data will always
        // be present.
        let socket_data = self
            .state
            .sockets
            .write()
            .unwrap()
            .remove(&self.socket_id)
            .unwrap();
        // The mutex can only be poisoned from an earlier panic. It is ok for
        // us to propagate that to all the threads.
        let mut interfaces = self.state.interfaces.write().unwrap();
        // The interface will always be present because of the refcounting.
        let entry = interfaces.get_mut(&socket_data.interface_filter).unwrap();
        // An underflowing refcount should never happen. If it does, something
        // is seriously wrong and aborting is the best solution.
        entry.refcount = entry.refcount.checked_sub(1).unwrap();
        if entry.refcount == 0 {
            interfaces.remove(&socket_data.interface_filter);
        }
    }
}
