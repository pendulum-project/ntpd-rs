use std::{collections::hash_map::Entry, sync::Arc};

use timestamped_socket::interface::InterfaceName;

use crate::{
    ConnectedSocket, NetworkManagerData, OpenSocket, PACKET_BUFFER_SIZE, PtpAddressFamily,
    SocketData, TimestampSource,
};

/// A handle for a network interface
///
/// Describes the configured network interface and way of timestamping for its
/// sockets. It also ensures the requested timestamping clock remains available
/// on the interface during its existence.
pub struct Interface<A: PtpAddressFamily> {
    pub(crate) state: Arc<NetworkManagerData<A>>,
    pub(crate) name: Option<InterfaceName>,
    pub(crate) timestamp_source: TimestampSource,
}

impl<A: PtpAddressFamily> Clone for Interface<A> {
    fn clone(&self) -> Self {
        // The mutex can only be poisoned from an earlier panic. It is ok for
        // us to propagate that to all the threads.
        let mut interfaces = self.state.interfaces.write().unwrap();
        // The interface will always be present because of the refcounting.
        let entry = interfaces.get_mut(&self.name).unwrap();
        // An overflowing reference count is an error condition from which we
        // cannot reasonably recover. A panic here is the best solution.
        entry.refcount = entry.refcount.checked_add(1).unwrap();
        Self {
            state: self.state.clone(),
            name: self.name,
            timestamp_source: self.timestamp_source,
        }
    }
}

impl<A: PtpAddressFamily> Drop for Interface<A> {
    fn drop(&mut self) {
        // The mutex can only be poisoned from an earlier panic. It is ok for
        // us to propagate that to all the threads.
        let mut interfaces = self.state.interfaces.write().unwrap();
        // The interface will always be present because of the refcounting.
        let entry = interfaces.get_mut(&self.name).unwrap();
        // An underflowing refcount should never happen. If it does, something
        // is seriously wrong and aborting is the best solution.
        entry.refcount = entry.refcount.checked_sub(1).unwrap();
        if entry.refcount == 0 {
            interfaces.remove(&self.name);
        }
    }
}

impl<A: PtpAddressFamily> Interface<A> {
    /// Create an open socket intended for listening to the network.
    ///
    /// Creates a socket that is intended to receive traffic from any remote,
    /// potentially providing responses to that traffic.
    #[must_use]
    #[expect(
        clippy::missing_panics_doc,
        reason = "Function will only panic if there is an implementation bug in this crate."
    )]
    pub fn listen_socket(&self) -> OpenSocket<A> {
        let (socket_channel_tx, socket_channel_rx) = tokio::sync::mpsc::channel(PACKET_BUFFER_SIZE);

        let socket = SocketData {
            remote_filter: None,
            local_filter: None,
            interface_filter: self.name,
            timestamp_source: self.timestamp_source,
            message_channel: socket_channel_tx,
        };

        {
            // The mutex can only be poisoned from an earlier panic. It is ok for
            // us to propagate that to all the threads.
            let mut interfaces = self.state.interfaces.write().unwrap();
            // The interface will always be present because of the refcounting.
            let entry = interfaces.get_mut(&self.name).unwrap();
            // An overflowing reference count is an error condition from which we
            // cannot reasonably recover. A panic here is the best solution.
            entry.refcount = entry.refcount.checked_add(1).unwrap();
        }

        let socket_id = {
            // The mutex can only be poisoned from an earlier panic. It is ok for
            // us to propagate that to all the threads.
            let mut sockets = self.state.sockets.write().unwrap();
            loop {
                let socket_id = self
                    .state
                    .next_socket_id
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if let Entry::Vacant(vacant_entry) = sockets.entry(socket_id) {
                    vacant_entry.insert(socket);
                    break socket_id;
                }
            }
        };

        OpenSocket {
            state: self.state.clone(),
            socket_id,
            packet_receiver: socket_channel_rx,
        }
    }

    /// Create a socket connected to a specific remote address.
    ///
    /// This creates a socket intended for use in communicating with a single
    /// remote party over the interface. The `remote` address specifies the
    /// network address of that party.
    ///
    /// The `local` address specifies which address should be used as the
    /// sender address on the messages. If this is not specified, the operating
    /// system will select a send address automatically.
    #[expect(
        clippy::missing_panics_doc,
        reason = "Function will only panic if there is an implementation bug in this crate."
    )]
    pub fn connected_socket(&self, local: Option<A>, remote: A) -> ConnectedSocket<A> {
        let (socket_channel_tx, socket_channel_rx) = tokio::sync::mpsc::channel(PACKET_BUFFER_SIZE);

        let socket = SocketData {
            remote_filter: Some(remote),
            local_filter: local,
            interface_filter: self.name,
            timestamp_source: self.timestamp_source,
            message_channel: socket_channel_tx,
        };

        {
            // The mutex can only be poisoned from an earlier panic. It is ok for
            // us to propagate that to all the threads.
            let mut interfaces = self.state.interfaces.write().unwrap();
            // The interface will always be present because of the refcounting.
            let entry = interfaces.get_mut(&self.name).unwrap();
            // An overflowing reference count is an error condition from which we
            // cannot reasonably recover. A panic here is the best solution.
            entry.refcount = entry.refcount.checked_add(1).unwrap();
        }

        let socket_id = {
            // The mutex can only be poisoned from an earlier panic. It is ok for
            // us to propagate that to all the threads.
            let mut sockets = self.state.sockets.write().unwrap();
            loop {
                let socket_id = self
                    .state
                    .next_socket_id
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if let Entry::Vacant(vacant_entry) = sockets.entry(socket_id) {
                    vacant_entry.insert(socket);
                    break socket_id;
                }
            }
        };

        ConnectedSocket {
            state: self.state.clone(),
            socket_id,
            packet_receiver: socket_channel_rx,
        }
    }
}
