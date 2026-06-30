use std::{
    future::poll_fn,
    io::Result,
    task::{Context, Poll, Waker},
};

use timestamped_socket::{interface::InterfaceName, socket::Timestamp};

use crate::{
    BoundInterface, CACHED_TIMESTAMPS, ConnectedSocket, NetworkManagerData, OpenSocket,
    PtpAddressFamily, TIMESTAMP_FETCH_TIMEOUT, TimestampSource,
};

impl<A: PtpAddressFamily> NetworkManagerData<A> {
    async fn send_event(
        &self,
        interface_name: Option<InterfaceName>,
        timestamp_source: TimestampSource,
        buf: &[u8],
        from: Option<A>,
        to: A,
    ) -> std::prelude::v1::Result<Option<Timestamp>, std::io::Error> {
        let (timestamp_id, last_seen) = poll_fn(|cx| {
            // The mutex can only be poisoned from an earlier panic. It is ok for
            // us to propagate that to all the threads.
            let interfaces = self.interfaces.read().unwrap();
            // Reference counting ensures the interface will always be available.
            let interface = &interfaces[&interface_name];

            let last_seen = *interfaces[&interface_name]
                .timestamp_counter
                .read()
                .unwrap();

            interface.send_wakers.add_waker(cx.waker().clone());
            interface
                .interface
                .poll_send_event(
                    buf,
                    from,
                    to,
                    &mut Context::from_waker(&Waker::from(interface.send_wakers.clone())),
                )
                .map(|v| v.map(|u| (u, last_seen)))
        })
        .await?;

        self.wait_for_send_timestamp(interface_name, timestamp_source, timestamp_id, last_seen)
            .await
    }

    async fn wait_for_send_timestamp(
        &self,
        interface_name: Option<InterfaceName>,
        timestamp_source: TimestampSource,
        timestamp_id: timestamped_socket::socket::SendTimestampToken,
        mut last_seen: usize,
    ) -> std::prelude::v1::Result<Option<Timestamp>, std::io::Error> {
        match tokio::time::timeout(
            TIMESTAMP_FETCH_TIMEOUT,
            poll_fn(|cx| {
                // The mutex can only be poisoned from an earlier panic. It is ok for
                // us to propagate that to all the threads.
                let interfaces = self.interfaces.read().unwrap();
                // Reference counting ensures the interface will always be available.
                let interface = &interfaces[&interface_name];

                loop {
                    interface.ts_wakers.add_waker(cx.waker().clone());
                    // The mutex can only be poisoned from an earlier panic. It is ok for
                    // us to propagate that to all the threads.
                    let cur_seen = *interface.timestamp_counter.read().unwrap();
                    let count = last_seen.wrapping_sub(cur_seen);
                    let start = last_seen % CACHED_TIMESTAMPS;

                    if count >= CACHED_TIMESTAMPS {
                        for ts_entry in &interface.previous_timestamps {
                            // The mutex can only be poisoned from an earlier panic. It is ok for
                            // us to propagate that to all the threads.
                            if let Some((cur_id, ts_data)) = *ts_entry.read().unwrap()
                                && cur_id == timestamp_id
                            {
                                return Poll::Ready(match timestamp_source {
                                    TimestampSource::System => ts_data.software,
                                    TimestampSource::Hardware => ts_data.hardware,
                                });
                            }
                        }
                    } else if start + count > CACHED_TIMESTAMPS {
                        // Will never underflow as start is guaranteed smaller than
                        // CACHED_TIMESTAMPS.
                        let head_size = CACHED_TIMESTAMPS - start;
                        // All the indexing here is guaranteed to be in range since
                        // head_size < count, and count < CACHED_TIMESTAMPS, and
                        // start < CACHED_TIMESTAMPS.
                        for ts_entry in interface.previous_timestamps[start..]
                            .iter()
                            .chain(interface.previous_timestamps[..(count - head_size)].iter())
                        {
                            if let Some((cur_id, ts_data)) = *ts_entry.read().unwrap()
                                && cur_id == timestamp_id
                            {
                                return Poll::Ready(match timestamp_source {
                                    TimestampSource::System => ts_data.software,
                                    TimestampSource::Hardware => ts_data.hardware,
                                });
                            }
                        }
                    } else {
                        // All the indexing here is guaranteed to be in range since
                        // start + count < CACHED_TIMESTAMPS, and both are smaller than
                        // CACHED_TIMESTAMPS, which in turn is smaller than usize::max/2.
                        for ts_entry in &interface.previous_timestamps[start..] {
                            if let Some((cur_id, ts_data)) = *ts_entry.read().unwrap()
                                && cur_id == timestamp_id
                            {
                                return Poll::Ready(match timestamp_source {
                                    TimestampSource::System => ts_data.software,
                                    TimestampSource::Hardware => ts_data.hardware,
                                });
                            }
                        }
                    }

                    last_seen = cur_seen;

                    match interface
                        .interface
                        .poll_recv_timestamp(&mut Context::from_waker(&Waker::from(
                            interface.ts_wakers.clone(),
                        ))) {
                        Poll::Ready(Ok((ts_id, ts_data))) => {
                            // The mutex can only be poisoned from an earlier panic. It is ok for
                            // us to propagate that to all the threads.
                            let mut ts_counter = interface.timestamp_counter.write().unwrap();
                            let write_idx = *ts_counter % CACHED_TIMESTAMPS;
                            // The mutex can only be poisoned from an earlier panic. It is ok for
                            // us to propagate that to all the threads.
                            let mut entry =
                                interface.previous_timestamps[write_idx].write().unwrap();
                            *entry = Some((ts_id, ts_data));
                            *ts_counter = ts_counter.wrapping_add(1);
                            if ts_id == timestamp_id {
                                return Poll::Ready(match timestamp_source {
                                    TimestampSource::System => ts_data.software,
                                    TimestampSource::Hardware => ts_data.hardware,
                                });
                            }
                        }
                        Poll::Ready(Err(e)) => {
                            tracing::warn!(
                                ?interface_name,
                                "Error trying to fetch send timestamp: {e}"
                            );
                        }
                        Poll::Pending => return Poll::Pending,
                    }
                }
            }),
        )
        .await
        {
            Ok(result) => Ok(result),
            Err(_) => Ok(None),
        }
    }
}

impl<A: PtpAddressFamily> OpenSocket<A> {
    /// Send an event message.
    ///
    /// Send the event message to the specified remote. If provided, `from`
    /// sets the sender address for this message, otherwise this is inferred.
    ///
    /// Returns the actual time the message was sent if the operating system
    /// was able to provide this.
    ///
    /// # Errors
    ///
    /// Returns any IO errors that occured trying to send the message.
    #[expect(
        clippy::missing_panics_doc,
        reason = "Function will only panic if there is an implementation bug in this crate."
    )]
    pub async fn send_event(
        &self,
        buf: &[u8],
        from: Option<A>,
        to: A,
    ) -> Result<Option<Timestamp>> {
        let (interface_name, timestamp_source) = {
            // The mutex can only be poisoned from an earlier panic. It is ok for
            // us to propagate that to all the threads.
            let sockets = self.state.sockets.read().unwrap();
            // The socket will always be available
            let socket = &sockets[&self.socket_id];
            (socket.interface_filter, socket.timestamp_source)
        };

        self.state
            .send_event(interface_name, timestamp_source, buf, from, to)
            .await
    }

    /// Send a general message.
    ///
    /// Send the event message to the specified remote. If provided, `from`
    /// sets the sender address for this message, otherwise this is inferred.
    ///
    /// # Errors
    ///
    /// Returns any IO errors that occured trying to send the message.
    #[expect(
        clippy::missing_panics_doc,
        reason = "Function will only panic if there is an implementation bug in this crate."
    )]
    pub async fn send_general(&self, buf: &[u8], from: Option<A>, to: A) -> Result<()> {
        poll_fn(|cx| {
            // The mutex can only be poisoned from an earlier panic. It is ok for
            // us to propagate that to all the threads.
            let sockets = self.state.sockets.read().unwrap();
            // The mutex can only be poisoned from an earlier panic. It is ok for
            // us to propagate that to all the threads.
            let interfaces = self.state.interfaces.read().unwrap();
            // The socket will always be available
            let interface_name = sockets[&self.socket_id].interface_filter;
            // Reference counting ensures the interface will always be available.
            // The same holds for the socket.
            let interface = &interfaces[&interface_name];
            interface.send_wakers.add_waker(cx.waker().clone());
            interface.interface.poll_send_general(
                buf,
                from,
                to,
                &mut Context::from_waker(&Waker::from(interface.send_wakers.clone())),
            )
        })
        .await
    }
}

impl<A: PtpAddressFamily> ConnectedSocket<A> {
    /// Send an event message
    ///
    /// Send the event message to the connected remote.
    ///
    /// Returns the actual time the message was sent if the operating system
    /// was able to provide this.
    ///
    /// # Errors
    ///
    /// Returns any IO errors that occured trying to send the message.
    #[expect(
        clippy::missing_panics_doc,
        reason = "Function will only panic if there is an implementation bug in this crate."
    )]
    pub async fn send_event(&self, buf: &[u8]) -> Result<Option<Timestamp>> {
        let (interface_name, timestamp_source, from, to) = {
            // The mutex can only be poisoned from an earlier panic. It is ok for
            // us to propagate that to all the threads.
            let sockets = self.state.sockets.read().unwrap();
            // The socket will always be available
            let socket = &sockets[&self.socket_id];
            // Connected sockets will always have a remote filter.
            (
                socket.interface_filter,
                socket.timestamp_source,
                socket.local_filter,
                socket.remote_filter.unwrap(),
            )
        };

        self.state
            .send_event(interface_name, timestamp_source, buf, from, to)
            .await
    }

    /// Send a general message.
    ///
    /// Send the general message to the connected remote.
    ///
    /// # Errors
    ///
    /// Returns any IO errors that occured trying to send the message.
    #[expect(
        clippy::missing_panics_doc,
        reason = "Function will only panic if there is an implementation bug in this crate."
    )]
    pub async fn send_general(&self, buf: &[u8]) -> Result<()> {
        poll_fn(|cx| {
            // The mutex can only be poisoned from an earlier panic. It is ok for
            // us to propagate that to all the threads.
            let sockets = self.state.sockets.read().unwrap();
            // The mutex can only be poisoned from an earlier panic. It is ok for
            // us to propagate that to all the threads.
            let interfaces = self.state.interfaces.read().unwrap();
            // The socket will always be available
            let socket = &sockets[&self.socket_id];
            // Reference counting ensures the interface will always be available.
            // The same holds for the socket.
            let interface = &interfaces[&socket.interface_filter];
            interface.send_wakers.add_waker(cx.waker().clone());
            // The remote filter is always in use for connected sockets.
            interface.interface.poll_send_general(
                buf,
                socket.local_filter,
                socket.remote_filter.unwrap(),
                &mut Context::from_waker(&Waker::from(interface.send_wakers.clone())),
            )
        })
        .await
    }
}
