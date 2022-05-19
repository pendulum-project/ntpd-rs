use std::{pin::Pin, sync::Arc};

use tracing::warn;

use ntp_proto::{
    AcceptSynchronizationError, IgnoreReason, NtpClock, NtpHeader, NtpInstant, NtpTimestamp, Peer,
    PeerSnapshot, ReferenceId, SystemConfig, SystemSnapshot,
};
use ntp_udp::UdpSocket;
use tracing::{info, instrument};

use tokio::{
    net::ToSocketAddrs,
    sync::watch,
    time::{Instant, Sleep},
};

#[derive(Debug, Clone, Copy)]
pub enum MsgForSystem {
    /// Received a Kiss-o'-Death and must demobilize
    MustDemobilize(usize),
    /// Received an acceptable packet and made a new peer snapshot
    Snapshot(usize, u64, PeerSnapshot),
}

struct PeerProcess<A, C> {
    index: usize,
    addr: A,
    clock: C,
    config: SystemConfig,
    msg_for_system_sender: tokio::sync::mpsc::Sender<MsgForSystem>,
    system_snapshots: Arc<tokio::sync::RwLock<SystemSnapshot>>,
    reset: watch::Receiver<u64>,
    socket: UdpSocket,

    peer: Peer,

    /// Timestamp of the last packet that we sent
    last_send_timestamp: Option<NtpTimestamp>,

    /// Instant last poll message was sent (used for timing the wait)
    last_poll_sent: Instant,

    /// Number of resets that this peer has performed
    reset_epoch: u64,
}

impl<A, C> PeerProcess<A, C>
where
    A: ToSocketAddrs + std::fmt::Debug,
    C: 'static + NtpClock + Send,
{
    async fn handle_poll(&mut self, poll_wait: &mut Pin<&mut Sleep>) {
        let system_snapshot = *self.system_snapshots.read().await;

        let packet = self.peer.generate_poll_message(system_snapshot);

        // Sent a poll, so update waiting to match deadline of next
        self.last_poll_sent = Instant::now();
        let poll_interval = self
            .peer
            .current_poll_interval(system_snapshot)
            .as_system_duration();
        poll_wait
            .as_mut()
            .reset(self.last_poll_sent + poll_interval);

        match self.clock.now() {
            Err(e) => {
                // we cannot determine the origin_timestamp
                panic!("`clock.now()` reported an error: {:?}", e)
            }
            Ok(ts) => {
                self.last_send_timestamp = Some(ts);
            }
        }

        if let Err(e) = self.socket.send(&packet.serialize()).await {
            warn!(error = debug(e), "poll message could not be sent");
        }
    }

    async fn handle_reset(&mut self, result: Result<(), ()>) {
        if let Ok(()) = result {
            // reset the measurement state (as if this association was just created).
            // crucially, this sets `self.next_expected_origin = None`, meaning that
            // in-flight requests are ignored
            self.peer.reset_measurements();

            // our next measurement will have the new reset epoch
            self.reset_epoch = *self.reset.borrow_and_update();
        }
    }

    async fn handle_packet(
        &mut self,
        poll_wait: &mut Pin<&mut Sleep>,
        packet: NtpHeader,
        send_timestamp: NtpTimestamp,
        recv_timestamp: NtpTimestamp,
    ) {
        let ntp_instant = NtpInstant::now();

        let system_snapshot = *self.system_snapshots.read().await;
        let result = self.peer.handle_incoming(
            system_snapshot,
            packet,
            ntp_instant,
            self.config.frequency_tolerance,
            send_timestamp,
            recv_timestamp,
        );

        // Handle incoming may have changed poll interval based on message, respect that change
        let poll_interval = self
            .peer
            .current_poll_interval(system_snapshot)
            .as_system_duration();
        poll_wait
            .as_mut()
            .reset(self.last_poll_sent + poll_interval);

        let system_poll = system_snapshot.poll_interval.as_duration();
        let accept = self.peer.accept_synchronization(
            ntp_instant,
            self.config.frequency_tolerance,
            self.config.distance_threshold,
            system_poll,
        );

        if let Some(msg) = prepare_msg_for_system(self.index, self.reset_epoch, accept, result) {
            self.msg_for_system_sender.send(msg).await.ok();
        }
    }
}

#[instrument(skip(clock, config, system_snapshots, reset))]
pub async fn start_peer<A: ToSocketAddrs + std::fmt::Debug, C: 'static + NtpClock + Send>(
    index: usize,
    addr: A,
    clock: C,
    config: SystemConfig,
    msg_for_system_sender: tokio::sync::mpsc::Sender<MsgForSystem>,
    system_snapshots: Arc<tokio::sync::RwLock<SystemSnapshot>>,
    mut reset: watch::Receiver<u64>,
) -> Result<(), std::io::Error> {
    let socket = UdpSocket::new("0.0.0.0:0", addr).await?;
    let our_id = ReferenceId::from_ip(socket.as_ref().local_addr().unwrap().ip());
    let peer_id = ReferenceId::from_ip(socket.as_ref().peer_addr().unwrap().ip());

    tokio::spawn(async move {
        let local_clock_time = NtpInstant::now();
        let mut peer = Peer::new(our_id, peer_id, local_clock_time);

        let poll_wait = tokio::time::sleep(std::time::Duration::default());
        tokio::pin!(poll_wait);

        // we don't store the real origin timestamp in the packet, because that would leak our
        // system time to the network (and could make attacks easier). So instead there is some
        // garbage data in the origin_timestamp field, and we need to track and pass along the
        // actual origin timestamp ourselves.
        let mut last_send_timestamp = None;

        // Instant last poll message was sent (used for timing the wait)
        let mut last_poll_sent = Instant::now();

        let mut reset_epoch = 0;

        loop {
            let mut buf = [0_u8; 48];

            tokio::select! {
                () = &mut poll_wait => {
                    let system_snapshot = *system_snapshots.read().await;


                    let packet = peer.generate_poll_message(system_snapshot);

                    // Sent a poll, so update waiting to match deadline of next
                    last_poll_sent = Instant::now();
                    poll_wait
                        .as_mut()
                        .reset(last_poll_sent + peer.current_poll_interval(system_snapshot).as_system_duration());

                    match clock.now() {
                        Err(e) => {
                            // we cannot determine the origin_timestamp
                            panic!("`clock.now()` reported an error: {:?}", e)
                        }
                        Ok(ts) => {
                            last_send_timestamp = Some(ts);
                        }
                    }

                    if let Err(e) = socket.send(&packet.serialize()).await {
                        warn!(error=debug(e), "poll message could not be sent");
                    }
                },
                result = reset.changed() => {
                    if let Ok(()) = result {
                        // reset the measurement state (as if this association was just created).
                        // crucially, this sets `self.next_expected_origin = None`, meaning that
                        // in-flight requests are ignored
                        peer.reset_measurements();

                        // our next measurement will have the new reset epoch
                        reset_epoch = *reset.borrow_and_update();
                    }
                }
                result = socket.recv(&mut buf) => {
                    let send_timestamp = match last_send_timestamp {
                        Some(ts) => ts,
                        None => {
                            info!("we received a message without having sent one; discard");
                            continue;
                        }
                    };

                    if let Some((packet, recv_timestamp)) = accept_packet(result, &buf) {
                        let ntp_instant = NtpInstant::now();

                        let system_snapshot = *system_snapshots.read().await;
                        let result = peer.handle_incoming(
                            system_snapshot,
                            packet,
                            ntp_instant,
                            config.frequency_tolerance,
                            send_timestamp,
                            recv_timestamp,
                        );

                        // Handle incoming may have changed poll interval based on message, respect that change
                        let poll_interval = peer.current_poll_interval(system_snapshot).as_system_duration();
                        poll_wait.as_mut().reset(last_poll_sent + poll_interval);

                        let system_poll = system_snapshot.poll_interval.as_duration();
                        let accept = peer.accept_synchronization(
                            ntp_instant,
                            config.frequency_tolerance,
                            config.distance_threshold,
                            system_poll,
                        );

                        if let Some(msg) = prepare_msg_for_system(index, reset_epoch, accept, result) {
                            msg_for_system_sender.send(msg).await.ok();
                        }
                    }
                },
            }
        }
    });

    Ok(())
}

fn prepare_msg_for_system(
    index: usize,
    reset_epoch: u64,
    accept: Result<(), AcceptSynchronizationError>,
    result: Result<PeerSnapshot, IgnoreReason>,
) -> Option<MsgForSystem> {
    match accept {
        Err(accept_error) => {
            info!(?accept_error, "packet is not accepted");
            None
        }
        Ok(_) => match result {
            Ok(update) => {
                info!("packet accepted");
                Some(MsgForSystem::Snapshot(index, reset_epoch, update))
            }
            Err(IgnoreReason::KissDemobilize) => {
                info!("peer must demobilize");
                Some(MsgForSystem::MustDemobilize(index))
            }
            Err(ignore_reason) => {
                info!(?ignore_reason, "packet ignored");
                None
            }
        },
    }
}

fn accept_packet(
    result: Result<(usize, Option<NtpTimestamp>), std::io::Error>,
    buf: &[u8; 48],
) -> Option<(NtpHeader, NtpTimestamp)> {
    match result {
        Ok((size, Some(recv_timestamp))) => {
            // Note: packets are allowed to be bigger when including extensions.
            // we don't expect them, but the server may still send them. The
            // extra bytes are guaranteed safe to ignore. `recv` truncates the messages.
            // Messages of fewer than 48 bytes are skipped entirely
            if size < 48 {
                warn!(expected = 48, actual = size, "received packet is too small");

                None
            } else {
                Some((NtpHeader::deserialize(buf), recv_timestamp))
            }
        }
        Ok((size, None)) => {
            warn!(?size, "received a packet without a timestamp");

            None
        }
        Err(receive_error) => {
            warn!(?receive_error, "could not receive packet");

            None
        }
    }
}
