use tracing::warn;

use ntp_proto::{
    IgnoreReason, NtpClock, NtpHeader, NtpInstant, Peer, PeerSnapshot, ReferenceId, SystemConfig,
    SystemSnapshot,
};
use ntp_udp::UdpSocket;
use tracing::instrument;

use tokio::{net::ToSocketAddrs, sync::watch, time::Instant};

#[derive(Debug, Clone, Copy)]
pub enum MsgForSystem {
    /// Received a Kiss-o'-Death and must demobilize
    MustDemobilize,
    /// There is no measurement available, either because no
    /// packet has been received yet, or because synchronization was rejected
    NoMeasurement,
    /// Received an acceptable packet and made a new peer snapshot
    Snapshot(PeerSnapshot),
}

pub struct PeerChannels {
    pub peer_snapshot: watch::Receiver<MsgForSystem>,
    pub peer_reset: watch::Receiver<u64>,
}

#[instrument(skip(clock, config, system_snapshots, reset))]
pub async fn start_peer<A: ToSocketAddrs + std::fmt::Debug, C: 'static + NtpClock + Send>(
    addr: A,
    clock: C,
    config: SystemConfig,
    mut system_snapshots: watch::Receiver<SystemSnapshot>,
    mut reset: watch::Receiver<u64>,
) -> Result<PeerChannels, std::io::Error> {
    let socket = UdpSocket::new("0.0.0.0:0", addr).await?;
    let our_id = ReferenceId::from_ip(socket.as_ref().local_addr().unwrap().ip());
    let peer_id = ReferenceId::from_ip(socket.as_ref().peer_addr().unwrap().ip());
    let (tx, rx) = watch::channel::<MsgForSystem>(MsgForSystem::NoMeasurement);

    // channel to notify that a reset has been completed by this peer
    let (notify_reset_send, notify_reset_receive) = watch::channel::<u64>(0);

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

        loop {
            let mut buf = [0_u8; 48];

            tokio::select! {
                () = &mut poll_wait => {
                    let system_snapshot = *system_snapshots.borrow_and_update();


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
                        tx.send_replace(MsgForSystem::NoMeasurement);

                        // notify the system that the reset has been successful, and that this
                        // association can produce valid measurements again
                        notify_reset_send.send_replace(*reset.borrow_and_update());
                    }
                }
                result = socket.recv(&mut buf) => {
                    if let Ok((size, Some(recv_timestamp))) = result {
                        // Note: packets are allowed to be bigger when including extensions.
                        // we don't expect them, but the server may still send them. The
                        // extra bytes are guaranteed safe to ignore. `recv` truncates the messages.
                        // Messages of fewer than 48 bytes are skipped entirely
                        if size < 48 {
                            warn!(expected=48, actual=size, "received packet is too small");
                        } else {
                            let packet = NtpHeader::deserialize(&buf);

                            let ntp_instant = NtpInstant::now();

                            let send_timestamp = match last_send_timestamp {
                                Some(ts) => ts,
                                None => {
                                    // we received a message without having sent one; discard
                                    continue
                                }
                            };

                            let system_snapshot = *system_snapshots.borrow_and_update();
                            let result = peer.handle_incoming(
                                system_snapshot,
                                packet,
                                ntp_instant,
                                config.frequency_tolerance,
                                send_timestamp,
                                recv_timestamp,
                            );

                            // Handle incoming may have changed poll interval based on
                            // message, respect that change
                            poll_wait
                                .as_mut()
                                .reset(last_poll_sent + peer.current_poll_interval(system_snapshot).as_system_duration());

                            let system_poll = system_snapshot.poll_interval.as_duration();
                            let accept = peer.accept_synchronization(
                                ntp_instant,
                                config.frequency_tolerance,
                                config.distance_threshold,
                                system_poll,
                            );

                            if accept.is_err() {
                                tx.send_replace(MsgForSystem::NoMeasurement);
                            } else  {
                                match result {
                                    Ok(update) => {
                                        tx.send_replace(MsgForSystem::Snapshot(update));
                                    }
                                    Err(IgnoreReason::KissDemobilize) => {
                                        tx.send_replace(MsgForSystem::MustDemobilize);
                                    }
                                    Err(_) => { /* ignore */ }

                                }
                            }
                        }
                    } else {
                        // TODO: log something
                    }
                },
            }
        }
    });

    let channels = PeerChannels {
        peer_snapshot: rx,
        peer_reset: notify_reset_receive,
    };

    Ok(channels)
}
