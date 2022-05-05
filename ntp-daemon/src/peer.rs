use std::time::Duration;

use ntp_proto::{
    IgnoreReason, NtpClock, NtpDuration, NtpHeader, NtpInstant, Peer, PeerSnapshot, ReferenceId,
    SystemConfig, SystemSnapshot,
};
use tokio::{
    net::{ToSocketAddrs, UdpSocket},
    sync::watch,
    time::Instant,
};

fn poll_interval_to_duration(poll_interval: i8) -> Duration {
    match poll_interval {
        i if i <= 0 => Duration::from_secs(1),
        i if i < 64 => Duration::from_secs(1 << i),
        _ => Duration::from_secs(std::u64::MAX),
    }
}

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

pub async fn start_peer<A: ToSocketAddrs, C: 'static + NtpClock + Send>(
    addr: A,
    clock: C,
    config: SystemConfig,
    mut system_snapshots: watch::Receiver<SystemSnapshot>,
) -> Result<watch::Receiver<MsgForSystem>, std::io::Error> {
    // setup socket
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.connect(addr).await?;

    let (tx, rx) = watch::channel::<MsgForSystem>(MsgForSystem::NoMeasurement);

    let our_id = ReferenceId::from_ip(socket.local_addr()?.ip());
    let peer_id = ReferenceId::from_ip(socket.peer_addr()?.ip());
    let socket = ntp_udp::UdpSocket::from_tokio(socket)?;

    tokio::spawn(async move {
        let local_clock_time = NtpInstant::from_ntp_timestamp(clock.now().unwrap());
        let mut peer = Peer::new(our_id, peer_id, local_clock_time);

        let poll_interval = {
            let system_snapshot = system_snapshots.borrow_and_update();
            peer.get_interval_next_poll(system_snapshot.poll_interval)
        };
        let poll_wait = tokio::time::sleep(poll_interval_to_duration(poll_interval));
        tokio::pin!(poll_wait);

        loop {
            let mut buf = [0_u8; 48];

            tokio::select! {
                () = &mut poll_wait => {
                    let poll_interval = {
                        let system_snapshot = system_snapshots.borrow_and_update();
                        peer.get_interval_next_poll(system_snapshot.poll_interval)
                    };
                    poll_wait
                        .as_mut()
                        .reset(Instant::now() + poll_interval_to_duration(poll_interval));

                    // TODO: Figure out proper error behaviour here
                    let ntp_instant = NtpInstant::from_ntp_timestamp(clock.now().unwrap());
                    let packet = peer.generate_poll_message(ntp_instant);
                    socket.send(&packet.serialize()).await.unwrap();
                },
                result = socket.recv(&mut buf) => {
                    if let Ok((size, Some(timestamp))) = result {
                        // Note: packets are allowed to be bigger when including extensions.
                        // we don't expect them, but the server may still send them. The
                        // extra bytes are guaranteed safe to ignore. `recv` truncates the messages.
                        // Messages of fewer than 48 bytes are skipped entirely
                        if size < 48 {
                            // TODO log something
                        } else {
                            let packet = NtpHeader::deserialize(&buf);

                            let ntp_instant = NtpInstant::from_ntp_timestamp(timestamp);

                            let system_snapshot = *system_snapshots.borrow_and_update();
                            let result = peer.handle_incoming(
                                system_snapshot,
                                packet,
                                ntp_instant,
                                config.frequency_tolerance,
                                timestamp,
                            );

                            let system_poll = NtpDuration::from_exponent(system_snapshot.poll_interval);
                            let accept = peer.accept_synchronization(
                                ntp_instant,
                                config.frequency_tolerance,
                                config.distance_threshold,
                                system_poll,
                            );

                            if accept.is_err() {
                                let _ = tx.send(MsgForSystem::NoMeasurement);
                            } else  {
                                match result {
                                    Ok(update) => {
                                        let _ = tx.send(MsgForSystem::Snapshot(update));
                                    }
                                    Err(IgnoreReason::KissDemobilize) => {
                                        let _ = tx.send(MsgForSystem::MustDemobilize);
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

    Ok(rx)
}
