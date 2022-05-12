#![forbid(unsafe_code)]
mod peer;

use futures::{stream::FuturesUnordered, StreamExt};
use ntp_os_clock::UnixNtpClock;
use ntp_proto::{
    FilterAndCombine, NtpClock, NtpInstant, PollInterval, SystemConfig, SystemSnapshot,
};
use peer::{start_peer, PeerChannels};
use std::error::Error;
use tokio::sync::watch;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let config = SystemConfig::default();
    let clock = UnixNtpClock::new();

    // channel for sending updated system state to the peers
    let (system_tx, system_rx) = watch::channel::<SystemSnapshot>(SystemSnapshot::default());

    // channel to send the reset signal to all peers
    let (_reset_tx, reset_rx) = watch::channel::<()>(());

    let new_peer = |address| {
        start_peer(
            address,
            UnixNtpClock::new(),
            config,
            system_rx.clone(),
            reset_rx.clone(),
        )
    };

    let mut peers = vec![
        new_peer("0.pool.ntp.org:123").await.unwrap(),
        new_peer("1.pool.ntp.org:123").await.unwrap(),
        new_peer("2.pool.ntp.org:123").await.unwrap(),
        new_peer("3.pool.ntp.org:123").await.unwrap(),
    ];

    let mut snapshots = Vec::with_capacity(peers.len());

    // when we perform a clock jump, all current measurement data is off. We force all associations
    // to clear their measurement data and get new data. This vector contains associations that
    // have not yet responded with a new valid measurement.
    let mut waiting_for_reset: Vec<PeerChannels> = Vec::with_capacity(peers.len());

    loop {
        // one of the peers has a new measurement
        let mut changed: FuturesUnordered<_> = peers
            .iter_mut()
            .enumerate()
            .map(|(i, c)| async move {
                c.peer_snapshot.changed().await.unwrap();
                i
            })
            .collect();

        // a peer that has been reset is saying it has resetted successfully
        let mut active_after_reset: FuturesUnordered<_> = waiting_for_reset
            .iter_mut()
            .enumerate()
            .map(|(i, c)| async move {
                c.peer_reset.notified().await;
                i
            })
            .collect();

        tokio::select! {
            Some(changed_index) = active_after_reset.next() => {
                drop(changed);
                drop(active_after_reset);

                let peer = waiting_for_reset.remove(changed_index);
                peers.push(peer);
            },
            Some(changed_index) = changed.next() => {
                drop(changed);
                drop(active_after_reset);

                let msg = *peers[changed_index].peer_snapshot.borrow();
                match msg {
                    peer::MsgForSystem::MustDemobilize => {
                        peers.remove(changed_index);
                        continue;
                    }
                    peer::MsgForSystem::NoMeasurement => {
                        continue;
                    }
                    peer::MsgForSystem::Snapshot(_) => {
                        // fall through
                    }
                }

                // remove all snapshots from a previous iteration
                snapshots.clear();

                for i in (0..peers.len()).rev() {
                    let msg = *peers[i].peer_snapshot.borrow_and_update();
                    match msg {
                        peer::MsgForSystem::MustDemobilize => {
                            peers.remove(i);
                        }
                        peer::MsgForSystem::NoMeasurement => {
                            // skip
                        }
                        peer::MsgForSystem::Snapshot(snapshot) => {
                            snapshots.push(snapshot);
                        }
                    }
                }

                let ntp_instant = NtpInstant::from_ntp_timestamp(clock.now().unwrap());
                let system_poll = PollInterval::MIN;
                let result = FilterAndCombine::run(&config, &snapshots, ntp_instant, system_poll);

                match result {
                    Some(clock_select) => {
                        let offset_ms = clock_select.system_offset.to_seconds() * 1000.0;
                        let jitter_ms = clock_select.system_jitter.to_seconds() * 1000.0;
                        println!("offset: {:.3}ms (jitter: {}ms)", offset_ms, jitter_ms);
                        println!();

                        // TODO update system state with result.peer_snapshot

                        // TODO produce an updated snapshot
                        let system_snapshot = SystemSnapshot::default();
                        system_tx.send(system_snapshot)?;
                    }
                    None => println!("filter and combine did not produce a result"),
                }
            }
        }
    }
}
