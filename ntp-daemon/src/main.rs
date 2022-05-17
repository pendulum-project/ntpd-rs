#![forbid(unsafe_code)]
mod peer;

use futures::{stream::FuturesUnordered, StreamExt};
use ntp_os_clock::UnixNtpClock;
use ntp_proto::{
    ClockController, ClockUpdateResult, FilterAndCombine, NtpInstant, PollInterval, SystemConfig,
    SystemSnapshot,
};
use peer::{start_peer, PeerChannels};
use tracing::info;

use std::error::Error;
use tokio::sync::watch;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt::init();

    let config = SystemConfig::default();

    // channel for sending updated system state to the peers
    let (system_tx, system_rx) = watch::channel::<SystemSnapshot>(SystemSnapshot::default());

    // channel to send the reset signal to all peers
    let (reset_tx, reset_rx) = watch::channel::<u64>(0);
    let mut last_reset_index: u64 = 0;

    let mut controller = ClockController::new(UnixNtpClock::new());

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
    // have not yet confirmed that their measurement data has been cleared.
    let mut waiting_for_reset: Vec<PeerChannels> = Vec::with_capacity(peers.len());

    loop {
        // one of the peers has a new measurement
        let mut has_new_measurement: FuturesUnordered<_> = peers
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
                c.peer_reset.changed().await.unwrap();
                (i, *c.peer_reset.borrow_and_update())
            })
            .collect();

        tokio::select! {
            Some((changed_index, reset_index)) = active_after_reset.next() => {
                drop(has_new_measurement);
                drop(active_after_reset);

                if reset_index == last_reset_index {
                    let peer = waiting_for_reset.remove(changed_index);
                    peers.push(peer);
                }
            },
            Some(changed_index) = has_new_measurement.next() => {
                drop(has_new_measurement);
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

                let ntp_instant = NtpInstant::now();
                let system_poll = PollInterval::MIN;
                let result = FilterAndCombine::run(&config, &snapshots, ntp_instant, system_poll);

                match result {
                    Some(clock_select) => {
                        let offset_ms = clock_select.system_offset.to_seconds() * 1000.0;
                        let jitter_ms = clock_select.system_jitter.to_seconds() * 1000.0;
                        info!(offset_ms, jitter_ms, "system offset and jitter");

                        let adjust_type = controller.update(
                            clock_select.system_offset,
                            clock_select.system_jitter,
                            clock_select.system_peer_snapshot.root_delay,
                            clock_select.system_peer_snapshot.root_dispersion,
                            clock_select.system_peer_snapshot.leap_indicator,
                            clock_select.system_peer_snapshot.time,
                        );

                        // Handle situations needing extra processing
                        match adjust_type {
                            ClockUpdateResult::Panic => {
                                panic!("Unusually large clock step suggested, please manually verify system clock and reference clock state and restart if appropriate.")
                            }
                            ClockUpdateResult::Step => {
                                waiting_for_reset.append(&mut peers);
                                last_reset_index += 1;
                                reset_tx.send_replace(last_reset_index);
                            }
                            _ => {}
                        }

                        // Handle updating system snapshot
                        match adjust_type {
                            ClockUpdateResult::Ignore => {},
                            _ => {
                                let mut system_snapshot = *system_rx.borrow();
                                system_snapshot.poll_interval = controller.preferred_poll_interval();
                                system_snapshot.leap_indicator = clock_select.system_peer_snapshot.leap_indicator;
                                system_tx.send(system_snapshot).expect("System snapshot mechanism failed");
                            }
                        }
                    }
                    None => info!("filter and combine did not produce a result"),
                }
            }
        }
    }
}
