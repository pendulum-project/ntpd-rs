#![forbid(unsafe_code)]
mod peer;

use futures::{stream::FuturesUnordered, StreamExt};
use ntp_os_clock::UnixNtpClock;
use ntp_proto::{
    ClockController, ClockUpdateResult, FilterAndCombine, NtpInstant, PeerSnapshot, PollInterval,
    SystemConfig, SystemSnapshot,
};
use peer::{start_peer, MsgForSystem, PeerChannels};
use tracing::info;

use std::error::Error;
use tokio::sync::watch;

#[derive(Debug, Clone, Copy)]
enum PeerState {
    Demobilized,
    AwaitingReset,
    Valid(PeerSnapshot),
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt::init();

    let config = SystemConfig::default();

    // channel for sending updated system state to the peers
    let (system_tx, system_rx) = watch::channel::<SystemSnapshot>(SystemSnapshot::default());

    // channel to send the reset signal to all peers
    let (reset_tx, reset_rx) = watch::channel::<u64>(0);
    let mut last_reset_index: u64 = 0;

    let (msg_for_system_tx, mut msg_for_system_rx) = tokio::sync::mpsc::channel::<MsgForSystem>(32);

    let mut controller = ClockController::new(UnixNtpClock::new());

    let peer_addresses = [
        "0.pool.ntp.org:123",
        "1.pool.ntp.org:123",
        "2.pool.ntp.org:123",
        "3.pool.ntp.org:123",
    ];

    let mut peers = Vec::with_capacity(peer_addresses.len());

    for (index, address) in peer_addresses.iter().enumerate() {
        let peer = start_peer(
            index,
            address,
            UnixNtpClock::new(),
            config,
            msg_for_system_tx.clone(),
            system_rx.clone(),
            reset_rx.clone(),
        )
        .await
        .unwrap();

        peers.push(peer);
    }

    let mut peers2 = vec![PeerState::AwaitingReset; peers.len()];

    let mut snapshots = Vec::with_capacity(peers.len());

    // when we perform a clock jump, all current measurement data is off. We force all associations
    // to clear their measurement data and get new data. This vector contains associations that
    // have not yet confirmed that their measurement data has been cleared.
    let mut waiting_for_reset: Vec<PeerChannels> = Vec::with_capacity(peers.len());

    loop {
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
                drop(active_after_reset);

                if reset_index == last_reset_index {
                    let peer = waiting_for_reset.remove(changed_index);
                    peers.push(peer);
                }
            },
            Some(msg_for_system) = msg_for_system_rx.recv() => {
                receive_msg_for_system(&mut peers2, msg_for_system, last_reset_index);

                // remove snapshots from previous iteration
                snapshots.clear();

                for peer_state in &peers2 {
                    if let PeerState::Valid(snapshot) = peer_state {
                        snapshots.push(*snapshot);
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
                                for peer_state in peers2.iter_mut() {
                                    if let PeerState::Valid(_) = peer_state {
                                        *peer_state = PeerState::AwaitingReset;
                                    }
                                }

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

fn receive_msg_for_system(
    peers: &mut [PeerState],
    msg_for_system: MsgForSystem,
    current_reset_epoch: u64,
) {
    match msg_for_system {
        MsgForSystem::MustDemobilize(index) => {
            peers[index] = PeerState::Demobilized;
        }
        MsgForSystem::Snapshot(index, msg_reset_epoch, snapshot) => {
            if current_reset_epoch == msg_reset_epoch {
                peers[index] = PeerState::Valid(snapshot);
            }
        }
    }
}
