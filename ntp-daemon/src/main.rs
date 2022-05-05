#![forbid(unsafe_code)]
mod peer;

use std::error::Error;

use ntp_os_clock::UnixNtpClock;
use ntp_proto::{
    filter_and_combine, NtpClock, NtpDuration, NtpInstant, PeerSnapshot, SystemConfig,
    SystemSnapshot,
};
use peer::{start_peer, PeerChannels};

use futures::{stream::FuturesUnordered, StreamExt};
use tokio::sync::watch;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let config = SystemConfig::default();
    let clock = UnixNtpClock::new();

    let (system_tx, system_rx) = watch::channel::<SystemSnapshot>(SystemSnapshot::default());

    let new_peer = |address| start_peer(address, UnixNtpClock::new(), config, system_rx.clone());

    let mut peers = vec![
        new_peer("0.pool.ntp.org:123").await.unwrap(),
        new_peer("1.pool.ntp.org:123").await.unwrap(),
        new_peer("2.pool.ntp.org:123").await.unwrap(),
        new_peer("3.pool.ntp.org:123").await.unwrap(),
    ];

    let mut snapshots = Vec::with_capacity(peers.len());

    loop {
        let mut changed: FuturesUnordered<_> = peers
            .iter_mut()
            .enumerate()
            .map(|(i, c)| async move {
                c.peer_snapshot.changed().await.unwrap();
                i
            })
            .collect();

        tokio::select! {
            Some(changed_index) = changed.next() => {
                drop(changed);
                update_loop(changed_index, &mut peers, &mut snapshots, &clock, &system_tx).await?;
            },
        }
    }
}

async fn update_loop<C>(
    changed_index: usize,
    peers: &mut Vec<PeerChannels>,
    snapshots: &mut Vec<PeerSnapshot>,
    clock: &C,
    system_tx: &watch::Sender<SystemSnapshot>,
) -> Result<(), Box<dyn Error>>
where
    C: NtpClock,
{
    let msg = *peers[changed_index].peer_snapshot.borrow();
    match msg {
        peer::MsgForSystem::MustDemobilize => {
            peers.remove(changed_index);
            return Ok(());
        }
        peer::MsgForSystem::NoMeasurement => {
            return Ok(());
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
    let config = SystemConfig::default();
    let result = filter_and_combine(
        &config,
        snapshots,
        ntp_instant,
        NtpDuration::from_exponent(2),
    );

    match result {
        Some(clock_select) => {
            let offset_ms = clock_select.system_offset.to_seconds() * 1000.0;
            let jitter_ms = clock_select.system_jitter.to_seconds() * 1000.0;
            println!("offset: {:.3}ms (jitter: {}ms)", offset_ms, jitter_ms);
            println!();
        }
        None => println!("filter and combine did not produce a result"),
    }

    // TODO produce an updated snapshot
    let system_snapshot = SystemSnapshot::default();
    system_tx.send(system_snapshot)?;

    Ok(())
}
