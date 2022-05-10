#![forbid(unsafe_code)]
mod peer;

use futures::{stream::FuturesUnordered, StreamExt};
use ntp_os_clock::UnixNtpClock;
use ntp_proto::{filter_and_combine, NtpClock, NtpInstant, PollInterval, SystemSnapshot};
use peer::start_peer;
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let clock = UnixNtpClock::new();

    use tokio::sync::watch;
    let (system_tx, system_rx) = watch::channel::<SystemSnapshot>(SystemSnapshot::default());

    let mut peers = vec![
        start_peer("0.pool.ntp.org:123", UnixNtpClock::new(), system_rx.clone())
            .await
            .unwrap(),
        start_peer("1.pool.ntp.org:123", UnixNtpClock::new(), system_rx.clone())
            .await
            .unwrap(),
        start_peer("2.pool.ntp.org:123", UnixNtpClock::new(), system_rx.clone())
            .await
            .unwrap(),
        start_peer("3.pool.ntp.org:123", UnixNtpClock::new(), system_rx)
            .await
            .unwrap(),
    ];

    let mut snapshots = Vec::with_capacity(peers.len());

    loop {
        let changed_index = {
            let mut changed: FuturesUnordered<_> = peers
                .iter_mut()
                .enumerate()
                .map(|(i, c)| async move {
                    c.changed().await.unwrap();
                    i
                })
                .collect();

            changed.next().await.unwrap()
        };

        let msg = *peers[changed_index].borrow();
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
            let msg = *peers[i].borrow_and_update();
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
        let result = filter_and_combine(&snapshots, ntp_instant, system_poll);

        match result {
            Some(clock_select) => {
                let offset_ms = clock_select.system_offset.to_seconds() * 1000.0;
                let jitter_ms = clock_select.system_jitter.to_seconds() * 1000.0;
                println!("offset: {:.3}ms (jitter: {}ms)", offset_ms, jitter_ms);
                println!();

                // TODO update system state with result.system_peer_variables

                // TODO produce an updated snapshot
                let system_snapshot = SystemSnapshot::default();
                system_tx.send(system_snapshot)?;
            }
            None => println!("filter and combine did not produce a result"),
        }
    }
}
