#![forbid(unsafe_code)]
mod peer;

use futures::{stream::FuturesUnordered, StreamExt};
use ntp_os_clock::UnixNtpClock;
use ntp_proto::{filter_and_combine, NtpClock, NtpDuration};
use peer::start_peer;
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let clock = UnixNtpClock::new();
    let mut peers = vec![
        start_peer("0.pool.ntp.org:123", UnixNtpClock::new())
            .await
            .unwrap(),
        start_peer("1.pool.ntp.org:123", UnixNtpClock::new())
            .await
            .unwrap(),
        start_peer("2.pool.ntp.org:123", UnixNtpClock::new())
            .await
            .unwrap(),
        start_peer("3.pool.ntp.org:123", UnixNtpClock::new())
            .await
            .unwrap(),
    ];

    loop {
        let i = {
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
        if peers[i].borrow().is_none() {
            continue;
        }

        let states: Vec<_> = peers
            .iter_mut()
            .filter_map(|c| *c.borrow_and_update())
            .collect();
        let result =
            filter_and_combine(&states, clock.now().unwrap(), NtpDuration::from_exponent(2));
        println!("{:?}", result);
    }
}
