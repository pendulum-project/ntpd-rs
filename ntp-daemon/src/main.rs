#![forbid(unsafe_code)]
mod peer;

use ntp_os_clock::UnixNtpClock;
use peer::start_peer;
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let clock = UnixNtpClock::new();
    let mut channel = start_peer("216.239.35.4:123", clock).await.unwrap();

    loop {
        channel.changed().await.unwrap();
        println!("{:?}", channel.borrow_and_update().as_ref())
    }
}
