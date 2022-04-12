#![forbid(unsafe_code)]

use ntp_os_clock::UnixNtpClock;
use ntp_proto::{NtpClock, NtpHeader};
use std::env;
use std::error::Error;
use tokio::net::UdpSocket;

/// Connect with the `time.google.com` NTP server
async fn setup_connection() -> std::io::Result<UdpSocket> {
    let addr = env::args()
        .nth(1)
        .unwrap_or_else(|| "0.0.0.0:8080".to_string());

    let socket = UdpSocket::bind(&addr).await?;

    let host_ip = "216.239.35.4"; // time.google.com
    let port = 123;

    socket.connect((host_ip, port)).await?;

    Ok(socket)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let socket = setup_connection().await?;
    let clock = UnixNtpClock::new();

    let initial = NtpHeader::new();
    let mut buf = initial.serialize();

    let t1 = clock.now().unwrap();

    let sent = socket.send(&buf).await.unwrap();
    assert!(sent == 48);

    let received = socket.recv(&mut buf).await.unwrap();
    assert!(received == 48);

    let t4 = clock.now().unwrap();

    let packet = ntp_proto::NtpHeader::deserialize(&buf);

    let t2 = packet.receive_timestamp;
    let t3 = packet.transmit_timestamp;

    let delta1 = t4 - t1;
    let delta2 = t3 - t2;

    dbg!(delta1, delta2);

    // let double_theta = (t2 - t1) + (t4 - t3);

    Ok(())
}
