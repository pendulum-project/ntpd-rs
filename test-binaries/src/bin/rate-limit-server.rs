// trivial server that forces an increment of the poll interval, then becomes a very bad NTP server

use ntp_proto::{NtpAssociationMode, NtpClock, NtpHeader, ReferenceId};
use std::{error::Error, time::Instant};
use tokio::net::UdpSocket;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let sock = UdpSocket::bind("0.0.0.0:8080").await?;

    let clock = ntp_os_clock::UnixNtpClock::new();
    let mut last_message = Instant::now();

    let mut buf = [0; 48];
    loop {
        let (len, addr) = sock.recv_from(&mut buf).await?;
        let ntp_receive = clock.now().unwrap();
        println!("{:?} bytes received from {:?}", len, addr);

        let now = Instant::now();
        let delta = now.duration_since(last_message);
        println!("{}s since last packet", delta.as_secs());
        last_message = now;

        let mut packet = ntp_proto::NtpHeader::default();

        // default poll interval is 16 seconds, so this will bump it once
        // and then stay steady at 32 seconds
        if delta < std::time::Duration::new(30, 0) {
            packet.reference_id = ReferenceId::KISS_RATE;
            packet.stratum = 0;
        } else {
            let parsed = NtpHeader::deserialize(&buf);

            packet.mode = NtpAssociationMode::Server;
            packet.stratum = 1;
            packet.origin_timestamp = parsed.transmit_timestamp;
            packet.receive_timestamp = ntp_receive;
            packet.transmit_timestamp = clock.now().unwrap();
        }

        let len = sock.send_to(&packet.serialize(), addr).await?;
        println!("{:?} bytes sent", len);
    }
}
