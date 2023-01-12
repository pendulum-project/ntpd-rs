// trivial server that forces an increment of the poll interval, then becomes a very bad NTP server

use ntp_proto::{NtpClock, NtpPacket, SystemSnapshot};
use std::{error::Error, io::Cursor, time::Instant};
use tokio::net::UdpSocket;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let socket = UdpSocket::bind("0.0.0.0:8080").await?;

    let clock = ntp_os_clock::UnixNtpClock::new();
    let mut last_message = Instant::now();

    let system = SystemSnapshot::default();

    let mut buf = [0; 48];
    loop {
        let (len, addr) = socket.recv_from(&mut buf).await?;
        let ntp_receive = clock.now().unwrap();
        println!("{:?} bytes received from {:?}", len, addr);

        let now = Instant::now();
        let delta = now.duration_since(last_message);
        println!("{}s since last packet", delta.as_secs());
        last_message = now;

        let parsed = match NtpPacket::deserialize(&buf) {
            Ok(packet) => packet,
            Err(_) => continue,
        };

        // default poll interval is 16 seconds, so this will bump it once
        // and then stay steady at 32 seconds
        let packet = if delta < std::time::Duration::new(30, 0) {
            NtpPacket::rate_limit_response(parsed)
        } else {
            NtpPacket::timestamp_response(&system, parsed, ntp_receive, &clock)
        };

        let mut buf = [0; 48];
        let mut cursor = Cursor::new(buf.as_mut_slice());
        packet.serialize(&mut cursor, None).unwrap();

        let pdata = &cursor.get_ref()[..cursor.position() as usize];
        let len = socket.send(pdata).await.unwrap();
        println!("{:?} bytes sent", len);
    }
}
