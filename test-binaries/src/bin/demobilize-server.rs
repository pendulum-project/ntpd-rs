// an NTP server that responds to any incomming request with the DENY kiss code

use ntp_proto::NtpPacket;
use std::error::Error;
use tokio::net::UdpSocket;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let sock = UdpSocket::bind("0.0.0.0:8080").await?;

    let mut buf = [0; 1024];
    #[allow(clippy::field_reassign_with_default)] // allow the explicit stratum
    loop {
        let (len, addr) = sock.recv_from(&mut buf).await?;
        println!("{:?} bytes received from {:?}", len, addr);

        let parsed = match NtpPacket::deserialize(buf[0..48].try_into().unwrap()) {
            Ok(packet) => packet,
            Err(_) => continue,
        };

        let packet = NtpPacket::deny_response(parsed);
        let mut pdata = vec![];
        packet.serialize(&mut pdata).unwrap();

        let len = sock.send_to(&pdata, addr).await?;
        println!("{:?} bytes sent", len);
    }
}
