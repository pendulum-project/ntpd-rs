// an NTP server that responds to any incomming request with the DENY kiss code

use ntp_proto::{NtpHeader, ReferenceId};
use std::error::Error;
use tokio::net::UdpSocket;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let sock = UdpSocket::bind("0.0.0.0:8080").await?;

    let mut buf = [0; 1024];
    loop {
        let (len, addr) = sock.recv_from(&mut buf).await?;
        println!("{:?} bytes received from {:?}", len, addr);

        let parsed = NtpHeader::deserialize(buf[0..48].try_into().unwrap());

        let mut packet = ntp_proto::NtpHeader::default();
        packet.stratum = 0;
        packet.origin_timestamp = parsed.origin_timestamp;
        packet.reference_id = ReferenceId::KISS_DENY;

        let len = sock.send_to(&packet.serialize(), addr).await?;
        println!("{:?} bytes sent", len);
    }
}
