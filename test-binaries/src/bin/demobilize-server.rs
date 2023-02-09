// an NTP server that responds to any incomming request with the DENY kiss code

use ntp_proto::{NoCipher, NtpPacket};
use std::{error::Error, io::Cursor};
use tokio::net::UdpSocket;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let socket = UdpSocket::bind("0.0.0.0:8080").await?;

    let mut buf = [0; 1024];
    #[allow(clippy::field_reassign_with_default)] // allow the explicit stratum
    loop {
        let (len, addr) = socket.recv_from(&mut buf).await?;
        println!("{len:?} bytes received from {addr:?}");

        let parsed = match NtpPacket::deserialize(buf[0..48].try_into().unwrap(), &NoCipher) {
            Ok(packet) => packet,
            Err(_) => continue,
        };

        let packet = NtpPacket::deny_response(parsed);
        let mut buf = [0; 48];
        let mut cursor = Cursor::new(buf.as_mut_slice());
        packet.serialize(&mut cursor, &NoCipher).unwrap();

        let pdata = &cursor.get_ref()[..cursor.position() as usize];
        let len = socket.send(pdata).await.unwrap();
        println!("{len:?} bytes sent");
    }
}
