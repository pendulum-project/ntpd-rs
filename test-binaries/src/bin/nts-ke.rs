use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs},
    sync::Arc,
};

use aes_siv::{
    aead::{Aead, KeyInit, Payload},
    Aes128SivAead,
    Key, // Or `Aes128SivAead`
    Nonce,
};

use ntp_proto::NtsRecord;
use ntp_udp::UdpSocket;
use tokio_rustls::rustls;

fn key_exchange_client() -> Result<tokio_rustls::TlsConnector, rustls::Error> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs().expect("could not load platform certs") {
        roots.add(&rustls::Certificate(cert.0)).unwrap();
    }

    let mut config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols.push(b"ntske/1".to_vec());

    let rc_config = Arc::new(config);

    Ok(tokio_rustls::TlsConnector::from(rc_config))
}

// unstable in std; check on https://github.com/rust-lang/rust/issues/88581 some time in the future
pub const fn next_multiple_of(lhs: usize, rhs: usize) -> usize {
    match lhs % rhs {
        0 => lhs,
        r => lhs + (rhs - r),
    }
}

// unstable in std; check on https://github.com/rust-lang/rust/issues/88581 some time in the future
pub const fn div_ceil(lhs: usize, rhs: usize) -> usize {
    let d = lhs / rhs;
    let r = lhs % rhs;
    if r > 0 && rhs > 0 {
        d + 1
    } else {
        d
    }
}

fn key_exchange_packet(cookie: &[u8], c2s: &[u8; 32]) -> Vec<u8> {
    let mut packet = vec![
        0b00100011, 0, 10, 0, //hdr
        0, 0, 0, 0, // root delay
        0, 0, 0, 0, // root dispersion
        0, 0, 0, 0, // refid
        0, 0, 0, 0, 0, 0, 0, 0, // ref timestamp
        0, 0, 0, 0, 0, 0, 0, 0, // org timestamp
        0, 0, 0, 0, 0, 0, 0, 0, // recv timestamp
        1, 2, 3, 4, 5, 6, 7, 8, // xmt timestamp
    ];

    // Add unique identifier EF
    packet.extend_from_slice(&0x0104_u16.to_be_bytes());
    packet.extend_from_slice(&(32_u16 + 4).to_be_bytes());
    packet.extend((0..).take(32));

    // Add cookie EF
    packet.extend_from_slice(&0x0204_u16.to_be_bytes());

    // + 4 for the extension field header
    let cookie_octet_count = next_multiple_of(cookie.len(), 4) * 4 + 4;
    packet.extend_from_slice(&(cookie_octet_count as u16).to_be_bytes());

    packet.extend_from_slice(cookie);
    packet.extend(std::iter::repeat(0).take(4 - cookie.len() % 4));

    let cipher = Aes128SivAead::new(Key::<Aes128SivAead>::from_slice(c2s));
    let nonce = b"any unique nonce";
    let ct = cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: b"",
                aad: &packet,
            },
        )
        .unwrap();

    // Add signature EF
    packet.extend_from_slice(&0x0404_u16.to_be_bytes());

    let nonce_octet_count = next_multiple_of(nonce.len(), 4) * 4;
    let ct_octet_count = next_multiple_of(ct.len(), 4) * 4;

    // + 8 for the extension field header (4 bytes) and nonce/cypher text length (2 bytes each)
    let signature_octet_count = nonce_octet_count + ct_octet_count + 8;

    packet.extend_from_slice(&(signature_octet_count as u16).to_be_bytes());
    packet.extend_from_slice(&(nonce_octet_count as u16).to_be_bytes());
    packet.extend_from_slice(&(ct_octet_count as u16).to_be_bytes());

    packet.extend_from_slice(nonce);
    packet.extend(std::iter::repeat(0).take(4 - nonce.len() % 4));

    packet.extend_from_slice(&ct);
    packet.extend(std::iter::repeat(0).take(4 - ct.len() % 4));

    packet
}

fn key_exchange_records() -> [NtsRecord; 3] {
    [
        NtsRecord::NextProtocol {
            protocol_ids: vec![0],
        },
        NtsRecord::AeadAlgorithm {
            critical: false,
            algorithm_ids: vec![15],
        },
        NtsRecord::EndOfMessage,
    ]
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let domain = "time.cloudflare.com";
    let config = key_exchange_client().unwrap();

    let addr = (domain, 4460)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))?;

    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut stream = config
        .connect(domain.try_into().unwrap(), stream)
        .await
        .unwrap();

    let records = key_exchange_records();

    for record in records {
        record.async_write(&mut stream).await?;
    }

    let mut remote = domain.to_string();
    let mut port = 123;
    let mut cookie = None;

    loop {
        match NtsRecord::async_read(&mut stream).await? {
            NtsRecord::EndOfMessage => break,
            NtsRecord::NewCookie { cookie_data } => cookie = Some(cookie_data),
            NtsRecord::Server { name, .. } => remote = name.to_string(),
            NtsRecord::Port { port: p, .. } => port = p,
            _ => { /* ignore */ }
        }
    }

    let cookie = match cookie {
        Some(cookie) => cookie,
        None => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "did not receive cookie",
            ))
        }
    };

    println!("cookie: {:?}", &cookie);

    let mut c2s = [0; 32];
    let mut s2c = [0; 32];
    let label = b"EXPORTER-network-time-security";

    stream
        .get_ref()
        .1
        .export_keying_material(&mut c2s, label, Some(&[0, 0, 0, 15, 0]))
        .unwrap();
    stream
        .get_ref()
        .1
        .export_keying_material(&mut s2c, label, Some(&[0, 0, 0, 15, 1]))
        .unwrap();

    let addr = (remote, port).to_socket_addrs().unwrap().next().unwrap();

    let mut socket = match addr {
        SocketAddr::V4(_) => UdpSocket::client((Ipv4Addr::UNSPECIFIED, 0).into(), addr).await?,
        SocketAddr::V6(_) => UdpSocket::client((Ipv6Addr::UNSPECIFIED, 0).into(), addr).await?,
    };

    let packet = key_exchange_packet(&cookie, &c2s);
    socket.send(&packet).await?;
    let mut buf = [0; 1024];
    let (n, _remote, _timestamp) = socket.recv(&mut buf).await?;
    println!("response: {:?}", &buf[0..n]);

    Ok(())
}
