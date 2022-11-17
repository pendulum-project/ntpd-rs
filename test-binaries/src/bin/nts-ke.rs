use std::{
    io::Write,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket},
    sync::Arc,
};

use aes_siv::{
    aead::{Aead, KeyInit, Payload},
    Aes128SivAead,
    Key, // Or `Aes128SivAead`
    Nonce,
};

use ntp_proto::NtsRecord;
use tokio_rustls::rustls::{self, ServerName};

fn key_exchange_client(server_name: ServerName) -> Result<rustls::ClientConnection, rustls::Error> {
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

    rustls::ClientConnection::new(rc_config, server_name)
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

fn key_exchange_request(writer: &mut impl Write) -> std::io::Result<()> {
    let message = [
        NtsRecord::NextProtocol {
            protocol_ids: [0].into(),
        },
        NtsRecord::AeadAlgorithm {
            critical: false,
            algorithm_ids: [15].into(),
        },
        NtsRecord::EndOfMessage,
    ];

    for r in message {
        r.write(writer)?;
    }

    Ok(())
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

struct CookieForRemote {
    remote: String,
    port: u16,
    cookie: Vec<u8>,
}

fn receive_response(
    client: &mut rustls::ClientConnection,
    domain: &str,
) -> std::io::Result<CookieForRemote> {
    const KE_PORT: u16 = 4460;
    let mut socket = TcpStream::connect((domain, KE_PORT))?;

    let mut remote = domain.to_string();
    let mut port = 123;
    let mut cookie = None;

    loop {
        if client.wants_write() {
            client.write_tls(&mut socket)?;
        } else if client.wants_read() {
            client.read_tls(&mut socket)?;
            client.process_new_packets().unwrap();
        } else {
            match NtsRecord::read(&mut client.reader())? {
                NtsRecord::EndOfMessage => break,
                NtsRecord::NewCookie { cookie_data } => cookie = Some(cookie_data),
                NtsRecord::Server { name, .. } => remote = name.to_string(),
                NtsRecord::Port { port: p, .. } => port = p,
                _ => { /* ignore */ }
            }
        }
    }

    match cookie {
        Some(cookie) => Ok(CookieForRemote {
            remote,
            port,
            cookie,
        }),
        None => Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "did not receive cookie",
        )),
    }
}

fn main() -> std::io::Result<()> {
    let domain = "time.cloudflare.com";
    let mut client = key_exchange_client(domain.try_into().unwrap()).unwrap();

    key_exchange_request(&mut client.writer())?;

    let response = receive_response(&mut client, domain)?;
    println!("cookie: {:?}", &response.cookie);

    let mut c2s = [0; 32];
    let mut s2c = [0; 32];
    let label = b"EXPORTER-network-time-security";

    client
        .export_keying_material(&mut c2s, label, Some(&[0, 0, 0, 15, 0]))
        .unwrap();
    client
        .export_keying_material(&mut s2c, label, Some(&[0, 0, 0, 15, 1]))
        .unwrap();

    let addr = (response.remote, response.port)
        .to_socket_addrs()
        .unwrap()
        .next()
        .unwrap();

    let socket = match addr {
        SocketAddr::V4(_) => UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?,
        SocketAddr::V6(_) => UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0))?,
    };

    socket.connect(addr)?;

    let packet = key_exchange_packet(&response.cookie, &c2s);
    socket.send(&packet)?;
    let mut buf = [0; 1024];
    let n = socket.recv(&mut buf)?;
    println!("{:?}", &buf[0..n]);

    Ok(())
}
