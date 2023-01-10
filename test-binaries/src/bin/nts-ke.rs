use std::{
    future::Future,
    io::{IoSlice, Read, Write},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs},
    pin::Pin,
    task::{Context, Poll},
};

use aes_siv::{
    aead::{Aead, Payload},
    Aes128SivAead, Nonce,
};

use ntp_proto::{KeyExchangeClient, KeyExchangeError, KeyExchangeResult};
use ntp_udp::UdpSocket;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::rustls;

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

fn key_exchange_packet(cookie: &[u8], cipher: Aes128SivAead) -> Vec<u8> {
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
    let cookie_octet_count = next_multiple_of(cookie.len(), 4) + 4;
    packet.extend_from_slice(&(cookie_octet_count as u16).to_be_bytes());

    packet.extend_from_slice(cookie);
    packet.extend(std::iter::repeat(0).take(cookie_octet_count - 4 - cookie.len()));

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

    let nonce_octet_count = next_multiple_of(nonce.len(), 4);
    let ct_octet_count = next_multiple_of(ct.len(), 4);

    // + 8 for the extension field header (4 bytes) and nonce/cypher text length (2 bytes each)
    let signature_octet_count = nonce_octet_count + ct_octet_count + 8;

    packet.extend_from_slice(&(signature_octet_count as u16).to_be_bytes());
    packet.extend_from_slice(&(nonce.len() as u16).to_be_bytes());
    packet.extend_from_slice(&(ct.len() as u16).to_be_bytes());

    packet.extend_from_slice(nonce);
    packet.extend(std::iter::repeat(0).take(nonce_octet_count - nonce.len()));

    packet.extend_from_slice(&ct);
    packet.extend(std::iter::repeat(0).take(ct_octet_count - ct.len()));

    packet
}

struct BoundKeyExchangeClient<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    io: IO,
    client: Option<KeyExchangeClient>,
    need_flush: bool,
}

// IO approach taken from tokio
impl<IO> BoundKeyExchangeClient<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new(
        io: IO,
        server_name: String,
        config: rustls::ClientConfig,
    ) -> Result<Self, KeyExchangeError> {
        Ok(Self {
            io,
            client: Some(KeyExchangeClient::new(server_name, config)?),
            need_flush: false,
        })
    }

    fn do_write(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<usize>> {
        struct Writer<'a, 'b, T> {
            io: &'a mut T,
            cx: &'a mut Context<'b>,
        }

        impl<'a, 'b, T: AsyncWrite + Unpin> Write for Writer<'a, 'b, T> {
            #[inline]
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                match Pin::<&mut T>::new(self.io).poll_write(self.cx, buf) {
                    Poll::Ready(result) => result,
                    Poll::Pending => Err(std::io::ErrorKind::WouldBlock.into()),
                }
            }

            #[inline]
            fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> std::io::Result<usize> {
                match Pin::<&mut T>::new(self.io).poll_write_vectored(self.cx, bufs) {
                    Poll::Ready(result) => result,
                    Poll::Pending => Err(std::io::ErrorKind::WouldBlock.into()),
                }
            }

            fn flush(&mut self) -> std::io::Result<()> {
                match Pin::<&mut T>::new(self.io).poll_flush(self.cx) {
                    Poll::Ready(result) => result,
                    Poll::Pending => Err(std::io::ErrorKind::WouldBlock.into()),
                }
            }
        }

        let mut writer = Writer {
            io: &mut self.io,
            cx,
        };

        match self.client.as_mut().unwrap().write_socket(&mut writer) {
            Err(ref err) if err.kind() == std::io::ErrorKind::WouldBlock => Poll::Pending,
            result => Poll::Ready(result),
        }
    }

    fn do_read(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<usize>> {
        struct Reader<'a, 'b, T> {
            io: &'a mut T,
            cx: &'a mut Context<'b>,
        }

        impl<'a, 'b, T: AsyncRead + Unpin> Read for Reader<'a, 'b, T> {
            fn read(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
                let mut buf = ReadBuf::new(buf);
                match Pin::<&mut T>::new(self.io).poll_read(self.cx, &mut buf) {
                    Poll::Ready(Ok(())) => Ok(buf.filled().len()),
                    Poll::Ready(Err(e)) => Err(e),
                    Poll::Pending => Err(std::io::ErrorKind::WouldBlock.into()),
                }
            }
        }

        let mut reader = Reader {
            io: &mut self.io,
            cx,
        };
        match self.client.as_mut().unwrap().read_socket(&mut reader) {
            Err(ref err) if err.kind() == std::io::ErrorKind::WouldBlock => Poll::Pending,
            result => Poll::Ready(result),
        }
    }
}

impl<IO> Future for BoundKeyExchangeClient<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    type Output = Result<KeyExchangeResult, KeyExchangeError>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let this = self.get_mut();

        let mut write_blocks = false;
        let mut read_blocks = false;

        loop {
            while !write_blocks && this.client.as_mut().unwrap().wants_write() {
                match this.do_write(cx) {
                    Poll::Ready(Ok(_)) => {
                        this.need_flush = true;
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
                    Poll::Pending => {
                        write_blocks = true;
                        break;
                    }
                }
            }

            if !write_blocks && this.need_flush {
                match Pin::new(&mut this.io).poll_flush(cx) {
                    Poll::Ready(Ok(())) => {
                        this.need_flush = false;
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
                    Poll::Pending => {
                        write_blocks = true;
                    }
                }
            }

            while !read_blocks && this.client.as_mut().unwrap().wants_read() {
                match this.do_read(cx) {
                    Poll::Ready(Ok(_)) => match this.client.take().unwrap().progress() {
                        std::ops::ControlFlow::Continue(client) => this.client = Some(client),
                        std::ops::ControlFlow::Break(result) => return Poll::Ready(result),
                    },
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
                    Poll::Pending => {
                        read_blocks = true;
                        break;
                    }
                }
            }

            if (write_blocks || !this.client.as_mut().unwrap().wants_write())
                && (read_blocks || !this.client.as_mut().unwrap().wants_read())
            {
                return Poll::Pending;
            }
        }
    }
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let domain = "time.cloudflare.com";

    let addr = (domain, 4460)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))?;

    let socket = tokio::net::TcpStream::connect(addr).await.unwrap();

    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs().expect("could not load platform certs") {
        roots.add(&rustls::Certificate(cert.0)).unwrap();
    }

    let config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(roots)
        .with_no_client_auth();

    let result = BoundKeyExchangeClient::new(socket, domain.to_string(), config)
        .unwrap()
        .await
        .unwrap();

    let cookie = &result.cookies[0];

    println!("cookie: {:?}", cookie);

    let addr = (result.remote, result.port)
        .to_socket_addrs()
        .unwrap()
        .next()
        .unwrap();

    let mut socket = match addr {
        SocketAddr::V4(_) => UdpSocket::client((Ipv4Addr::UNSPECIFIED, 0).into(), addr).await?,
        SocketAddr::V6(_) => UdpSocket::client((Ipv6Addr::UNSPECIFIED, 0).into(), addr).await?,
    };

    let packet = key_exchange_packet(cookie, result.key_c2s);
    socket.send(&packet).await?;
    let mut buf = [0; 1024];
    let (n, _remote, _timestamp) = socket.recv(&mut buf).await?;
    println!("response: {:?}", &buf[0..n]);

    Ok(())
}
