use std::{
    future::Future,
    io::{Cursor, IoSlice, Read, Write},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs},
    pin::Pin,
    task::{Context, Poll},
};

use ntp_proto::{KeyExchangeClient, KeyExchangeError, KeyExchangeResult, NtpPacket, PollInterval};
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

    // adapter between AsyncWrite and std::io::Write
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

    // adapter between AsyncRead and std::io::Read
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

pub(crate) async fn perform_key_exchange(
    server_name: String,
    port: u16,
) -> Result<KeyExchangeResult, KeyExchangeError> {
    let socket = tokio::net::TcpStream::connect((server_name.as_str(), port))
        .await
        .unwrap();

    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs().expect("could not load platform certs") {
        roots.add(&rustls::Certificate(cert.0)).unwrap();
    }

    let config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(roots)
        .with_no_client_auth();

    BoundKeyExchangeClient::new(socket, server_name, config)?.await
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let domain = "time.cloudflare.com";
    let port = 4460;

    let mut key_exchange = perform_key_exchange(domain.to_string(), port)
        .await
        .unwrap();

    let cookie = key_exchange.nts.get_cookie().unwrap();
    let (c2s, _) = key_exchange.nts.get_keys();

    println!("cookie: {:?}", cookie);

    let addr = (key_exchange.remote, key_exchange.port)
        .to_socket_addrs()
        .unwrap()
        .next()
        .unwrap();

    let mut socket = match addr {
        SocketAddr::V4(_) => UdpSocket::client((Ipv4Addr::UNSPECIFIED, 0).into(), addr).await?,
        SocketAddr::V6(_) => UdpSocket::client((Ipv6Addr::UNSPECIFIED, 0).into(), addr).await?,
    };

    let (packet, _) = NtpPacket::nts_poll_message(&cookie, 1, PollInterval::default());

    let mut raw = [0u8; 1024];
    let mut w = Cursor::new(raw.as_mut_slice());
    packet.serialize(&mut w, Some(&c2s))?;
    socket.send(&w.get_ref()[..w.position() as usize]).await?;

    let mut buf = [0; 1024];
    let (n, _remote, _timestamp) = socket.recv(&mut buf).await?;
    println!("response: {:?}", &buf[0..n]);

    Ok(())
}
