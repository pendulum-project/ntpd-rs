use std::{
    future::Future,
    io::{BufRead, BufReader, IoSlice, Read, Write},
    path::Path,
    pin::Pin,
    task::{Context, Poll},
};

use ntp_proto::{
    KeyExchangeClient, KeyExchangeClientResult, KeyExchangeError, KeyExchangeServer,
    KeyExchangeServerResult,
};
use rustls::Certificate;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

// --certs /home/folkertdev/tg/ntp/ntpd-rs/test-keys/sample.pem --key /home/folkertdev/tg/ntp/ntpd-rs/test-keys/sample.rsa

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind("0.0.0.0:4460").await?;

    loop {
        let (stream, socket) = listener.accept().await?;

        dbg!(socket);

        key_exchange_server(stream).await.unwrap();
    }

    Ok(())
}

fn error(err: String) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, err)
}

// Load private key from file.
fn load_private_key(filename: &str) -> std::io::Result<rustls::PrivateKey> {
    use std::{fs, io};

    // Open keyfile.
    let keyfile = fs::File::open(filename)
        .map_err(|e| error(format!("failed to open {}: {}", filename, e)))?;
    let mut reader = io::BufReader::new(keyfile);

    // Load and return a single private key.
    let keys = rustls_pemfile::rsa_private_keys(&mut reader)
        .map_err(|_| error("failed to load private key".into()))?;
    if keys.is_empty() {
        return Err(error(format!("no keys in key file {filename:?}")));
    }
    if keys.len() != 1 {
        return Err(error("expected a single private key".into()));
    }

    Ok(rustls::PrivateKey(keys[0].clone()))
}

// Load public certificate from file.
fn load_certs(filename: &str) -> std::io::Result<Vec<rustls::Certificate>> {
    use std::{fs, io};

    // Open certificate file.
    let certfile = fs::File::open(filename)
        .map_err(|e| error(format!("failed to open {}: {}", filename, e)))?;
    let mut reader = io::BufReader::new(certfile);

    // Load and return certificate.
    let certs = rustls_pemfile::certs(&mut reader)
        .map_err(|_| error("failed to load certificate".into()))?;

    let mut certs: Vec<_> = certs.into_iter().map(rustls::Certificate).collect();

    certs.extend(
        rustls_native_certs::load_native_certs()
            .expect("could not load platform certs")
            .into_iter()
            .map(|t| rustls::Certificate(t.0)),
    );

    Ok(certs)
}

pub(crate) async fn key_exchange_server(
    stream: tokio::net::TcpStream,
) -> Result<KeyExchangeServerResult, KeyExchangeError> {
    // Build TLS configuration.
    let tls_cfg = {
        // Load public certificate.
        let certs = load_certs("test-keys/signed.crt").unwrap();
        // Load private key.
        let key = load_private_key("test-keys/tls.key").unwrap();
        // Do not use client certificate authentication.
        let mut cfg = rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| error(format!("{}", e)))
            .unwrap();

        // Ensure we send only ntske/1 as alpn
        cfg.alpn_protocols.clear();
        cfg.alpn_protocols.push(b"ntske/1".to_vec());

        cfg
    };

    BoundKeyExchangeServer::new(stream, tls_cfg)?.await
}

pub(crate) struct BoundKeyExchangeServer<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    inner: Option<BoundKeyExchangeServerData<IO>>,
}

impl<IO> BoundKeyExchangeServer<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new(io: IO, config: rustls::ServerConfig) -> Result<Self, KeyExchangeError> {
        Ok(Self {
            inner: Some(BoundKeyExchangeServerData {
                io,
                client: KeyExchangeServer::new(config)?,
                need_flush: false,
            }),
        })
    }
}

struct BoundKeyExchangeServerData<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    io: IO,
    client: KeyExchangeServer,
    need_flush: bool,
}

// IO approach taken from tokio
impl<IO> BoundKeyExchangeServerData<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
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

        match self.client.write_socket(&mut writer) {
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
        match self.client.read_socket(&mut reader) {
            Err(ref err) if err.kind() == std::io::ErrorKind::WouldBlock => Poll::Pending,
            result => Poll::Ready(result),
        }
    }
}

impl<IO> Future for BoundKeyExchangeServer<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    type Output = Result<KeyExchangeServerResult, KeyExchangeError>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let outer = self.get_mut();
        let mut this = outer.inner.take().unwrap();

        let mut write_blocks = false;
        let mut read_blocks = false;

        loop {
            dbg!("foobar");
            while !write_blocks && this.client.wants_write() {
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

            while !read_blocks && this.client.wants_read() {
                match this.do_read(cx) {
                    Poll::Ready(Ok(_)) => {
                        this.client = match this.client.progress() {
                            std::ops::ControlFlow::Continue(client) => client,
                            std::ops::ControlFlow::Break(result) => return Poll::Ready(result),
                        }
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
                    Poll::Pending => {
                        read_blocks = true;
                        break;
                    }
                }
            }

            if (write_blocks || !this.client.wants_write())
                && (read_blocks || !this.client.wants_read())
            {
                outer.inner = Some(this);
                return Poll::Pending;
            }
        }
    }
}
