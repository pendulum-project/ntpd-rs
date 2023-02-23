use std::{
    fs::File,
    future::Future,
    io::Write,
    io::{self, BufReader, IoSlice, Read},
    path::Path,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use ntp_proto::{KeyExchangeError, KeyExchangeServer, KeySet, KeySetProvider};
use rustls::{Certificate, PrivateKey};
use rustls_pemfile::{certs, rsa_private_keys};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpListener,
};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let addr = ("localhost", 4460u16);

    // geneted using openssl
    // ```
    // openssl req -nodes -x509 -days 3650 -subj "/C=NL/L=Nijmegen/O=TG/CN=localhost/" -newkey rsa:4096 -keyout rootCA.key -out rootCA.crt
    // openssl req -nodes -new -newkey rsa:4096 -subj "/C=NL/L=Nijmegen/O=TG/CN=localhost/" -addext "subjectAltName = DNS:localhost" -keyout tls.key -out tls.crt
    // openssl x509 -req -extfile <(printf "subjectAltName=DNS:example.com,DNS:www.example.com") -in tls.crt -days 3650 -CA rootCA.crt -CAkey rootCA.key -CAcreateserial -out signed.crt
    // openssl x509 -in signed.crt -text -noout
    // ```
    let certs = load_certs(Path::new("test-keys/signed.crt")).unwrap();
    let mut keys = load_keys(Path::new("test-keys/tls.key")).unwrap();

    let mut config = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, keys.remove(0))
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;

    config.alpn_protocols.clear();
    config.alpn_protocols.push(b"ntske/1".to_vec());

    let config = Arc::new(config);

    println!("listener running on {:?}", &addr);
    let listener = TcpListener::bind(&addr).await?;

    let provider = KeySetProvider::new(8);

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let config = config.clone();
        let keyset = provider.get();

        let fut = async move {
            let server = BoundKeyExchangeServer::new(stream, config, keyset).unwrap();

            server.await.unwrap();

            println!("Responded to: {}", peer_addr);

            Ok(()) as io::Result<()>
        };

        tokio::spawn(async move {
            if let Err(err) = fut.await {
                eprintln!("{:?}", err);
            }
        });
    }
}

fn load_certs(path: &Path) -> io::Result<Vec<Certificate>> {
    certs(&mut BufReader::new(File::open(path)?))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid cert"))
        .map(|mut certs| certs.drain(..).map(Certificate).collect())
}

fn load_keys(path: &Path) -> io::Result<Vec<PrivateKey>> {
    let keys: Vec<PrivateKey> = rsa_private_keys(&mut BufReader::new(File::open(path)?))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid key"))
        .map(|mut keys| keys.drain(..).map(PrivateKey).collect())?;

    // so instead of `rsa_private_keys`, maybe try `pkcs8_private_keys` or one of the other formats
    assert!(
        !keys.is_empty(),
        r"could not parse any keys. the parser returns an empty vec when the format does not match"
    );

    Ok(keys)
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
    pub fn new(
        io: IO,
        config: Arc<rustls::ServerConfig>,
        keyset: Arc<KeySet>,
    ) -> Result<Self, KeyExchangeError> {
        Ok(Self {
            inner: Some(BoundKeyExchangeServerData {
                io,
                server: KeyExchangeServer::new(config, keyset)?,
                need_flush: false,
            }),
        })
    }
}

struct BoundKeyExchangeServerData<IO> {
    io: IO,
    server: KeyExchangeServer,
    need_flush: bool,
}

// IO approach taken from tokio
impl<IO> BoundKeyExchangeServerData<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    fn do_write(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<usize>> {
        let mut writer = WriterAdapter {
            io: &mut self.io,
            cx,
        };

        match self.server.write_socket(&mut writer) {
            Err(ref err) if err.kind() == std::io::ErrorKind::WouldBlock => Poll::Pending,
            result => Poll::Ready(result),
        }
    }

    fn do_read(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<usize>> {
        let mut reader = ReaderAdapter {
            io: &mut self.io,
            cx,
        };
        match self.server.read_socket(&mut reader) {
            Err(ref err) if err.kind() == std::io::ErrorKind::WouldBlock => Poll::Pending,
            result => Poll::Ready(result),
        }
    }
}

impl<IO> Future for BoundKeyExchangeServer<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    type Output = Result<(), KeyExchangeError>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let outer = self.get_mut();
        let mut this = outer.inner.take().unwrap();

        let mut write_blocks = false;
        let mut read_blocks = false;

        loop {
            while !write_blocks && this.server.wants_write() {
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

            while !read_blocks && this.server.wants_read() {
                match this.do_read(cx) {
                    Poll::Ready(Ok(_)) => {
                        this.server = match this.server.progress() {
                            std::ops::ControlFlow::Continue(client) => client,
                            std::ops::ControlFlow::Break(result) => return Poll::Ready(result),
                        };
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
                    Poll::Pending => {
                        read_blocks = true;
                        break;
                    }
                }
            }

            if (write_blocks || !this.server.wants_write())
                && (read_blocks || !this.server.wants_read())
            {
                outer.inner = Some(this);
                return Poll::Pending;
            }
        }
    }
}

/// adapter between AsyncWrite and std::io::Write
struct WriterAdapter<'a, 'b, T> {
    io: &'a mut T,
    cx: &'a mut Context<'b>,
}

impl<'a, 'b, T: AsyncWrite + Unpin> Write for WriterAdapter<'a, 'b, T> {
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

/// adapter between AsyncRead and std::io::Read
struct ReaderAdapter<'a, 'b, T> {
    io: &'a mut T,
    cx: &'a mut Context<'b>,
}

impl<'a, 'b, T: AsyncRead + Unpin> Read for ReaderAdapter<'a, 'b, T> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
        let mut buf = ReadBuf::new(buf);
        match Pin::<&mut T>::new(self.io).poll_read(self.cx, &mut buf) {
            Poll::Ready(Ok(())) => Ok(buf.filled().len()),
            Poll::Ready(Err(e)) => Err(e),
            Poll::Pending => Err(std::io::ErrorKind::WouldBlock.into()),
        }
    }
}
