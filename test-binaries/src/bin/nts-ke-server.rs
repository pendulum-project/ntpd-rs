use std::{
    fs::File,
    future::Future,
    io::Write,
    io::{self, BufReader, IoSlice, Read},
    ops::{Deref, DerefMut},
    path::Path,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use std::task::ready;

use ntp_proto::{KeyExchangeError, KeyExchangeServer, KeyExchangeServerResult};
use rustls::{Certificate, ConnectionCommon, PrivateKey, ServerConfig, ServerConnection, SideData};
use rustls_pemfile::{certs, rsa_private_keys};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpListener,
};

const NTS_TIME_NL_RESPONSE: &[u8] = &[
    128, 1, 0, 2, 0, 0, 0, 4, 0, 2, 0, 15, 0, 5, 0, 104, 178, 15, 188, 164, 68, 107, 175, 34, 77,
    63, 18, 34, 122, 22, 95, 242, 175, 224, 29, 173, 58, 187, 47, 11, 245, 247, 119, 89, 5, 8, 221,
    162, 106, 66, 30, 65, 218, 13, 108, 238, 12, 29, 200, 9, 92, 218, 38, 20, 238, 251, 68, 35, 44,
    129, 189, 132, 4, 93, 117, 136, 91, 234, 58, 195, 223, 171, 207, 247, 172, 128, 5, 219, 97, 21,
    128, 107, 96, 220, 189, 53, 223, 111, 181, 164, 185, 173, 80, 101, 75, 18, 180, 129, 243, 140,
    253, 236, 45, 62, 101, 155, 252, 51, 102, 97, 0, 5, 0, 104, 178, 15, 188, 164, 106, 99, 31,
    229, 75, 104, 141, 204, 89, 184, 80, 227, 43, 85, 25, 33, 78, 82, 22, 97, 167, 52, 65, 243,
    216, 198, 99, 98, 161, 219, 215, 253, 165, 121, 130, 232, 131, 150, 158, 136, 113, 141, 34,
    223, 42, 122, 185, 132, 185, 153, 158, 249, 192, 80, 167, 251, 116, 45, 179, 151, 82, 248, 13,
    208, 33, 74, 125, 233, 176, 153, 61, 58, 25, 23, 54, 106, 208, 31, 40, 155, 227, 63, 58, 219,
    119, 76, 101, 62, 154, 34, 187, 212, 106, 162, 140, 223, 37, 194, 20, 107, 0, 5, 0, 104, 178,
    15, 188, 164, 240, 20, 28, 103, 149, 25, 37, 145, 187, 196, 100, 113, 36, 76, 171, 29, 69, 40,
    19, 70, 95, 60, 30, 27, 188, 25, 1, 148, 55, 18, 253, 131, 8, 108, 44, 173, 236, 74, 227, 49,
    47, 183, 156, 118, 152, 88, 31, 254, 134, 220, 129, 254, 186, 117, 80, 163, 167, 223, 208, 8,
    124, 141, 240, 43, 161, 240, 60, 54, 241, 44, 87, 135, 116, 63, 236, 40, 138, 162, 65, 143,
    193, 98, 44, 9, 61, 189, 89, 19, 45, 94, 6, 102, 82, 8, 175, 206, 87, 132, 51, 63, 0, 5, 0,
    104, 178, 15, 188, 164, 56, 48, 71, 172, 153, 142, 223, 150, 73, 72, 201, 236, 26, 68, 29, 14,
    139, 66, 190, 77, 218, 206, 90, 117, 75, 128, 88, 186, 187, 156, 130, 57, 198, 118, 176, 199,
    55, 56, 173, 109, 35, 37, 15, 223, 17, 53, 110, 167, 251, 167, 208, 44, 158, 89, 113, 22, 178,
    92, 235, 114, 176, 41, 255, 172, 175, 191, 227, 29, 85, 70, 152, 125, 67, 125, 96, 151, 151,
    160, 188, 8, 35, 205, 152, 142, 225, 59, 71, 224, 254, 84, 20, 51, 162, 164, 94, 241, 7, 15, 9,
    138, 0, 5, 0, 104, 178, 15, 188, 164, 198, 114, 113, 134, 102, 130, 116, 104, 6, 6, 81, 118,
    89, 146, 119, 198, 80, 135, 104, 155, 101, 107, 51, 215, 243, 241, 163, 55, 84, 206, 179, 241,
    105, 210, 184, 30, 44, 133, 235, 227, 87, 7, 40, 230, 185, 47, 180, 189, 84, 157, 182, 81, 69,
    168, 147, 115, 94, 53, 242, 198, 132, 188, 56, 86, 70, 201, 78, 219, 140, 212, 94, 100, 38,
    106, 168, 35, 57, 236, 156, 41, 86, 176, 225, 129, 152, 206, 49, 176, 252, 29, 235, 180, 161,
    148, 195, 223, 27, 217, 85, 220, 0, 5, 0, 104, 178, 15, 188, 164, 52, 150, 226, 182, 229, 113,
    23, 67, 155, 54, 34, 141, 125, 225, 98, 4, 22, 105, 111, 150, 212, 32, 9, 204, 212, 242, 161,
    213, 135, 199, 246, 74, 160, 126, 167, 94, 174, 76, 11, 228, 13, 251, 20, 135, 0, 197, 207, 18,
    168, 118, 218, 39, 79, 100, 203, 234, 224, 116, 59, 234, 247, 156, 128, 58, 104, 57, 204, 85,
    48, 68, 229, 37, 20, 146, 159, 67, 49, 235, 142, 58, 225, 149, 187, 3, 11, 146, 193, 114, 122,
    160, 19, 180, 146, 196, 50, 229, 22, 10, 86, 219, 0, 5, 0, 104, 178, 15, 188, 164, 98, 15, 6,
    117, 71, 114, 79, 45, 197, 158, 30, 187, 51, 12, 43, 131, 252, 74, 92, 251, 139, 159, 99, 163,
    149, 111, 89, 184, 95, 125, 73, 106, 62, 214, 210, 50, 190, 83, 138, 46, 65, 126, 152, 54, 137,
    189, 19, 247, 37, 116, 79, 178, 83, 51, 31, 129, 24, 172, 108, 58, 10, 171, 128, 40, 220, 250,
    168, 133, 164, 32, 47, 19, 231, 181, 124, 242, 192, 212, 153, 25, 10, 165, 52, 170, 177, 42,
    232, 2, 77, 246, 118, 192, 68, 96, 152, 77, 238, 130, 53, 128, 0, 5, 0, 104, 178, 15, 188, 164,
    208, 86, 125, 128, 153, 10, 107, 157, 50, 100, 148, 177, 10, 163, 41, 208, 32, 142, 176, 21,
    10, 15, 39, 208, 111, 47, 233, 154, 23, 161, 191, 192, 105, 242, 25, 68, 234, 211, 81, 89, 244,
    142, 184, 187, 236, 171, 34, 23, 227, 55, 207, 94, 48, 71, 236, 188, 146, 223, 77, 213, 74,
    234, 190, 192, 151, 172, 223, 158, 44, 230, 247, 248, 212, 245, 43, 131, 80, 57, 187, 105, 148,
    232, 15, 107, 239, 84, 131, 9, 222, 225, 137, 73, 202, 40, 48, 57, 122, 198, 245, 40, 128, 0,
    0, 0,
];

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

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let config = config.clone();

        let fut = async move {
            let server = BoundKeyExchangeServer::new(stream, config).unwrap();

            let result = server.await.unwrap();

            result.send_help().await.unwrap();

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
    pub fn new(io: IO, config: Arc<rustls::ServerConfig>) -> Result<Self, KeyExchangeError> {
        Ok(Self {
            inner: Some(BoundKeyExchangeServerData {
                io,
                server: KeyExchangeServer::new(config)?,
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
                        this.server = match dbg!(this.server.progress()) {
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
