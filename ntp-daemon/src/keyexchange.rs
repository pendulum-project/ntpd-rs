use std::{
    future::Future,
    io::{BufRead, BufReader, IoSlice, Read, Write},
    path::Path,
    pin::Pin,
    task::{Context, Poll},
};

use ntp_proto::{KeyExchangeClient, KeyExchangeClientResult, KeyExchangeError};
use rustls::Certificate;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub(crate) async fn key_exchange(
    server_name: String,
    port: u16,
    extra_certificates: &[Certificate],
) -> Result<KeyExchangeClientResult, KeyExchangeError> {
    let socket = tokio::net::TcpStream::connect((server_name.as_str(), port))
        .await
        .unwrap();

    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs()? {
        roots.add(&rustls::Certificate(cert.0)).unwrap();
    }

    for cert in extra_certificates {
        roots.add(cert).unwrap();
    }

    let config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(roots)
        .with_no_client_auth();

    BoundKeyExchangeClient::new(socket, server_name, config)?.await
}

pub(crate) struct BoundKeyExchangeClient<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    inner: Option<BoundKeyExchangeClientData<IO>>,
}

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
            inner: Some(BoundKeyExchangeClientData {
                io,
                client: KeyExchangeClient::new(server_name, config)?,
                need_flush: false,
            }),
        })
    }
}

struct BoundKeyExchangeClientData<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    io: IO,
    client: KeyExchangeClient,
    need_flush: bool,
}

// IO approach taken from tokio
impl<IO> BoundKeyExchangeClientData<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    fn do_write(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<usize>> {
        let mut writer = WriterAdapter {
            io: &mut self.io,
            cx,
        };

        match self.client.write_socket(&mut writer) {
            Err(ref err) if err.kind() == std::io::ErrorKind::WouldBlock => Poll::Pending,
            result => Poll::Ready(result),
        }
    }

    fn do_read(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<usize>> {
        let mut reader = ReaderAdapter {
            io: &mut self.io,
            cx,
        };
        match self.client.read_socket(&mut reader) {
            Err(ref err) if err.kind() == std::io::ErrorKind::WouldBlock => Poll::Pending,
            result => Poll::Ready(result),
        }
    }
}

impl<IO> Future for BoundKeyExchangeClient<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    type Output = Result<KeyExchangeClientResult, KeyExchangeError>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let outer = self.get_mut();
        let mut this = outer.inner.take().unwrap();

        let mut write_blocks = false;
        let mut read_blocks = false;

        loop {
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

pub(crate) fn certificates_from_file(path: &Path) -> std::io::Result<Vec<Certificate>> {
    let file = std::fs::File::open(path)?;
    let reader = BufReader::new(file);

    certificates_from_bufread(reader)
}

fn certificates_from_bufread(mut reader: impl BufRead) -> std::io::Result<Vec<Certificate>> {
    use rustls_pemfile::{read_one, Item};

    let mut output = Vec::new();

    for item in std::iter::from_fn(|| read_one(&mut reader).transpose()) {
        if let Item::X509Certificate(cert) = item? {
            output.push(Certificate(cert));
        }
    }

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::certificates_from_bufread;

    #[test]
    fn nos_nl_pem() {
        let input = include_bytes!("../testdata/certificates/nos-nl.pem");
        let certificates = certificates_from_bufread(input.as_slice()).unwrap();

        assert_eq!(certificates.len(), 1);
    }

    #[test]
    fn nos_nl_chain_pem() {
        let input = include_bytes!("../testdata/certificates/nos-nl-chain.pem");
        let certificates = certificates_from_bufread(input.as_slice()).unwrap();

        assert_eq!(certificates.len(), 3);
    }
}
