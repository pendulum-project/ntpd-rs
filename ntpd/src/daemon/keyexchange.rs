use std::{
    future::Future,
    io::{BufRead, BufReader, IoSlice, Read, Write},
    ops::ControlFlow,
    path::Path,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use ntp_proto::{
    KeyExchangeClient, KeyExchangeError, KeyExchangeResult, KeyExchangeServer, KeySet,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpListener,
    task::JoinHandle,
};

use super::config::NtsKeConfig;
use super::exitcode;

async fn build_client_config(
    extra_certificates: &[CertificateDer<'_>],
) -> Result<rustls::ClientConfig, KeyExchangeError> {
    let mut roots = tokio::task::spawn_blocking(move || {
        let mut roots = rustls::RootCertStore::empty();
        for cert in rustls_native_certs::load_native_certs()? {
            roots.add(cert).map_err(KeyExchangeError::Certificate)?;
        }
        Ok::<_, KeyExchangeError>(roots)
    })
    .await
    .expect("Unexpected error while loading root certificates")?;

    for cert in extra_certificates {
        roots
            .add(cert.clone())
            .map_err(KeyExchangeError::Certificate)?;
    }

    Ok(rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth())
}

pub(crate) async fn key_exchange_client(
    server_name: String,
    port: u16,
    extra_certificates: &[CertificateDer<'_>],
) -> Result<KeyExchangeResult, KeyExchangeError> {
    let socket = tokio::net::TcpStream::connect((server_name.as_str(), port)).await?;
    let config = build_client_config(extra_certificates).await?;

    BoundKeyExchangeClient::new(socket, server_name, config, Vec::new())?.await
}

#[cfg(feature = "unstable_nts-pool")]
pub(crate) async fn key_exchange_client_with_denied_servers(
    server_name: String,
    port: u16,
    extra_certificates: &[CertificateDer<'_>],
    denied_servers: impl IntoIterator<Item = String>,
) -> Result<KeyExchangeResult, KeyExchangeError> {
    let socket = tokio::net::TcpStream::connect((server_name.as_str(), port)).await?;
    let config = build_client_config(extra_certificates).await?;

    BoundKeyExchangeClient::new(socket, server_name, config, denied_servers)?.await
}

pub fn spawn(
    nts_ke_config: NtsKeConfig,
    keyset: tokio::sync::watch::Receiver<Arc<KeySet>>,
) -> JoinHandle<std::io::Result<()>> {
    tokio::spawn(async move {
        let result = run_nts_ke(nts_ke_config, keyset).await;

        match result {
            Ok(v) => Ok(v),
            Err(e) => {
                tracing::error!("Abnormal termination of NTS KE server: {e}");
                std::process::exit(exitcode::SOFTWARE)
            }
        }
    })
}

fn io_error(msg: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, msg)
}

async fn run_nts_ke(
    nts_ke_config: NtsKeConfig,
    keyset: tokio::sync::watch::Receiver<Arc<KeySet>>,
) -> std::io::Result<()> {
    let certificate_chain_file = std::fs::File::open(&nts_ke_config.certificate_chain_path)
        .map_err(|e| {
            io_error(&format!(
                "error reading certificate_chain_path at `{:?}`: {:?}",
                nts_ke_config.certificate_chain_path, e
            ))
        })?;

    let private_key_file = std::fs::File::open(&nts_ke_config.private_key_path).map_err(|e| {
        io_error(&format!(
            "error reading key_der_path at `{:?}`: {:?}",
            nts_ke_config.private_key_path, e
        ))
    })?;

    let cert_chain: Vec<rustls::pki_types::CertificateDer> =
        rustls_pemfile::certs(&mut std::io::BufReader::new(certificate_chain_file))
            .collect::<std::io::Result<Vec<rustls::pki_types::CertificateDer>>>()?;

    #[cfg_attr(not(feature = "unstable_nts-pool"), allow(unused_mut))]
    let mut pool_certs: Vec<rustls::pki_types::CertificateDer> = Vec::new();
    #[cfg(feature = "unstable_nts-pool")]
    for client_cert in &nts_ke_config.authorized_pool_server_certificates {
        let pool_certificate_file = std::fs::File::open(client_cert).map_err(|e| {
            io_error(&format!(
                "error reading authorized-pool-server-certificate at `{:?}`: {:?}",
                client_cert, e
            ))
        })?;
        let mut certs: Vec<_> =
            rustls_pemfile::certs(&mut std::io::BufReader::new(pool_certificate_file))
                .collect::<std::io::Result<Vec<_>>>()?;
        // forbid certificate chains at this point
        if certs.len() == 1 {
            pool_certs.push(certs.pop().unwrap())
        } else {
            return Err(io_error(&format!(
                "pool certificate file at `{:?}` should contain exactly one certificate",
                client_cert
            )));
        }
    }

    let private_key = rustls_pemfile::private_key(&mut std::io::BufReader::new(private_key_file))?
        .ok_or(io_error("could not parse private key"))?;

    key_exchange_server(keyset, nts_ke_config, cert_chain, pool_certs, private_key).await
}

fn build_server_config(
    certificate_chain: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
) -> std::io::Result<Arc<rustls::ServerConfig>> {
    let mut config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(Arc::new(
            #[cfg(not(feature = "unstable_nts-pool"))]
            rustls::server::NoClientAuth,
            #[cfg(feature = "unstable_nts-pool")]
            ntp_proto::tls_utils::AllowAnyAnonymousOrCertificateBearingClient::new(
                rustls::crypto::ring::default_provider(),
            ),
        ))
        .with_single_cert(certificate_chain, private_key)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidInput, err))?;

    config.alpn_protocols.clear();
    config.alpn_protocols.push(b"ntske/1".to_vec());

    Ok(Arc::new(config))
}

async fn key_exchange_server(
    keyset: tokio::sync::watch::Receiver<Arc<KeySet>>,
    ke_config: NtsKeConfig,
    certificate_chain: Vec<CertificateDer<'static>>,
    pool_certs: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(&ke_config.listen).await?;

    let config = build_server_config(certificate_chain, private_key)?;
    let pool_certs = Arc::<[_]>::from(pool_certs);

    loop {
        let (stream, source_addr) = listener.accept().await?;
        let config = config.clone();
        let keyset = keyset.borrow().clone();
        let pool_certs = pool_certs.clone();
        let ntp_port = ke_config.ntp_port;
        let ntp_server = ke_config.ntp_server.clone();
        let timeout_ms = ke_config.key_exchange_timeout_ms;

        let fut = async move {
            BoundKeyExchangeServer::run(
                stream,
                config,
                keyset,
                ntp_port,
                ntp_server.clone(),
                pool_certs,
            )
            .await
            .map_err(|ke_error| std::io::Error::new(std::io::ErrorKind::Other, ke_error))
        };

        tokio::spawn(async move {
            let timeout = std::time::Duration::from_millis(timeout_ms);
            match tokio::time::timeout(timeout, fut).await {
                Err(_) => tracing::debug!(?source_addr, "NTS KE timed out"),
                Ok(Err(err)) => tracing::debug!(?err, ?source_addr, "NTS KE failed"),
                Ok(Ok(())) => tracing::debug!(?source_addr, "NTS KE completed"),
            }
        });
    }
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
        denied_servers: impl IntoIterator<Item = String>,
    ) -> Result<Self, KeyExchangeError> {
        Ok(Self {
            inner: Some(BoundKeyExchangeClientData {
                io,
                client: KeyExchangeClient::new(server_name, config, denied_servers)?,
                need_flush: false,
            }),
        })
    }
}

struct BoundKeyExchangeClientData<IO> {
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
    type Output = Result<KeyExchangeResult, KeyExchangeError>;

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
                            ControlFlow::Continue(client) => client,
                            ControlFlow::Break(result) => return Poll::Ready(result),
                        }
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
                    Poll::Pending => {
                        read_blocks = true;
                        break;
                    }
                }
            }

            let no_write = write_blocks || !this.client.wants_write();
            let no_read = read_blocks || !this.client.wants_read();
            if no_write && no_read {
                outer.inner = Some(this);
                return Poll::Pending;
            }
        }
    }
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
        ntp_port: Option<u16>,
        ntp_server: Option<String>,
        pool_certs: Arc<[rustls::pki_types::CertificateDer<'static>]>,
    ) -> Result<Self, KeyExchangeError> {
        let data = BoundKeyExchangeServerData {
            io,
            server: KeyExchangeServer::new(config, keyset, ntp_port, ntp_server, pool_certs)?,
            need_flush: false,
        };

        Ok(Self { inner: Some(data) })
    }

    pub async fn run(
        io: IO,
        config: Arc<rustls::ServerConfig>,
        keyset: Arc<KeySet>,
        ntp_port: Option<u16>,
        ntp_server: Option<String>,
        pool_certs: Arc<[rustls::pki_types::CertificateDer<'static>]>,
    ) -> Result<(), KeyExchangeError> {
        let this = Self::new(io, config, keyset, ntp_port, ntp_server, pool_certs)?;

        this.await
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
                            ControlFlow::Continue(client) => client,
                            ControlFlow::Break(Err(e)) => return Poll::Ready(Err(e)),
                            ControlFlow::Break(Ok(_)) => return Poll::Ready(Ok(())),
                        }
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
                    Poll::Pending => {
                        read_blocks = true;
                        break;
                    }
                }
            }

            let no_write = write_blocks || !this.server.wants_write();
            let no_read = read_blocks || !this.server.wants_read();
            if no_write && no_read {
                outer.inner = Some(this);
                return Poll::Pending;
            }
        }
    }
}

/// adapter between `AsyncWrite` and `std::io::Write`
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

/// adapter between `AsyncRead` and `std::io::Read`
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

pub(crate) fn certificates_from_file(path: &Path) -> std::io::Result<Vec<CertificateDer<'static>>> {
    let file = std::fs::File::open(path)?;
    let reader = BufReader::new(file);

    certificates_from_bufread(reader)
}

fn certificates_from_bufread(
    mut reader: impl BufRead,
) -> std::io::Result<Vec<CertificateDer<'static>>> {
    rustls_pemfile::certs(&mut reader).collect()
}

