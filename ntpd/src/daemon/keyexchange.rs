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
use rustls::{Certificate, PrivateKey};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpListener, ToSocketAddrs},
    task::JoinHandle,
};

use super::config::NtsKeConfig;
use super::exitcode;

pub(crate) async fn key_exchange_client(
    server_name: String,
    port: u16,
    extra_certificates: &[Certificate],
) -> Result<KeyExchangeResult, KeyExchangeError> {
    let socket = tokio::net::TcpStream::connect((server_name.as_str(), port)).await?;

    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs()? {
        let cert = rustls::Certificate(cert.0);
        roots.add(&cert).map_err(KeyExchangeError::Certificate)?;
    }

    for cert in extra_certificates {
        roots.add(cert).map_err(KeyExchangeError::Certificate)?;
    }

    let config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(roots)
        .with_no_client_auth();

    BoundKeyExchangeClient::new(socket, server_name, config)?.await
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

    let cert_chain: Vec<rustls::Certificate> =
        rustls_pemfile::certs(&mut std::io::BufReader::new(certificate_chain_file))?
            .into_iter()
            .map(rustls::Certificate)
            .collect();

    #[cfg_attr(not(feature = "unstable_nts-pool"), allow(unused_mut))]
    let mut pool_certs: Vec<rustls::Certificate> = Vec::new();
    #[cfg(feature = "unstable_nts-pool")]
    for client_cert in nts_ke_config.authorized_pool_server_certificates {
        let pool_certificate_file = std::fs::File::open(&client_cert).map_err(|e| {
            io_error(&format!(
                "error reading authorized-pool-server-certificate at `{:?}`: {:?}",
                client_cert, e
            ))
        })?;
        let mut certs = rustls_pemfile::certs(&mut std::io::BufReader::new(pool_certificate_file))?;
        // forbid certificate chains at this point
        if certs.len() == 1 {
            pool_certs.push(rustls::Certificate(certs.pop().unwrap()))
        } else {
            return Err(io_error(&format!(
                "pool certificate file at `{:?}` should contain exactly one certificate",
                client_cert
            )));
        }
    }

    let private_key = private_key_from_bufread(&mut std::io::BufReader::new(private_key_file))?
        .ok_or(io_error("could not parse private key"))?;

    key_exchange_server(
        keyset,
        nts_ke_config.listen,
        cert_chain,
        pool_certs,
        private_key,
        nts_ke_config.key_exchange_timeout_ms,
    )
    .await
}

async fn key_exchange_server(
    keyset: tokio::sync::watch::Receiver<Arc<KeySet>>,
    address: impl ToSocketAddrs,
    certificate_chain: Vec<Certificate>,
    pool_certs: Vec<Certificate>,
    private_key: PrivateKey,
    timeout_ms: u64,
) -> std::io::Result<()> {
    use std::io;

    let listener = TcpListener::bind(&address).await?;

    let mut config = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certificate_chain, private_key)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;

    config.alpn_protocols.clear();
    config.alpn_protocols.push(b"ntske/1".to_vec());

    let config = Arc::new(config);
    let pool_certs = Arc::new(pool_certs);

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let config = config.clone();
        let keyset = keyset.borrow().clone();
        let pool_certs = pool_certs.clone();

        let fut = async move {
            BoundKeyExchangeServer::run(stream, config, keyset, pool_certs)
                .await
                .map_err(|ke_error| std::io::Error::new(std::io::ErrorKind::Other, ke_error))
        };

        tokio::spawn(async move {
            let timeout = std::time::Duration::from_millis(timeout_ms);
            match tokio::time::timeout(timeout, fut).await {
                Err(_) => tracing::debug!(?peer_addr, "NTS KE timed out"),
                Ok(Err(err)) => tracing::debug!(?err, ?peer_addr, "NTS KE failed"),
                Ok(Ok(())) => tracing::debug!(?peer_addr, "NTS KE completed"),
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
        pool_certs: Arc<Vec<rustls::Certificate>>,
    ) -> Result<Self, KeyExchangeError> {
        let data = BoundKeyExchangeServerData {
            io,
            server: KeyExchangeServer::new(config, keyset, pool_certs)?,
            need_flush: false,
        };

        Ok(Self { inner: Some(data) })
    }

    pub async fn run(
        io: IO,
        config: Arc<rustls::ServerConfig>,
        keyset: Arc<KeySet>,
        pool_certs: Arc<Vec<rustls::Certificate>>,
    ) -> Result<(), KeyExchangeError> {
        let this = Self::new(io, config, keyset, pool_certs)?;

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

pub(crate) fn certificates_from_file(path: &Path) -> std::io::Result<Vec<Certificate>> {
    let file = std::fs::File::open(path)?;
    let reader = BufReader::new(file);

    Ok(certificates_from_bufread(reader))
}

fn certificates_from_bufread(mut reader: impl BufRead) -> Vec<Certificate> {
    rustls_pemfile::certs(&mut reader)
        .unwrap()
        .iter()
        .map(|v| rustls::Certificate(v.clone()))
        .collect()
}

fn private_key_from_bufread(
    mut reader: impl BufRead,
) -> std::io::Result<Option<rustls::PrivateKey>> {
    use rustls_pemfile::Item;

    loop {
        match rustls_pemfile::read_one(&mut reader)? {
            Some(Item::RSAKey(key)) => return Ok(Some(rustls::PrivateKey(key))),
            Some(Item::PKCS8Key(key)) => return Ok(Some(rustls::PrivateKey(key))),
            Some(Item::ECKey(key)) => return Ok(Some(rustls::PrivateKey(key))),
            None => break,
            _ => {}
        }
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use std::{io::Cursor, path::PathBuf};

    use ntp_proto::KeySetProvider;

    use super::*;

    #[test]
    fn nos_nl_pem() {
        let input = include_bytes!("../../testdata/certificates/nos-nl.pem");
        let certificates = certificates_from_bufread(input.as_slice());

        assert_eq!(certificates.len(), 1);
    }

    #[test]
    fn nos_nl_chain_pem() {
        let input = include_bytes!("../../testdata/certificates/nos-nl-chain.pem");
        let certificates = certificates_from_bufread(input.as_slice());

        assert_eq!(certificates.len(), 3);
    }

    #[test]
    fn parse_private_keys() {
        let input = include_bytes!("../../test-keys/end.key");
        let _ = private_key_from_bufread(input.as_slice()).unwrap().unwrap();

        let input = include_bytes!("../../test-keys/testca.key");
        let _ = private_key_from_bufread(input.as_slice()).unwrap().unwrap();

        // openssl does no longer seem to want to generate this format
        // so we use https://github.com/rustls/pemfile/blob/main/tests/data/rsa1024.pkcs1.pem
        let input = include_bytes!("../../test-keys/rsa_key.pem");
        let _ = private_key_from_bufread(input.as_slice()).unwrap().unwrap();

        // openssl ecparam -name prime256v1 -genkey -noout -out ec_key.pem
        let input = include_bytes!("../../test-keys/ec_key.pem");
        let _ = private_key_from_bufread(input.as_slice()).unwrap().unwrap();

        // openssl genpkey -algorithm EC -out pkcs8_key.pem -pkeyopt ec_paramgen_curve:prime256v1
        let input = include_bytes!("../../test-keys/pkcs8_key.pem");
        let _ = private_key_from_bufread(input.as_slice()).unwrap().unwrap();
    }

    #[tokio::test]
    async fn key_exchange_roundtrip() {
        let provider = KeySetProvider::new(1);
        let keyset = provider.get();
        let pool_certs = ["testdata/certificates/nos-nl.pem"];

        let (_sender, keyset) = tokio::sync::watch::channel(keyset);
        let nts_ke_config = NtsKeConfig {
            certificate_chain_path: PathBuf::from("test-keys/end.fullchain.pem"),
            private_key_path: PathBuf::from("test-keys/end.key"),
            #[cfg(feature = "unstable_nts-pool")]
            authorized_pool_server_certificates: pool_certs.iter().map(PathBuf::from).collect(),
            key_exchange_timeout_ms: 1000,
            listen: "0.0.0.0:5431".parse().unwrap(),
        };

        let _join_handle = spawn(nts_ke_config, keyset);

        // give the server some time to make the port available
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let ca = include_bytes!("../../test-keys/testca.pem");
        let result = key_exchange_client(
            "localhost".to_string(),
            5431,
            &certificates_from_bufread(BufReader::new(Cursor::new(ca))),
        )
        .await
        .unwrap();

        assert_eq!(result.remote, "localhost");
        assert_eq!(result.port, 123);
    }

    #[cfg(feature = "unstable_nts-pool")]
    #[tokio::test]
    async fn key_exchange_refusal_due_to_invalid_config() {
        let cert_path = "testdata/certificates/nos-nl-chain.pem";
        let certs = [cert_path];

        let provider = KeySetProvider::new(1);
        let keyset = provider.get();

        let (_sender, keyset) = tokio::sync::watch::channel(keyset);
        let nts_ke_config = NtsKeConfig {
            certificate_chain_path: PathBuf::from("../test-keys/end.fullchain.pem"),
            private_key_path: PathBuf::from("../test-keys/end.key"),
            authorized_pool_server_certificates: certs.iter().map(PathBuf::from).collect(),
            key_exchange_timeout_ms: 1000,
            listen: "0.0.0.0:5431".parse().unwrap(),
        };

        let Err(io_error) = run_nts_ke(nts_ke_config, keyset).await else {
            panic!("nts server started normally, this should not happen");
        };

        let expected_error_msg = format!(
            "pool certificate file at `\"{cert_path}\"` should contain exactly one certificate"
        );
        assert_eq!(io_error.to_string(), expected_error_msg);
    }

    #[tokio::test]
    async fn client_connection_refused() {
        let result = key_exchange_client("localhost".to_string(), 5434, &[]).await;

        let error = result.unwrap_err();

        match error {
            KeyExchangeError::Io(error) => {
                assert_eq!(error.kind(), std::io::ErrorKind::ConnectionRefused);
            }
            _ => panic!(),
        }
    }
}
