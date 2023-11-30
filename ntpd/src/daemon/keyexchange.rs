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

fn build_client_config(
    extra_certificates: &[Certificate],
) -> Result<rustls::ClientConfig, KeyExchangeError> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs()? {
        let cert = rustls::Certificate(cert.0);
        roots.add(&cert).map_err(KeyExchangeError::Certificate)?;
    }

    for cert in extra_certificates {
        roots.add(cert).map_err(KeyExchangeError::Certificate)?;
    }

    Ok(rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(roots)
        .with_no_client_auth())
}

pub(crate) async fn key_exchange_client(
    server_name: String,
    port: u16,
    extra_certificates: &[Certificate],
) -> Result<KeyExchangeResult, KeyExchangeError> {
    let socket = tokio::net::TcpStream::connect((server_name.as_str(), port)).await?;
    let config = build_client_config(extra_certificates)?;

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

fn build_server_config(
    certificate_chain: Vec<Certificate>,
    private_key: PrivateKey,
) -> std::io::Result<Arc<rustls::ServerConfig>> {
    let mut config = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_client_cert_verifier(Arc::new(
            #[cfg(not(feature = "unstable_nts-pool"))]
            rustls::server::NoClientAuth,
            #[cfg(feature = "unstable_nts-pool")]
            ntp_proto::tls_utils::AllowAnyAnonymousOrCertificateBearingClient,
        ))
        .with_single_cert(certificate_chain, private_key)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidInput, err))?;

    config.alpn_protocols.clear();
    config.alpn_protocols.push(b"ntske/1".to_vec());

    Ok(Arc::new(config))
}

async fn key_exchange_server(
    keyset: tokio::sync::watch::Receiver<Arc<KeySet>>,
    address: impl ToSocketAddrs,
    certificate_chain: Vec<Certificate>,
    pool_certs: Vec<Certificate>,
    private_key: PrivateKey,
    timeout_ms: u64,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(&address).await?;

    let config = build_server_config(certificate_chain, private_key)?;
    let pool_certs = Arc::<[_]>::from(pool_certs);

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
        pool_certs: Arc<[rustls::Certificate]>,
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
        pool_certs: Arc<[rustls::Certificate]>,
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

    use ntp_proto::{KeySetProvider, NtsRecord};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
        #[cfg(feature = "unstable_nts-pool")]
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
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

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

    fn client_key_exchange_message_length() -> usize {
        let mut buffer = Vec::with_capacity(1024);
        for record in ntp_proto::NtsRecord::client_key_exchange_records() {
            record.write(&mut buffer).unwrap();
        }

        buffer.len()
    }

    async fn send_records_to_client(
        records: Vec<NtsRecord>,
    ) -> Result<KeyExchangeResult, KeyExchangeError> {
        let listener = tokio::net::TcpListener::bind(("localhost", 0))
            .await
            .unwrap();
        let port = listener.local_addr()?.port();

        tokio::spawn(async move {
            let cc = include_bytes!("../../test-keys/end.fullchain.pem");
            let certificate_chain = certificates_from_bufread(BufReader::new(Cursor::new(cc)));

            let pk = include_bytes!("../../test-keys/end.key");
            let private_key = private_key_from_bufread(pk.as_slice()).unwrap().unwrap();

            let config = build_server_config(certificate_chain, private_key).unwrap();

            let (stream, _) = listener.accept().await.unwrap();

            let acceptor = tokio_rustls::TlsAcceptor::from(config);
            let mut stream = acceptor.accept(stream).await.unwrap();

            // so that we could in theory handle multiple write calls
            let mut buf = vec![0; client_key_exchange_message_length()];
            stream.read_exact(&mut buf).await.unwrap();

            for record in records {
                let mut buffer = Vec::with_capacity(1024);
                record.write(&mut buffer).unwrap();

                stream.write_all(&buffer).await.unwrap();
            }
        });

        let ca = include_bytes!("../../test-keys/testca.pem");
        let extra_certificates = &certificates_from_bufread(BufReader::new(Cursor::new(ca)));

        key_exchange_client("localhost".to_string(), port, extra_certificates).await
    }

    async fn run_server(listener: tokio::net::TcpListener) -> Result<(), KeyExchangeError> {
        let cc = include_bytes!("../../test-keys/end.fullchain.pem");
        let certificate_chain = certificates_from_bufread(BufReader::new(Cursor::new(cc)));

        let pk = include_bytes!("../../test-keys/end.key");
        let private_key = private_key_from_bufread(pk.as_slice()).unwrap().unwrap();

        let config = build_server_config(certificate_chain, private_key).unwrap();
        let pool_certs = Arc::<[_]>::from(vec![]);

        let (stream, _) = listener.accept().await.unwrap();

        let provider = KeySetProvider::new(0);
        let keyset = provider.get();

        BoundKeyExchangeServer::run(stream, config, keyset, pool_certs).await
    }

    async fn client_tls_stream(
        server_name: &str,
        port: u16,
    ) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
        let stream = tokio::net::TcpStream::connect((server_name, port))
            .await
            .unwrap();

        let ca = include_bytes!("../../test-keys/testca.pem");
        let extra_certificates = &certificates_from_bufread(BufReader::new(Cursor::new(ca)));

        let config = build_client_config(extra_certificates).unwrap();

        let domain = rustls::ServerName::try_from(server_name)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid dnsname"))
            .unwrap();

        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        connector.connect(domain, stream).await.unwrap()
    }

    async fn send_records_to_server(records: Vec<NtsRecord>) -> Result<(), KeyExchangeError> {
        let listener = TcpListener::bind(&("localhost", 0)).await?;
        let port = listener.local_addr()?.port();

        tokio::spawn(async move {
            let mut stream = client_tls_stream("localhost", port).await;

            for record in records {
                let mut buffer = Vec::with_capacity(1024);
                record.write(&mut buffer).unwrap();

                stream.write_all(&buffer).await.unwrap();
            }

            let mut buf = [0; 1024];
            loop {
                match stream.read(&mut buf).await.unwrap() {
                    0 => break,
                    _ => continue,
                }
            }
        });

        run_server(listener).await
    }

    #[tokio::test]
    async fn receive_cookies() {
        let result = send_records_to_client(vec![
            NtsRecord::NextProtocol {
                protocol_ids: vec![0],
            },
            NtsRecord::AeadAlgorithm {
                critical: false,
                algorithm_ids: vec![15],
            },
            NtsRecord::NewCookie {
                cookie_data: vec![1, 2, 3],
            },
            NtsRecord::EndOfMessage,
        ])
        .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn records_after_end_are_ignored() {
        let result = send_records_to_client(vec![
            NtsRecord::NextProtocol {
                protocol_ids: vec![0],
            },
            NtsRecord::AeadAlgorithm {
                critical: false,
                algorithm_ids: vec![15],
            },
            NtsRecord::NewCookie {
                cookie_data: vec![1, 2, 3],
            },
            NtsRecord::EndOfMessage,
            NtsRecord::NewCookie {
                cookie_data: vec![1, 2, 3],
            },
        ])
        .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn no_cookies() {
        let result = send_records_to_client(vec![NtsRecord::EndOfMessage]).await;

        let error = result.unwrap_err();

        assert!(matches!(error, KeyExchangeError::NoCookies));
    }

    async fn client_error_record(errorcode: u16) -> KeyExchangeError {
        let result = send_records_to_client(vec![
            NtsRecord::Error { errorcode },
            NtsRecord::EndOfMessage,
        ])
        .await;

        result.unwrap_err()
    }

    #[tokio::test]
    async fn client_receives_error_record() {
        use KeyExchangeError as KEE;

        let error = client_error_record(NtsRecord::UNRECOGNIZED_CRITICAL_RECORD).await;
        assert!(matches!(error, KEE::UnrecognizedCriticalRecord));

        let error = client_error_record(NtsRecord::BAD_REQUEST).await;
        assert!(matches!(error, KEE::BadRequest));

        let error = client_error_record(NtsRecord::INTERNAL_SERVER_ERROR).await;
        assert!(matches!(error, KEE::InternalServerError));
    }

    #[tokio::test]
    async fn server_expected_client_records() {
        let records = NtsRecord::client_key_exchange_records().to_vec();
        let result = send_records_to_server(records).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn immediate_end_of_message() {
        let records = vec![NtsRecord::EndOfMessage];
        let result = send_records_to_server(records).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn double_end_of_message() {
        let records = vec![NtsRecord::EndOfMessage, NtsRecord::EndOfMessage];
        let result = send_records_to_server(records).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn client_no_valid_algorithm() {
        let records = vec![
            NtsRecord::NextProtocol {
                protocol_ids: vec![0],
            },
            NtsRecord::AeadAlgorithm {
                critical: false,
                algorithm_ids: vec![],
            },
            NtsRecord::EndOfMessage,
        ];
        let result = send_records_to_server(records).await;

        assert!(matches!(result, Err(KeyExchangeError::NoValidAlgorithm)));
    }

    #[tokio::test]
    async fn client_no_valid_protocol() {
        let records = vec![
            NtsRecord::NextProtocol {
                protocol_ids: vec![],
            },
            NtsRecord::AeadAlgorithm {
                critical: false,
                algorithm_ids: vec![15],
            },
            NtsRecord::EndOfMessage,
        ];
        let result = send_records_to_server(records).await;

        assert!(matches!(result, Err(KeyExchangeError::NoValidProtocol)));
    }

    #[tokio::test]
    async fn unrecognized_critical_record() {
        let records = vec![
            NtsRecord::Unknown {
                record_type: 1234,
                critical: true,
                data: vec![],
            },
            NtsRecord::EndOfMessage,
        ];
        let result = send_records_to_server(records).await;

        assert!(matches!(
            result,
            Err(KeyExchangeError::UnrecognizedCriticalRecord)
        ));
    }

    #[tokio::test]
    async fn client_sends_no_records_clean_shutdown() {
        let listener = TcpListener::bind(&("localhost", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            // give the server some time to make the port available
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;

            // create the stream, then shut it down without sending anything
            let mut stream = client_tls_stream("localhost", port).await;
            stream.shutdown().await.unwrap();
        });

        let result = run_server(listener).await;
        assert!(matches!(result, Err(KeyExchangeError::IncompleteResponse)));
    }

    #[tokio::test]
    async fn client_sends_no_records_dirty_shutdown() {
        let listener = TcpListener::bind(&("localhost", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            // create the stream, then shut it down without sending anything
            let stream = client_tls_stream("localhost", port).await;
            stream.into_inner().0.shutdown().await.unwrap();
        });

        let result = run_server(listener).await;
        assert!(matches!(result, Err(KeyExchangeError::IncompleteResponse)));
    }

    async fn server_error_record(errorcode: u16) -> KeyExchangeError {
        let result = send_records_to_server(vec![
            NtsRecord::Error { errorcode },
            NtsRecord::EndOfMessage,
        ])
        .await;

        result.unwrap_err()
    }

    #[tokio::test]
    async fn server_receives_error_record() {
        use KeyExchangeError as KEE;

        let error = server_error_record(NtsRecord::UNRECOGNIZED_CRITICAL_RECORD).await;
        assert!(matches!(error, KEE::UnrecognizedCriticalRecord));

        let error = server_error_record(NtsRecord::BAD_REQUEST).await;
        assert!(matches!(error, KEE::BadRequest));

        let error = server_error_record(NtsRecord::INTERNAL_SERVER_ERROR).await;
        assert!(matches!(error, KEE::InternalServerError));
    }
}
