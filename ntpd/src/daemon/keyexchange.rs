use std::{
    io::{BufRead, BufReader},
    path::Path,
    sync::Arc,
};

use libc::{ECONNABORTED, EMFILE, ENFILE, ENOBUFS, ENOMEM};
use ntp_proto::{KeyExchangeServer, KeySet};
use ntp_proto::{NtsServerConfig, tls_utils::Certificate};
use tokio::{net::TcpListener, task::JoinHandle};
use tracing::{Instrument, Span, debug, error, instrument};

use super::config::NtsKeConfig;
use super::exitcode;

#[instrument(level = tracing::Level::ERROR, name = "Nts Server", skip_all, fields(address = debug(nts_ke_config.listen)))]
pub fn spawn(
    nts_ke_config: NtsKeConfig,
    keyset: tokio::sync::watch::Receiver<Arc<KeySet>>,
) -> JoinHandle<std::io::Result<()>> {
    tokio::spawn(
        (async move {
            let result = run_nts_ke(nts_ke_config, keyset).await;

            match result {
                Ok(v) => Ok(v),
                Err(e) => {
                    tracing::error!("Abnormal termination of NTS KE server: {e}");
                    std::process::exit(exitcode::SOFTWARE)
                }
            }
        })
        .instrument(Span::current()),
    )
}

fn io_error(msg: &str) -> std::io::Error {
    std::io::Error::other(msg)
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

    let certificate_chain: Vec<Certificate> =
        ntp_proto::tls_utils::pemfile::certs(&mut std::io::BufReader::new(certificate_chain_file))
            .collect::<std::io::Result<Vec<Certificate>>>()?;

    let private_key =
        ntp_proto::tls_utils::pemfile::private_key(&mut std::io::BufReader::new(private_key_file))?;

    let key_exchange_server = KeyExchangeServer::new(NtsServerConfig {
        certificate_chain,
        private_key,
        accepted_versions: nts_ke_config.accept_ntp_versions.clone(),
        server: nts_ke_config.ntp_server.clone(),
        port: nts_ke_config.ntp_port,
        pool_authentication_tokens: nts_ke_config.accepted_pool_authentication_tokens.clone(),
    })
    .map_err(std::io::Error::other)?;

    run_key_exchange_server(keyset, key_exchange_server, nts_ke_config).await
}

async fn run_key_exchange_server(
    keyset: tokio::sync::watch::Receiver<Arc<KeySet>>,
    key_exchange_server: KeyExchangeServer,
    ke_config: NtsKeConfig,
) -> std::io::Result<()> {
    let timeout = std::time::Duration::from_millis(ke_config.key_exchange_timeout_ms);
    let key_exchange_server = Arc::new(key_exchange_server);

    loop {
        let listener = match TcpListener::bind(&ke_config.listen).await {
            Ok(listener) => listener,
            Err(e) => {
                error!("Could not open network port for KE server: {}", e);
                tokio::time::sleep(timeout).await;
                continue;
            }
        };

        // Ensure we do not make too many connections. We can reinitialize here because any error path recreating the socket
        // waits at least ke_config.key_exchange_timeout_ms milliseconds, ensuring all pre-existing connections are or will very
        // soon be gone.
        let connectionpermits = Arc::new(tokio::sync::Semaphore::new(
            ke_config.concurrent_connections,
        ));

        loop {
            let permit = match connectionpermits.clone().acquire_owned().await {
                Ok(permit) => permit,
                Err(e) => {
                    error!("Could not get ticket for new connection: {}", e);
                    tokio::time::sleep(timeout).await;
                    break;
                }
            };
            let (stream, source_addr) = match listener.accept().await {
                Ok(a) => a,
                Err(e) if matches!(e.raw_os_error(), Some(ECONNABORTED)) => {
                    debug!("Potential client-triggered accept error in NTS-KE: {}", e);
                    continue;
                }
                Err(e)
                    if matches!(
                        e.raw_os_error(),
                        Some(ENFILE) | Some(EMFILE) | Some(ENOMEM) | Some(ENOBUFS)
                    ) =>
                {
                    error!(
                        "Out of resources in NTS-KE, consider raising limits or lowering max parallel connections: {}",
                        e
                    );
                    tokio::time::sleep(timeout).await;
                    continue;
                }
                Err(e) => {
                    error!("Could not accept NTS-KE connection: {}", e);
                    tokio::time::sleep(timeout).await;
                    break;
                }
            };
            let keyset = keyset.borrow().clone();
            let key_exchange_server = key_exchange_server.clone();

            let fut = async move { key_exchange_server.handle_connection(stream, &keyset).await };

            tokio::spawn(async move {
                match tokio::time::timeout(timeout, fut).await {
                    Err(_) => tracing::debug!(?source_addr, "NTS KE timed out"),
                    Ok(Err(err)) => tracing::debug!(?err, ?source_addr, "NTS KE failed"),
                    Ok(Ok(())) => tracing::debug!(?source_addr, "NTS KE completed"),
                }
                drop(permit);
            });
        }
    }
}

pub(crate) fn certificates_from_file(path: &Path) -> std::io::Result<Vec<Certificate>> {
    let file = std::fs::File::open(path)?;
    let reader = BufReader::new(file);

    certificates_from_bufread(reader)
}

fn certificates_from_bufread(mut reader: impl BufRead) -> std::io::Result<Vec<Certificate>> {
    ntp_proto::tls_utils::pemfile::certs(&mut reader).collect()
}

#[cfg(test)]
mod tests {
    use std::{io::Cursor, net::SocketAddr, path::PathBuf};

    use ntp_proto::KeySetProvider;
    use ntp_proto::{KeyExchangeClient, NtpVersion, NtsClientConfig};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    use crate::test::alloc_port;

    use super::*;

    #[test]
    fn nos_nl_pem() {
        let input = include_bytes!("../../testdata/certificates/nos-nl.pem");
        let certificates = certificates_from_bufread(input.as_slice()).unwrap();

        assert_eq!(certificates.len(), 1);
    }

    #[test]
    fn nos_nl_chain_pem() {
        let input = include_bytes!("../../testdata/certificates/nos-nl-chain.pem");
        let certificates = certificates_from_bufread(input.as_slice()).unwrap();

        assert_eq!(certificates.len(), 3);
    }

    #[test]
    fn parse_private_keys() {
        let input = include_bytes!("../../test-keys/end.key");
        let _ = ntp_proto::tls_utils::pemfile::private_key(&mut input.as_slice()).unwrap();

        let input = include_bytes!("../../test-keys/testca.key");
        let _ = ntp_proto::tls_utils::pemfile::private_key(&mut input.as_slice()).unwrap();

        // openssl does no longer seem to want to generate this format
        // so we use https://github.com/rustls/pemfile/blob/main/tests/data/rsa1024.pkcs1.pem
        let input = include_bytes!("../../test-keys/rsa_key.pem");
        let _ = ntp_proto::tls_utils::pemfile::private_key(&mut input.as_slice()).unwrap();

        // openssl ecparam -name prime256v1 -genkey -noout -out ec_key.pem
        let input = include_bytes!("../../test-keys/ec_key.pem");
        let _ = ntp_proto::tls_utils::pemfile::private_key(&mut input.as_slice()).unwrap();

        // openssl genpkey -algorithm EC -out pkcs8_key.pem -pkeyopt ec_paramgen_curve:prime256v1
        let input = include_bytes!("../../test-keys/pkcs8_key.pem");
        let _ = ntp_proto::tls_utils::pemfile::private_key(&mut input.as_slice()).unwrap();
    }

    #[tokio::test]
    async fn key_exchange_connection_limiter() {
        let port = alloc_port();

        let provider = KeySetProvider::new(1);
        let keyset = provider.get();

        let (_sender, keyset) = tokio::sync::watch::channel(keyset);
        let nts_ke_config = NtsKeConfig {
            certificate_chain_path: PathBuf::from("test-keys/end.fullchain.pem"),
            private_key_path: PathBuf::from("test-keys/end.key"),
            accepted_pool_authentication_tokens: vec![],
            key_exchange_timeout_ms: 10000,
            concurrent_connections: 1,
            listen: SocketAddr::new("0.0.0.0".parse().unwrap(), port),
            ntp_port: None,
            ntp_server: None,
            accept_ntp_versions: vec![NtpVersion::V4],
        };

        let _join_handle = spawn(nts_ke_config, keyset);

        // give the server some time to make the port available
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        let mut blocker =
            tokio::net::TcpStream::connect(SocketAddr::new("127.0.0.1".parse().unwrap(), port))
                .await
                .unwrap();

        // Ensure connection, just send a random client hello
        blocker.write_all(b"\x16\x03\x01\x00\xf5\x01\x00\x00\xf1\x03\x03\xfc\x86\xea\x41\x80\x21\xec\x3e\x14\x5f\xf9\x4c\xa0\xcd\x8a\x1a\x66\x65\x41\xe5\x95\xd6\x8e\xb4\x65\x3b\x62\x49\x8d\xe1\xe0\xd8\x20\xe9\xa8\x94\xdb\xbf\x99\xfd\xc9\x3d\xd7\xcf\x7a\xc6\x7c\x03\xee\xb3\xcf\x17\x0b\x57\x69\xb6\x51\x48\xb1\xc6\x3e\xcb\x2d\x54\x2c\x00\x14\x13\x02\x13\x01\x13\x03\xc0\x2c\xc0\x2b\xcc\xa9\xc0\x30\xc0\x2f\xcc\xa8\x00\xff\x01\x00\x00\x94\x00\x33\x00\x26\x00\x24\x00\x1d\x00\x20\x4e\xcb\x36\xd3\xff\xc7\x64\x3e\xd8\x25\xf2\x1a\x20\x42\xc7\xa0\x29\x89\x8d\x00\x82\x0c\x9f\xff\xdf\xa6\xa0\xdc\xcf\xa7\xb8\x2b\x00\x0d\x00\x14\x00\x12\x05\x03\x04\x03\x08\x07\x08\x06\x08\x05\x08\x04\x06\x01\x05\x01\x04\x01\x00\x2b\x00\x05\x04\x03\x04\x03\x03\x00\x23\x00\x00\x00\x05\x00\x05\x01\x00\x00\x00\x00\x00\x17\x00\x00\x00\x10\x00\x0a\x00\x08\x07\x6e\x74\x73\x6b\x65\x2f\x31\x00\x00\x00\x0e\x00\x0c\x00\x00\x09\x6c\x6f\x63\x61\x6c\x68\x6f\x73\x74\x00\x2d\x00\x02\x01\x01\x00\x0a\x00\x08\x00\x06\x00\x1d\x00\x17\x00\x18\x00\x0b\x00\x02\x01\x00").await.unwrap();
        blocker.flush().await.unwrap();

        // give the server time to accept the connection
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        let ca = include_bytes!("../../test-keys/testca.pem");

        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(750), async move {
                let kex = KeyExchangeClient::new(NtsClientConfig {
                    certificates: certificates_from_bufread(BufReader::new(Cursor::new(ca)))
                        .unwrap()
                        .into(),
                    protocol_version: ntp_proto::ProtocolVersion::V4,
                })
                .unwrap();
                let io = TcpStream::connect(("localhost", port)).await.unwrap();
                kex.exchange_keys(io, "localhost".into(), []).await
            })
            .await
            .is_err()
        );

        blocker.shutdown().await.unwrap();
        let mut buf = vec![];
        let _ = blocker.read_to_end(&mut buf).await; // explicitly ignore error as this might be EPIPE
        drop(blocker);

        let result = tokio::time::timeout(
            std::time::Duration::from_millis(750), // large timeout is needed to ensure test succeeds consistently on MacOS M2 E-cores
            async move {
                let kex = KeyExchangeClient::new(NtsClientConfig {
                    certificates: certificates_from_bufread(BufReader::new(Cursor::new(ca)))
                        .unwrap()
                        .into(),
                    protocol_version: ntp_proto::ProtocolVersion::V4,
                })
                .unwrap();
                let io = TcpStream::connect(("localhost", port)).await.unwrap();
                kex.exchange_keys(io, "localhost".into(), []).await
            },
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(result.remote, "localhost");
        assert_eq!(result.port, 123);
    }

    #[tokio::test]
    async fn key_exchange_roundtrip_with_port_server() {
        let port = alloc_port();

        let provider = KeySetProvider::new(1);
        let keyset = provider.get();

        let (_sender, keyset) = tokio::sync::watch::channel(keyset);
        let nts_ke_config = NtsKeConfig {
            certificate_chain_path: PathBuf::from("test-keys/end.fullchain.pem"),
            private_key_path: PathBuf::from("test-keys/end.key"),
            accepted_pool_authentication_tokens: vec![],
            key_exchange_timeout_ms: 1000,
            concurrent_connections: 512,
            listen: SocketAddr::new("0.0.0.0".parse().unwrap(), port),
            ntp_port: Some(568),
            ntp_server: Some("jantje".into()),
            accept_ntp_versions: vec![NtpVersion::V4],
        };

        let _join_handle = spawn(nts_ke_config, keyset);

        // give the server some time to make the port available
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        let ca = include_bytes!("../../test-keys/testca.pem");
        let result = async move {
            let kex = KeyExchangeClient::new(NtsClientConfig {
                certificates: certificates_from_bufread(BufReader::new(Cursor::new(ca)))
                    .unwrap()
                    .into(),
                protocol_version: ntp_proto::ProtocolVersion::V4,
            })
            .unwrap();
            let io = TcpStream::connect(("localhost", port)).await.unwrap();
            kex.exchange_keys(io, "localhost".into(), []).await
        }
        .await
        .unwrap();

        assert_eq!(result.remote, "jantje");
        assert_eq!(result.port, 568);
    }
}
