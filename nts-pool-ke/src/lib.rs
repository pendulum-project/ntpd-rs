#![deny(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::explicit_iter_loop)] // breaking on msrv
mod cli;
mod config;

mod tracing;

use std::{io::ErrorKind, ops::ControlFlow, path::PathBuf, sync::Arc};

use ::tracing::{info, warn};
use cli::NtsPoolKeOptions;
use config::{Config, NtsPoolKeConfig};
use ntp_proto::{
    AeadAlgorithm, ClientToPoolData, KeyExchangeError, NtsRecord, PoolToServerData,
    PoolToServerDecoder, SupportedAlgorithmsDecoder,
};
use rustls::{
    pki_types::{CertificateDer, ServerName},
    version::TLS13,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, ToSocketAddrs},
};
use tokio_rustls::TlsConnector;

use crate::tracing as daemon_tracing;
use daemon_tracing::LogLevel;
use tracing_subscriber::util::SubscriberInitExt;

pub(crate) mod exitcode {
    /// An internal software error has been detected.  This
    /// should be limited to non-operating system related
    /// errors as possible.
    pub const SOFTWARE: i32 = 70;

    /// Something was found in an unconfigured or misconfigured state.
    pub const CONFIG: i32 = 78;
}

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// # Errors
///
/// Will return `Err` if `cli::NtsPoolKeAction` fails.
pub async fn nts_pool_ke_main() -> Result<(), Box<dyn std::error::Error>> {
    let options = NtsPoolKeOptions::try_parse_from(std::env::args())?;

    match options.action {
        cli::NtsPoolKeAction::Help => {
            println!("{}", cli::long_help_message());
        }
        cli::NtsPoolKeAction::Version => {
            eprintln!("nts-pool-ke {VERSION}");
        }
        cli::NtsPoolKeAction::Run => run(options).await?,
    }

    Ok(())
}

// initializes the logger so that logs during config parsing are reported. Then it overrides the
// log level based on the config if required.
pub(crate) async fn initialize_logging_parse_config(
    initial_log_level: Option<LogLevel>,
    config_path: Option<PathBuf>,
) -> Config {
    let mut log_level = initial_log_level.unwrap_or_default();

    let config_tracing = daemon_tracing::tracing_init(log_level);
    let config = ::tracing::subscriber::with_default(config_tracing, || {
        async {
            match config_path {
                None => {
                    eprintln!("no configuration path specified");
                    std::process::exit(exitcode::CONFIG);
                }
                Some(config_path) => {
                    match Config::from_args(config_path).await {
                        Ok(c) => c,
                        Err(e) => {
                            // print to stderr because tracing is not yet setup
                            eprintln!("There was an error loading the config: {e}");
                            std::process::exit(exitcode::CONFIG);
                        }
                    }
                }
            }
        }
    })
    .await;

    if let Some(config_log_level) = config.observability.log_level {
        if initial_log_level.is_none() {
            log_level = config_log_level;
        }
    }

    // set a default global subscriber from now on
    let tracing_inst = daemon_tracing::tracing_init(log_level);
    tracing_inst.init();

    config
}

async fn run(options: NtsPoolKeOptions) -> Result<(), Box<dyn std::error::Error>> {
    let config = initialize_logging_parse_config(options.log_level, options.config).await;

    // give the user a warning that we use the command line option
    if config.observability.log_level.is_some() && options.log_level.is_some() {
        ::tracing::info!("Log level override from command line arguments is active");
    }

    // Warn/error if the config is unreasonable. We do this after finishing
    // tracing setup to ensure logging is fully configured.
    config.check();

    let result = run_nts_pool_ke(config.nts_pool_ke_server).await;

    match result {
        Ok(v) => Ok(v),
        Err(e) => {
            ::tracing::error!("Abnormal termination of NTS KE server: {e}");
            std::process::exit(exitcode::SOFTWARE)
        }
    }
}

async fn run_nts_pool_ke(nts_pool_ke_config: NtsPoolKeConfig) -> std::io::Result<()> {
    let certificate_authority_file =
        std::fs::File::open(&nts_pool_ke_config.certificate_authority_path).map_err(|e| {
            io_error(&format!(
                "error reading certificate_authority_path at `{:?}`: {:?}",
                nts_pool_ke_config.certificate_authority_path, e
            ))
        })?;

    let certificate_chain_file = std::fs::File::open(&nts_pool_ke_config.certificate_chain_path)
        .map_err(|e| {
            io_error(&format!(
                "error reading certificate_chain_path at `{:?}`: {:?}",
                nts_pool_ke_config.certificate_chain_path, e
            ))
        })?;

    let private_key_file =
        std::fs::File::open(&nts_pool_ke_config.private_key_path).map_err(|e| {
            io_error(&format!(
                "error reading key_der_path at `{:?}`: {:?}",
                nts_pool_ke_config.private_key_path, e
            ))
        })?;

    let certificate_authority: Arc<[rustls::pki_types::CertificateDer]> =
        rustls_pemfile::certs(&mut std::io::BufReader::new(certificate_authority_file))
            .collect::<std::io::Result<Arc<[rustls::pki_types::CertificateDer]>>>()?;

    let certificate_chain: Vec<rustls::pki_types::CertificateDer> =
        rustls_pemfile::certs(&mut std::io::BufReader::new(certificate_chain_file))
            .collect::<std::io::Result<Vec<rustls::pki_types::CertificateDer>>>()?;

    let private_key = rustls_pemfile::private_key(&mut std::io::BufReader::new(private_key_file))?
        .ok_or(io_error("could not parse private key"))?;

    pool_key_exchange_server(
        nts_pool_ke_config.listen,
        certificate_authority,
        certificate_chain,
        private_key,
        nts_pool_ke_config.key_exchange_servers,
        nts_pool_ke_config.key_exchange_timeout_ms,
    )
    .await
}

fn io_error(msg: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, msg)
}

async fn pool_key_exchange_server(
    address: impl ToSocketAddrs,
    certificate_authority: Arc<[rustls::pki_types::CertificateDer<'static>]>,
    certificate_chain: Vec<rustls::pki_types::CertificateDer<'static>>,
    private_key: rustls::pki_types::PrivateKeyDer<'static>,
    servers: Vec<config::KeyExchangeServer>,
    timeout_ms: u64,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(address).await?;

    let mut config = rustls::ServerConfig::builder_with_protocol_versions(&[&TLS13])
        .with_no_client_auth()
        .with_single_cert(certificate_chain.clone(), private_key.clone_key())
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidInput, err))?;

    config.alpn_protocols.clear();
    config.alpn_protocols.push(b"ntske/1".to_vec());

    let config = Arc::new(config);
    let servers: Arc<[_]> = servers.into();

    info!("listening on '{:?}'", listener.local_addr());

    loop {
        let (client_stream, source_address) = listener.accept().await?;
        let client_to_pool_config = config.clone();
        let servers = servers.clone();
        let certificate_chain = certificate_chain.clone();
        let private_key = private_key.clone_key();

        let certificate_authority = certificate_authority.clone();
        let fut = handle_client(
            client_stream,
            client_to_pool_config,
            certificate_authority,
            certificate_chain,
            private_key,
            servers,
        );

        tokio::spawn(async move {
            let timeout = std::time::Duration::from_millis(timeout_ms);
            match tokio::time::timeout(timeout, fut).await {
                Err(_) => ::tracing::debug!(?source_address, "NTS Pool KE timed out"),
                Ok(Err(err)) => ::tracing::debug!(?err, ?source_address, "NTS Pool KE failed"),
                Ok(Ok(())) => ::tracing::debug!(?source_address, "NTS Pool KE completed"),
            }
        });
    }
}

async fn try_nts_ke_server<'a>(
    connector: &TlsConnector,
    config::KeyExchangeServer { domain, port }: &'a config::KeyExchangeServer,
    selected_algorithm: AeadAlgorithm,
) -> Result<(&'a str, u16, ServerName<'static>), KeyExchangeError> {
    info!("checking supported algorithms for '{domain}:{port}'");

    let domain = domain.as_str();
    let server_name = rustls::pki_types::ServerName::try_from(domain)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid dnsname"))?
        .to_owned();

    let server_stream = match tokio::net::TcpStream::connect((domain, *port)).await {
        Ok(server_stream) => server_stream,
        Err(e) => return Err(e.into()),
    };
    let mut server_stream = connector
        .connect(server_name.clone(), server_stream)
        .await?;

    info!("established connection to the server");

    let supported_algorithms = supported_algorithms_request(&mut server_stream).await?;

    info!("received supported algorithms from the NTS KE server");

    if supported_algorithms
        .iter()
        .any(|(algorithm_id, _)| *algorithm_id == selected_algorithm as u16)
    {
        Ok((domain, *port, server_name))
    } else {
        Err(KeyExchangeError::NoValidAlgorithm)
    }
}

async fn pick_nts_ke_servers<'a>(
    connector: &TlsConnector,
    servers: &'a [config::KeyExchangeServer],
    selected_algorithm: AeadAlgorithm,
    denied_servers: &[String],
) -> Result<(&'a str, u16, ServerName<'static>), KeyExchangeError> {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static START_INDEX: AtomicUsize = AtomicUsize::new(0);
    let start_index = START_INDEX.fetch_add(1, Ordering::Relaxed);

    // rotate the serverlist so that an error caused by a single NTS-KE server doesn't
    // permanently cripple the pool
    let (left, right) = servers.split_at(start_index % servers.len());
    let rotated_servers = right.iter().chain(left.iter());
    let mut connection_error = false;

    for server in rotated_servers {
        if denied_servers.contains(&server.domain) {
            continue;
        }

        match try_nts_ke_server(connector, server, selected_algorithm).await {
            Ok(x) => return Ok(x),
            Err(e) => match e {
                // only if the connection was refused do we try another server during this
                // connection, because otherwise key material from this TLS connection could have
                // been shared with multiple servers through the FixedKeyRequest
                KeyExchangeError::Io(e) if e.kind() == ErrorKind::ConnectionRefused => {
                    connection_error = true;
                    ::tracing::debug!("connection refused: {e}");
                    continue;
                }
                _ => return Err(e),
            },
        }
    }

    warn!("pool could not find a valid KE server");

    // if finding a KE server failed because of a connection error,
    // report a Internal Server Error; if it failed because all our servers
    // were able and willing, but rejected by the client, return a Bad Request
    if connection_error {
        Err(KeyExchangeError::InternalServerError)
    } else {
        Err(KeyExchangeError::BadRequest)
    }
}

async fn handle_client(
    client_stream: tokio::net::TcpStream,
    config: Arc<rustls::ServerConfig>,
    certificate_authority: Arc<[rustls::pki_types::CertificateDer<'static>]>,
    certificate_chain: Vec<rustls::pki_types::CertificateDer<'static>>,
    private_key: rustls::pki_types::PrivateKeyDer<'static>,
    servers: Arc<[config::KeyExchangeServer]>,
) -> Result<(), KeyExchangeError> {
    // handle the initial client to pool
    let acceptor = tokio_rustls::TlsAcceptor::from(config);
    let mut client_stream = acceptor.accept(client_stream).await?;

    // read all records from the client
    let client_data = client_to_pool_request(&mut client_stream).await?;

    info!("received records from the client",);

    let connector =
        pool_to_server_connector(&certificate_authority, certificate_chain, private_key)?;

    let pick = pick_nts_ke_servers(
        &connector,
        &servers,
        client_data.algorithm,
        &client_data.denied_servers,
    )
    .await;

    let (server_name, port, domain) = match pick {
        Ok(x) => x,
        Err(e) => {
            // for now, just send back to the client that its algorithms were invalid
            // AeadAlgorithm::AeadAesSivCmac256 should always be supported by servers and clients
            info!(?e, "could not find a valid KE server");

            let records = [
                NtsRecord::NextProtocol {
                    protocol_ids: vec![0],
                },
                NtsRecord::Error {
                    errorcode: e.to_error_code(),
                },
                NtsRecord::EndOfMessage,
            ];

            let mut buffer = Vec::with_capacity(1024);
            for record in records {
                record.write(&mut buffer)?;
            }

            client_stream.write_all(&buffer).await?;
            client_stream.shutdown().await?;

            return Ok(());
        }
    };

    // this is inefficient of course, but spec-compliant: the TLS connection is closed when the server
    // receives a EndOfMessage record, so we have to establish a new one. re-using the TCP
    // connection runs into issues (seems to leave the server in an invalid state).
    let server_stream = tokio::net::TcpStream::connect((server_name, port)).await?;
    let server_stream = connector.connect(domain, server_stream).await?;

    info!("fetching cookies from the NTS KE server");

    // get the cookies from the NTS KE server
    let records_for_server = prepare_records_for_server(&client_stream, client_data)?;
    match cookie_request(server_stream, &records_for_server).await {
        Err(e) => {
            warn!(?e, "NTS KE server returned an error");

            Err(e)
        }
        Ok(records_for_client) => {
            const NTP_DEFAULT_PORT: u16 = 123;

            info!("received cookies from the NTS KE server");

            // now we just forward the response
            let mut buffer = Vec::with_capacity(1024);
            let (mut mentions_server, mut mentions_port) = (false, false);

            for record in &records_for_client {
                mentions_server |= matches!(record, NtsRecord::Server { .. });
                mentions_port |= matches!(record, NtsRecord::Port { .. });
            }

            if !mentions_server {
                NtsRecord::Server {
                    critical: true,
                    name: server_name.to_string(),
                }
                .write(&mut buffer)?;
            }

            if !mentions_port {
                NtsRecord::Port {
                    critical: true,
                    port: NTP_DEFAULT_PORT,
                }
                .write(&mut buffer)?;
            }

            for record in records_for_client {
                record.write(&mut buffer)?;
            }

            client_stream.write_all(&buffer).await?;
            client_stream.shutdown().await?;

            info!("wrote records for client");

            Ok(())
        }
    }
}

fn prepare_records_for_server(
    client_stream: &tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    client_data: ClientToPoolData,
) -> Result<Vec<NtsRecord>, KeyExchangeError> {
    let nts_keys = client_data.extract_nts_keys(client_stream.get_ref().1)?;

    let mut records_for_server = client_data.records;
    records_for_server.extend([
        NtsRecord::NextProtocol {
            protocol_ids: vec![0],
        },
        NtsRecord::AeadAlgorithm {
            critical: false,
            algorithm_ids: vec![client_data.algorithm as u16],
        },
        nts_keys.as_fixed_key_request(),
        NtsRecord::EndOfMessage,
    ]);

    Ok(records_for_server)
}

fn pool_to_server_connector(
    extra_certificates: &[CertificateDer<'static>],
    certificate_chain: Vec<rustls::pki_types::CertificateDer<'static>>,
    private_key: rustls::pki_types::PrivateKeyDer<'static>,
) -> Result<tokio_rustls::TlsConnector, KeyExchangeError> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs()? {
        roots.add(cert).map_err(KeyExchangeError::Certificate)?;
    }

    for cert in extra_certificates {
        roots
            .add(cert.clone())
            .map_err(KeyExchangeError::Certificate)?;
    }

    let config = rustls::ClientConfig::builder_with_protocol_versions(&[&TLS13])
        .with_root_certificates(roots)
        .with_client_auth_cert(certificate_chain, private_key)
        .unwrap();

    // already has the FixedKeyRequest record
    Ok(tokio_rustls::TlsConnector::from(Arc::new(config)))
}

async fn client_to_pool_request(
    stream: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
) -> Result<ClientToPoolData, KeyExchangeError> {
    let mut decoder = ntp_proto::ClientToPoolDecoder::default();

    let mut buf = [0; 1024];

    loop {
        let n = stream.read(&mut buf).await?;

        if n == 0 {
            break Err(KeyExchangeError::IncompleteResponse);
        }

        decoder = match decoder.step_with_slice(&buf[..n]) {
            ControlFlow::Continue(decoder) => decoder,
            ControlFlow::Break(done) => break done,
        };
    }
}

async fn cookie_request(
    mut stream: tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    nts_records: &[NtsRecord],
) -> Result<Vec<NtsRecord>, KeyExchangeError> {
    // now we just forward the response
    let mut buf = Vec::with_capacity(1024);
    for record in nts_records {
        record.write(&mut buf)?;
    }

    stream.write_all(&buf).await?;

    let mut buf = [0; 1024];
    let mut decoder = PoolToServerDecoder::default();

    loop {
        let n = stream.read(&mut buf).await?;

        if n == 0 {
            break Err(KeyExchangeError::IncompleteResponse);
        }

        decoder = match decoder.step_with_slice(&buf[..n]) {
            ControlFlow::Continue(decoder) => decoder,
            ControlFlow::Break(Ok(PoolToServerData {
                records,
                algorithm: _,
                protocol: _,
            })) => {
                stream.shutdown().await?;
                break Ok(records);
            }
            ControlFlow::Break(Err(error)) => break Err(error),
        };
    }
}

async fn supported_algorithms_request(
    stream: &mut tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
) -> Result<Vec<(u16, u16)>, KeyExchangeError> {
    let nts_records = [
        NtsRecord::SupportedAlgorithmList {
            supported_algorithms: vec![],
        },
        NtsRecord::EndOfMessage,
    ];

    // now we just forward the response
    let mut buf = Vec::with_capacity(1024);
    for record in nts_records {
        record.write(&mut buf)?;
    }

    stream.write_all(&buf).await?;

    let mut buf = [0; 1024];
    let mut decoder = SupportedAlgorithmsDecoder::default();

    loop {
        let n = stream.read(&mut buf).await?;

        if n == 0 {
            break Err(KeyExchangeError::IncompleteResponse);
        }

        decoder = match decoder.step_with_slice(&buf[..n]) {
            ControlFlow::Continue(decoder) => decoder,
            ControlFlow::Break(result) => break result,
        };
    }
}
