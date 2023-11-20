mod cli;
mod config;

mod bound_keyexchange;
mod tracing;

use std::{
    io::BufRead,
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
};

use bound_keyexchange::{BoundClientToPool, BoundPoolToServer};
use cli::NtsPoolKeOptions;
use config::{Config, NtsPoolKeConfig};
use ntp_proto::KeyExchangeError;
use tokio::net::{TcpListener, ToSocketAddrs};

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

    let cert_chain: Vec<rustls::Certificate> =
        rustls_pemfile::certs(&mut std::io::BufReader::new(certificate_chain_file))?
            .into_iter()
            .map(rustls::Certificate)
            .collect();

    let private_key = private_key_from_bufread(&mut std::io::BufReader::new(private_key_file))?
        .ok_or(io_error("could not parse private key"))?;

    pool_key_exchange_server(
        nts_pool_ke_config.listen,
        cert_chain,
        private_key,
        nts_pool_ke_config.key_exchange_timeout_ms,
    )
    .await
}

fn io_error(msg: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, msg)
}

async fn pool_key_exchange_server(
    address: impl ToSocketAddrs,
    certificate_chain: Vec<rustls::Certificate>,
    private_key: rustls::PrivateKey,
    timeout_ms: u64,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(address).await?;

    let mut config = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certificate_chain, private_key)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidInput, err))?;

    config.alpn_protocols.clear();
    config.alpn_protocols.push(b"ntske/1".to_vec());

    let config = Arc::new(config);

    loop {
        let (client_stream, peer_address) = listener.accept().await?;

        dbg!("new client");

        let client_to_pool_config = config.clone();

        let fut = foo(client_stream, client_to_pool_config);

        tokio::spawn(async move {
            let timeout = std::time::Duration::from_millis(timeout_ms);
            match tokio::time::timeout(timeout, fut).await {
                Err(_) => ::tracing::debug!(?peer_address, "NTS Pool KE timed out"),
                Ok(Err(err)) => ::tracing::debug!(?err, ?peer_address, "NTS Pool KE failed"),
                Ok(Ok(())) => ::tracing::debug!(?peer_address, "NTS Pool KE completed"),
            }
        });
    }
}

async fn foo(
    client_stream: tokio::net::TcpStream,
    config: Arc<rustls::ServerConfig>,
) -> Result<(), KeyExchangeError> {
    // handle the initial client to pool
    let client_connection = dbg!(BoundClientToPool::run(client_stream, config).await)?;

    dbg!(&client_connection.records);

    // next we should pick a server that satisfies the algorithm used and is not denied by the
    // client. But this server hardcoded for now.
    let server_name = String::from("127.0.0.1");
    let port = 8080;
    let server_stream = tokio::net::TcpStream::connect((server_name.as_str(), port)).await?;

    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs()? {
        let cert = rustls::Certificate(cert.0);
        roots.add(&cert).map_err(KeyExchangeError::Certificate)?;
    }

    let extra_certificates = [];
    for cert in extra_certificates {
        roots.add(cert).map_err(KeyExchangeError::Certificate)?;
    }

    let config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(roots)
        .with_no_client_auth();

    // already has the FixedKeyRequest record
    let records_for_server = &client_connection.records;

    let server_connection =
        BoundPoolToServer::new(server_stream, server_name, config, records_for_server)?.await?;

    // now we just forward the response
    let mut buffer = Vec::with_capacity(1024);
    for record in server_connection.records {
        record.write(&mut buffer)?;
    }

    use std::io::Write;
    let mut client_connection = client_connection;
    client_connection
        .tls_connection
        .writer()
        .write_all(&buffer)?;

    Ok(())
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
