use libc::{ECONNABORTED, EMFILE, ENFILE, ENOBUFS, ENOMEM};
use timestamped_socket::interface::ChangeDetector;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{debug, error, trace, warn};

use std::{
    fmt::Write,
    path::{Path, PathBuf},
    sync::Arc,
};

use crate::daemon::{config::CliArg, initialize_logging_parse_config, ObservableState};

const VERSION: &str = env!("CARGO_PKG_VERSION");

const USAGE_MSG: &str = "\
usage: ntp-metrics-exporter [-c PATH]
       ntp-metrics-exporter -h | ntp-metrics-exporter -v";

const DESCRIPTOR: &str = "ntp-metrics-exporter - serve ntpd-rs openmetrics via http";

const HELP_MSG: &str = "Options:
  -c, --config=CONFIG                  ntpd-rs configuration file (default:
                                       /etc/ntpd-rs/ntp.toml)
  -h, --help                           display this help text
  -v, --version                        display version information";

pub fn long_help_message() -> String {
    format!("{DESCRIPTOR}\n\n{USAGE_MSG}\n\n{HELP_MSG}")
}

#[derive(Debug, Default, PartialEq, Eq)]
pub enum MetricsAction {
    #[default]
    Help,
    Version,
    Run,
}

#[derive(Debug, Default)]
pub(crate) struct NtpMetricsExporterOptions {
    config: Option<PathBuf>,
    help: bool,
    version: bool,
    action: MetricsAction,
}

impl NtpMetricsExporterOptions {
    const TAKES_ARGUMENT: &'static [&'static str] = &["--config"];
    const TAKES_ARGUMENT_SHORT: &'static [char] = &['c'];

    /// parse an iterator over command line arguments
    pub fn try_parse_from<I, T>(iter: I) -> Result<Self, String>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<str> + Clone,
    {
        let mut options = NtpMetricsExporterOptions::default();

        let arg_iter = CliArg::normalize_arguments(
            Self::TAKES_ARGUMENT,
            Self::TAKES_ARGUMENT_SHORT,
            iter.into_iter().map(|x| x.as_ref().to_string()),
        )?
        .into_iter()
        .peekable();

        for arg in arg_iter {
            match arg {
                CliArg::Flag(flag) => match flag.as_str() {
                    "-h" | "--help" => {
                        options.help = true;
                    }
                    "-v" | "--version" => {
                        options.version = true;
                    }
                    option => {
                        Err(format!("invalid option provided: {option}"))?;
                    }
                },
                CliArg::Argument(option, value) => match option.as_str() {
                    "-c" | "--config" => {
                        options.config = Some(PathBuf::from(value));
                    }
                    option => {
                        Err(format!("invalid option provided: {option}"))?;
                    }
                },
                CliArg::Rest(_rest) => { /* do nothing, drop remaining arguments */ }
            }
        }

        options.resolve_action();
        // nothing to validate at the moment

        Ok(options)
    }

    /// from the arguments resolve which action should be performed
    fn resolve_action(&mut self) {
        if self.help {
            self.action = MetricsAction::Help;
        } else if self.version {
            self.action = MetricsAction::Version;
        } else {
            self.action = MetricsAction::Run;
        }
    }
}

/// # Errors
///
/// Returns `Error` if `MetricsAction::Run` fails.
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let options = NtpMetricsExporterOptions::try_parse_from(std::env::args())?;
    match options.action {
        MetricsAction::Help => {
            println!("{}", long_help_message());
            Ok(())
        }
        MetricsAction::Version => {
            eprintln!("ntp-metrics-exporter {VERSION}");
            Ok(())
        }
        MetricsAction::Run => run(options).await,
    }
}

async fn run(options: NtpMetricsExporterOptions) -> Result<(), Box<dyn std::error::Error>> {
    let config = initialize_logging_parse_config(None, options.config).await;
    let timeout = std::time::Duration::from_millis(1000);

    let observation_socket_path = if let Some(path) = config.observability.observation_path {
        Arc::new(path)
    } else {
        eprintln!("An observation socket path must be configured using the observation-path option in the [observability] section of the configuration");
        std::process::exit(1);
    };

    println!(
        "starting ntp-metrics-exporter on {}",
        &config.observability.metrics_exporter_listen
    );

    let listener = loop {
        match TcpListener::bind(&config.observability.metrics_exporter_listen).await {
            Err(e) if e.kind() == std::io::ErrorKind::AddrNotAvailable => {
                tracing::info!("Could not open listening socket, waiting for interface to come up");
                let _ = tokio::time::timeout(
                    std::time::Duration::from_secs(60),
                    ChangeDetector::new()?.wait_for_change(),
                )
                .await;
            }
            Err(e) => {
                tracing::warn!("Could not open listening socket: {}", e);
                let _ = tokio::time::timeout(
                    std::time::Duration::from_secs(60),
                    ChangeDetector::new()?.wait_for_change(),
                )
                .await;
            }
            Ok(listener) => break listener,
        };
    };

    // this has a lot more permits than the daemon observer has, but we expect http transfers to
    // take longer than how much time the daemon needs to return observability data
    let permits = Arc::new(tokio::sync::Semaphore::new(100));

    loop {
        let permit = permits
            .clone()
            .acquire_owned()
            .await
            .expect("semaphore was unexpectedly closed");
        let (mut tcp_stream, _) = match listener.accept().await {
            Ok(a) => a,
            Err(e) if matches!(e.raw_os_error(), Some(ECONNABORTED)) => {
                debug!("Client unexpectedly closed connection: {e}");
                continue;
            }
            Err(e) if matches!(e.raw_os_error(), Some(ENFILE | EMFILE | ENOMEM | ENOBUFS)) => {
                error!("Not enough resources available to accept incoming connection: {e}");
                tokio::time::sleep(timeout).await;
                continue;
            }
            Err(e) => {
                error!("Could not accept incoming connection: {e}");
                return Err(e.into());
            }
        };
        let path = observation_socket_path.clone();

        // handle each connection on a separate task
        let fut = async move { handle_connection(&mut tcp_stream, &path).await };

        tokio::spawn(async move {
            match tokio::time::timeout(timeout, fut).await {
                Err(_) => debug!("connection timed out"),
                Ok(Err(e)) => warn!("error handling connection: {e}"),
                Ok(_) => trace!("connection handled successfully"),
            }
            drop(permit);
        });
    }
}

async fn handle_connection(
    stream: &mut (impl tokio::io::AsyncWrite + tokio::io::AsyncRead + Unpin),
    observation_socket_path: &Path,
) -> std::io::Result<()> {
    const ERROR_RESPONSE: &str = concat!(
        "HTTP/1.1 500 Internal Server Error\r\n",
        "content-type: text/plain\r\n",
        "content-length: 0\r\n\r\n",
    );

    // Wait until a request was sent, dropping the bytes read when this scope ends
    // to ensure we don't accidentally use them afterwards
    {
        // Receive all data until the header was fully received, or until max buf size
        let mut buf = [0u8; 2048];
        let mut bytes_read = 0;
        loop {
            bytes_read += stream.read(&mut buf[bytes_read..]).await?;

            // The headers end with two CRLFs in a row
            if buf[0..bytes_read].windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }

            // Headers should easily fit within the buffer
            // If we have not found the end yet, we are not going to
            if bytes_read >= buf.len() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Request too long",
                ));
            }
        }

        // We only respond to GET requests
        if !buf[0..bytes_read].starts_with(b"GET ") {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Expected GET request",
            ));
        }
    }

    // Send the response
    let mut buf = String::with_capacity(4 * 1024);
    match handler(&mut buf, observation_socket_path).await {
        Ok(()) => {
            stream.write_all(buf.as_bytes()).await?;
        }
        Err(e) => {
            tracing::warn!("hit an error: {e}");

            stream.write_all(ERROR_RESPONSE.as_bytes()).await?;
        }
    }
    Ok(())
}

async fn handler(buf: &mut String, observation_socket_path: &Path) -> std::io::Result<()> {
    let mut stream = tokio::net::UnixStream::connect(observation_socket_path).await?;
    let mut msg = Vec::with_capacity(16 * 1024);
    let observable_state: ObservableState =
        crate::daemon::sockets::read_json(&mut stream, &mut msg).await?;

    format_response(buf, &observable_state)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "formatting error"))
}

fn format_response(buf: &mut String, state: &ObservableState) -> std::fmt::Result {
    let mut content = String::with_capacity(4 * 1024);
    crate::metrics::format_state(&mut content, state)?;

    // headers
    buf.push_str("HTTP/1.1 200 OK\r\n");
    buf.push_str("content-type: text/plain\r\n");
    buf.write_fmt(format_args!("content-length: {}\r\n\r\n", content.len()))?;

    // actual content
    buf.write_str(&content)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    const BINARY: &str = "/usr/bin/ntp-metrics-exporter";

    #[test]
    fn cli_config() {
        let config_str = "/foo/bar/ntp.toml";
        let config = Path::new(config_str);
        let arguments = &[BINARY, "-c", config_str];

        let options = NtpMetricsExporterOptions::try_parse_from(arguments).unwrap();
        assert_eq!(options.config.unwrap().as_path(), config);
    }

    #[tokio::test]
    async fn deny_non_get_request() {
        let mut example = b"POST / HTTP/1.1\r\n\r\n".to_vec();
        let mut cursor = Cursor::new(&mut example);
        let res = handle_connection(&mut cursor, Path::new("/tmp/ntpd-rs.sock")).await;
        let err = res.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert_eq!(err.to_string(), "Expected GET request");
    }

    #[tokio::test]
    async fn does_not_accept_large_requests() {
        let mut example = [1u8; 4096].to_vec();
        let mut cursor = Cursor::new(&mut example);
        let res = handle_connection(&mut cursor, Path::new("/tmp/ntpd-rs.sock")).await;
        let err = res.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert_eq!(err.to_string(), "Request too long");
    }
}
