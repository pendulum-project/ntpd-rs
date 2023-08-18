//! This crate contains the OpenMetrics/Prometheus metrics exporter for ntpd-rs, but
//! is not intended as a public interface at this time. It follows the same version
//! as the main ntpd-rs crate, but that version is not intended to give any
//! stability guarantee. Use at your own risk.
//!
//! Please visit the [ntpd-rs](https://github.com/pendulum-project/ntpd-rs) project
//! for more information.
#![forbid(unsafe_code)]

use super::Metrics;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

use std::{
    fmt::Write,
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
};

use crate::daemon::{config::CliArg, Config, ObservableState};

const VERSION: &str = env!("CARGO_PKG_VERSION");

const USAGE_MSG: &str = "\
usage: ntp-metrics-exporter [-c PATH] [-o PATH] [-l SOCKET_ADDR]
       ntp-metrics-exporter -h | ntp-metrics-exporter -v";

const DESCRIPTOR: &str = "ntp-metrics-exporter - serve ntpd-rs openmetrics via http";

const HELP_MSG: &str = "Options:
  -c, --config=CONFIG                  which configuration file to read the socket paths from
  -o, --observation-socket=SOCKET      path of the observation socket
  -l, --listen-socket=SOCKET_ADDR      socket to run the http server on";

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

#[derive(Debug)]
pub(crate) struct NtpMetricsExporterOptions {
    config: Option<PathBuf>,
    observation_socket: Option<PathBuf>,
    listen_addr: SocketAddr,
    help: bool,
    version: bool,
    action: MetricsAction,
}

impl Default for NtpMetricsExporterOptions {
    fn default() -> Self {
        Self {
            config: Default::default(),
            observation_socket: Default::default(),
            listen_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 9975)),
            help: Default::default(),
            version: Default::default(),
            action: Default::default(),
        }
    }
}

impl NtpMetricsExporterOptions {
    const TAKES_ARGUMENT: &[&'static str] =
        &["--config", "--observation-socket", "--listen-socket"];
    const TAKES_ARGUMENT_SHORT: &[char] = &['o', 'c', 'l'];

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
                    "-o" | "--observation-socket" => {
                        options.observation_socket = Some(PathBuf::from(value));
                    }
                    "-l" | "--listen-socket" => match value.parse() {
                        Ok(socket_addr) => options.listen_addr = socket_addr,
                        Err(e) => Err(e.to_string())?,
                    },
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
    let config = Config::from_args(options.config, vec![], vec![]).await;

    if let Err(ref e) = config {
        println!("Warning: Unable to load configuration file: {e}");
    }

    let config = config.unwrap_or_default();

    let observation_socket_path = match options.observation_socket {
        Some(path) => path,
        None => match config.observability.observe.observation_path {
            Some(path) => path,
            None => "/run/ntpd-rs/observe".into(),
        },
    };

    println!("starting ntp-metrics-exporter on {}", &options.listen_addr);

    let listener = TcpListener::bind(options.listen_addr).await?;

    loop {
        let (mut tcp_stream, _) = listener.accept().await?;

        let mut stream = tokio::net::UnixStream::connect(&observation_socket_path).await?;
        let mut msg = Vec::with_capacity(16 * 1024);
        let output: ObservableState =
            crate::daemon::sockets::read_json(&mut stream, &mut msg).await?;
        let metrics = Metrics::default();
        metrics.fill(&output);
        let registry = metrics.registry();

        let mut content = String::with_capacity(4 * 1024);
        prometheus_client::encoding::text::encode(&mut content, &registry)?;

        let mut buf = String::with_capacity(4 * 1024);

        // headers
        buf.push_str("HTTP/1.1 200 OK\r\n");
        buf.push_str("content-type: text/plain\r\n");
        write!(buf, "content-length: {}\r\n\r\n", content.len()).unwrap();

        // actual content
        buf.push_str(&content);

        tcp_stream.write_all(buf.as_bytes()).await.unwrap();
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

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

    #[test]
    fn cli_observation_socket() {
        let observation_str = "/bar/baz";
        let observation = Path::new(observation_str);

        let arguments = &[BINARY, "-o", observation_str];

        let options = NtpMetricsExporterOptions::try_parse_from(arguments).unwrap();

        assert_eq!(options.observation_socket.unwrap().as_path(), observation);
    }

    #[test]
    fn cli_listen_socket() {
        let listen_str = "127.0.0.1:1234";
        let listen = SocketAddr::from((Ipv4Addr::LOCALHOST, 1234));

        let arguments = &[BINARY, "-l", listen_str];

        let options = NtpMetricsExporterOptions::try_parse_from(arguments).unwrap();

        assert_eq!(options.listen_addr, listen);
    }
}
