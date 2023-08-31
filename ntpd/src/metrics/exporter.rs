use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tracing_subscriber::util::SubscriberInitExt;

use std::{
    fmt::Write,
    net::{Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
};

use crate::daemon::{config::CliArg, Config, ObservableState};

const VERSION: &str = env!("CARGO_PKG_VERSION");

const USAGE_MSG: &str = "\
usage: ntp-metrics-exporter [-c PATH] [-o PATH] [-l SOCKET_ADDR]
       ntp-metrics-exporter -h | ntp-metrics-exporter -v";

const DESCRIPTOR: &str = "ntp-metrics-exporter - serve ntpd-rs openmetrics via http";

const HELP_MSG: &str = "Options:
  -c, --config=CONFIG                  ntpd-rs configuration file (default: 
                                       /etc/ntpd-rs/ntp.toml)
  -o, --observation-socket=SOCKET      path of the observation socket (default
                                       is taken from the configuration)
  -l, --listen-socket=SOCKET_ADDR      address to serve prometheus output on
                                       (default: 127.0.0.1:9975)";

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

async fn initialize_logging(config_path: Option<PathBuf>) -> Config {
    let options_log_level = None;

    let mut log_level = options_log_level.unwrap_or_default();

    let config_tracing = crate::daemon::tracing::tracing_init(log_level);
    let config = ::tracing::subscriber::with_default(config_tracing, || {
        async {
            match Config::from_args(config_path, vec![], vec![]).await {
                Ok(c) => c,
                Err(e) => {
                    // print to stderr because tracing is not yet setup
                    eprintln!("There was an error loading the config: {e}");
                    std::process::exit(crate::daemon::exitcode::CONFIG);
                }
            }
        }
    })
    .await;

    if let Some(config_log_level) = config.observability.log_level {
        if options_log_level.is_none() {
            log_level = config_log_level;
        }
    }

    // set a default global subscriber from now on
    let tracing_inst = crate::daemon::tracing::tracing_init(log_level);
    tracing_inst.init();

    config
}

async fn run(options: NtpMetricsExporterOptions) -> Result<(), Box<dyn std::error::Error>> {
    let config = initialize_logging(options.config).await;

    let observation_socket_path = match options.observation_socket {
        Some(path) => path,
        None => match config.observability.observe.observation_path {
            Some(path) => path,
            None => "/run/ntpd-rs/observe".into(),
        },
    };

    println!("starting ntp-metrics-exporter on {}", &options.listen_addr);

    let listener = TcpListener::bind(options.listen_addr).await?;
    let mut buf = String::with_capacity(4 * 1024);

    loop {
        let (mut tcp_stream, _) = listener.accept().await?;

        buf.clear();
        match handler(&mut buf, &observation_socket_path).await {
            Ok(()) => {
                tcp_stream.write_all(buf.as_bytes()).await?;
            }
            Err(e) => {
                tracing::warn!("hit an error: {e}");

                const ERROR_REPONSE: &str = concat!(
                    "HTTP/1.1 500 Internal Server Error\r\n",
                    "content-type: text/plain\r\n",
                    "content-length: 0\r\n\r\n",
                );

                tcp_stream.write_all(ERROR_REPONSE.as_bytes()).await?;
            }
        }
    }
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
    buf.write_str("HTTP/1.1 200 OK\r\n")?;
    buf.write_str("content-type: text/plain\r\n")?;
    buf.write_fmt(format_args!("content-length: {}\r\n\r\n", content.len()))?;

    // actual content
    buf.write_str(&content)?;

    Ok(())
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
