//! This crate contains the control interface client for ntpd-rs and is not intended
//! as a public interface at this time. It follows the same version as the main
//! ntpd-rs crate, but that version is not intended to give any stability guarantee.
//! Use at your own risk.
//!
//! Please visit the [ntpd-rs](https://github.com/pendulum-project/ntpd-rs) project
//! for more information.
#![forbid(unsafe_code)]

use std::{path::PathBuf, process::ExitCode};

use ntp_daemon::{config::CliArg, Config, ObservableState};
use ntp_metrics_exporter::Metrics;

const USAGE_MSG: &str = "\
usage: ntp-ctl validate [-c PATH]
       ntp-ctl status [-f FORMAT] [-c PATH] [-o PATH]
       ntp-ctl -h | ntp-ctl -v";

const DESCRIPTOR: &str = "ntp-ctl - ntp-daemon monitoring";

const HELP_MSG: &str = "Options:
  -f, --format=FORMAT                  which format to use for printing statistics [plain, prometheus]
  -c, --config=CONFIG                  which configuration file to read the socket paths from
  -o, --observation-socket=SOCKET      path of the observation socket";

pub fn long_help_message() -> String {
    format!("{DESCRIPTOR}\n\n{USAGE_MSG}\n\n{HELP_MSG}")
}

#[derive(Debug, Default, PartialEq, Eq)]
enum Format {
    #[default]
    Plain,
    Prometheus,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub enum NtpCtlAction {
    #[default]
    Help,
    Version,
    Validate,
    Status,
}

#[derive(Debug, Default)]
pub(crate) struct NtpDaemonOptions {
    config: Option<PathBuf>,
    observation_socket: Option<PathBuf>,
    format: Format,
    help: bool,
    version: bool,
    validate: bool,
    status: bool,
    action: NtpCtlAction,
}

impl NtpDaemonOptions {
    const TAKES_ARGUMENT: &[&'static str] = &["--config", "--format", "--observation-socket"];
    const TAKES_ARGUMENT_SHORT: &[char] = &['o', 'c', 'f'];

    /// parse an iterator over command line arguments
    pub fn try_parse_from<I, T>(iter: I) -> Result<Self, String>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<str> + Clone,
    {
        let mut options = NtpDaemonOptions::default();

        let mut it = iter.into_iter().map(|x| x.as_ref().to_string()).peekable();

        match it.peek().map(|x| x.as_str()) {
            Some("validate") => {
                let _ = it.next();
                options.validate = true;
            }
            Some("status") => {
                let _ = it.next();
                options.status = true;
            }
            _ => { /* do nothing */ }
        };

        let arg_iter =
            CliArg::normalize_arguments(Self::TAKES_ARGUMENT, Self::TAKES_ARGUMENT_SHORT, it)?
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
                    "-f" | "--format" => match value.as_str() {
                        "plain" => options.format = Format::Plain,
                        "prometheus" => options.format = Format::Prometheus,
                        _ => Err(format!("invalid format option provided: {value}"))?,
                    },
                    "-o" | "--observation-socket" => {
                        options.observation_socket = Some(PathBuf::from(value));
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
            self.action = NtpCtlAction::Help;
        } else if self.version {
            self.action = NtpCtlAction::Version;
        } else if self.validate {
            self.action = NtpCtlAction::Validate;
        } else if self.status {
            self.action = NtpCtlAction::Status;
        } else {
            self.action = NtpCtlAction::Help;
        }
    }
}

async fn validate(config: Option<PathBuf>) -> std::io::Result<ExitCode> {
    // Late completion not needed, so ignore result.
    let _ = ntp_daemon::tracing::init(tracing_subscriber::EnvFilter::new("info"));
    match Config::from_args(config, vec![], vec![]).await {
        Ok(config) => {
            if config.check() {
                eprintln!("Config looks good");
                Ok(ExitCode::SUCCESS)
            } else {
                Ok(ExitCode::FAILURE)
            }
        }
        Err(e) => {
            eprintln!("Error: Could not load configuration: {e}");
            Ok(ExitCode::FAILURE)
        }
    }
}

const VERSION: &str = env!("CARGO_PKG_VERSION");

pub async fn main() -> std::io::Result<ExitCode> {
    let options = match NtpDaemonOptions::try_parse_from(std::env::args()) {
        Ok(options) => options,
        Err(msg) => return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, msg)),
    };

    match options.action {
        NtpCtlAction::Help => {
            println!("{}", long_help_message());
            Ok(ExitCode::SUCCESS)
        }
        NtpCtlAction::Version => {
            eprintln!("ntp-ctl {VERSION}");
            Ok(ExitCode::SUCCESS)
        }
        NtpCtlAction::Validate => validate(options.config).await,
        NtpCtlAction::Status => {
            let config = Config::from_args(options.config, vec![], vec![]).await;

            if let Err(ref e) = config {
                println!("Warning: Unable to load configuration file: {e}");
            }

            let config = config.unwrap_or_default();

            let observation = options
                .observation_socket
                .or(config.observe.path)
                .unwrap_or_else(|| PathBuf::from("/run/ntpd-rs/observe"));

            match options.format {
                Format::Plain => print_state(Format::Plain, observation).await,
                Format::Prometheus => print_state(Format::Prometheus, observation).await,
            }
        }
    }
}

async fn print_state(print: Format, observe_socket: PathBuf) -> Result<ExitCode, std::io::Error> {
    let mut stream = match tokio::net::UnixStream::connect(&observe_socket).await {
        Ok(stream) => stream,
        Err(e) => {
            eprintln!("Could not open socket at {}: {e}", observe_socket.display(),);
            return Ok(ExitCode::FAILURE);
        }
    };

    let mut msg = Vec::with_capacity(16 * 1024);
    let output =
        match ntp_daemon::sockets::read_json::<ObservableState>(&mut stream, &mut msg).await {
            Ok(output) => output,
            Err(e) => {
                eprintln!("Failed to read state from observation socket: {e}");

                return Ok(ExitCode::FAILURE);
            }
        };

    match print {
        Format::Plain => {
            // Unwrap here is fine as our serializer is infallible.
            println!("{}", serde_json::to_string_pretty(&output).unwrap());
        }
        Format::Prometheus => {
            let metrics = Metrics::default();
            metrics.fill(&output);
            let registry = metrics.registry();
            let mut buf = String::new();

            if let Err(e) = prometheus_client::encoding::text::encode(&mut buf, &registry) {
                eprintln!("Failed to encode prometheus data: {e}");

                return Ok(ExitCode::FAILURE);
            }

            println!("{buf}");
        }
    }

    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use std::os::unix::prelude::PermissionsExt;

    use ntp_daemon::{
        config::ObserveConfig,
        sockets::{create_unix_socket, write_json},
    };

    use super::*;

    async fn write_socket_helper(
        command: Format,
        socket_name: &str,
    ) -> std::io::Result<Result<ExitCode, std::io::Error>> {
        let config: ObserveConfig = Default::default();

        // be careful with copying: tests run concurrently and should use a unique socket name!
        let path = std::env::temp_dir().join(socket_name);
        if path.exists() {
            std::fs::remove_file(&path).unwrap();
        }

        let peers_listener = create_unix_socket(&path)?;

        let permissions: std::fs::Permissions = PermissionsExt::from_mode(config.mode);
        std::fs::set_permissions(&path, permissions)?;

        let fut = super::print_state(command, path);
        let handle = tokio::spawn(fut);

        let value = ObservableState {
            system: Default::default(),
            peers: vec![],
            servers: vec![],
        };

        let (mut stream, _addr) = peers_listener.accept().await?;
        write_json(&mut stream, &value).await?;

        let result = handle.await.unwrap();

        Ok(result)
    }

    #[tokio::test]
    async fn test_control_socket_peer() -> std::io::Result<()> {
        // be careful with copying: tests run concurrently and should use a unique socket name!
        let result = write_socket_helper(Format::Plain, "ntp-test-stream-6").await?;

        assert_eq!(
            format!("{:?}", result.unwrap()),
            format!("{:?}", ExitCode::SUCCESS)
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_control_socket_prometheus() -> std::io::Result<()> {
        // be careful with copying: tests run concurrently and should use a unique socket name!
        let result = write_socket_helper(Format::Prometheus, "ntp-test-stream-8").await?;

        assert_eq!(
            format!("{:?}", result.unwrap()),
            format!("{:?}", ExitCode::SUCCESS)
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_control_socket_peer_invalid_input() -> std::io::Result<()> {
        let config: ObserveConfig = Default::default();

        // be careful with copying: tests run concurrently and should use a unique socket name!
        let path = std::env::temp_dir().join("ntp-test-stream-10");
        if path.exists() {
            std::fs::remove_file(&path).unwrap();
        }

        let peers_listener = create_unix_socket(&path)?;

        let permissions: std::fs::Permissions = PermissionsExt::from_mode(config.mode);
        std::fs::set_permissions(&path, permissions)?;

        let fut = super::print_state(Format::Plain, path);
        let handle = tokio::spawn(fut);

        let value = 42u32;

        let (mut stream, _addr) = peers_listener.accept().await?;
        write_json(&mut stream, &value).await?;

        let result = handle.await.unwrap();

        assert_eq!(
            format!("{:?}", result.unwrap()),
            format!("{:?}", ExitCode::FAILURE)
        );

        Ok(())
    }
}
