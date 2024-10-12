use std::{path::PathBuf, process::ExitCode};

use crate::{
    daemon::{config::CliArg, tracing::LogLevel, Config, ObservableState},
    force_sync,
};
use tracing_subscriber::util::SubscriberInitExt;

const USAGE_MSG: &str = "\
usage: ntp-ctl validate [-c PATH]
       ntp-ctl status [-f FORMAT] [-c PATH]
       ntp-ctl force-sync [-c PATH]
       ntp-ctl -h | ntp-ctl -v";

const DESCRIPTOR: &str = "ntp-ctl - ntp-daemon monitoring";

const HELP_MSG: &str = "Options:
  -f, --format=FORMAT                  which format to use for printing statistics [plain, prometheus]
  -c, --config=CONFIG                  which configuration file to read the socket paths from
  -h, --help                           display this help text
  -v, --version                        display version information";

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
    ForceSync,
}

#[derive(Debug, Default)]
pub(crate) struct NtpCtlOptions {
    config: Option<PathBuf>,
    format: Format,
    action: NtpCtlAction,
}

impl NtpCtlOptions {
    const TAKES_ARGUMENT: &'static [&'static str] = &["--config", "--format"];
    const TAKES_ARGUMENT_SHORT: &'static [char] = &['c', 'f'];

    /// parse an iterator over command line arguments
    pub fn try_parse_from<I, T>(iter: I) -> Result<Self, String>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<str> + Clone,
    {
        let mut options = NtpCtlOptions::default();

        let it = iter.into_iter().map(|x| x.as_ref().to_string());

        let arg_iter =
            CliArg::normalize_arguments(Self::TAKES_ARGUMENT, Self::TAKES_ARGUMENT_SHORT, it)?
                .into_iter()
                .peekable();

        for arg in arg_iter {
            match arg {
                CliArg::Flag(flag) => match flag.as_str() {
                    "-h" | "--help" => {
                        options.action = NtpCtlAction::Help;
                    }
                    "-v" | "--version" => {
                        options.action = NtpCtlAction::Version;
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
                    option => {
                        Err(format!("invalid option provided: {option}"))?;
                    }
                },
                CliArg::Rest(rest) => {
                    if rest.len() > 1 {
                        eprintln!("Warning: Too many commands provided.");
                    }
                    for command in rest {
                        match command.as_str() {
                            "validate" => {
                                options.action = NtpCtlAction::Validate;
                            }
                            "status" => {
                                options.action = NtpCtlAction::Status;
                            }
                            "force-sync" => {
                                options.action = NtpCtlAction::ForceSync;
                            }
                            unknown => {
                                eprintln!("Warning: Unknown command {unknown}");
                            }
                        }
                    }
                }
            }
        }

        // nothing to validate at the moment

        Ok(options)
    }
}

async fn validate(config: Option<PathBuf>) -> std::io::Result<ExitCode> {
    // Late completion not needed, so ignore result.
    crate::daemon::tracing::tracing_init(LogLevel::Info).init();
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
    let options = match NtpCtlOptions::try_parse_from(std::env::args()) {
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
        NtpCtlAction::ForceSync => force_sync::force_sync(options.config).await,
        NtpCtlAction::Status => {
            let config = Config::from_args(options.config, vec![], vec![]).await;

            if let Err(ref e) = config {
                println!("Warning: Unable to load configuration file: {e}");
            }

            let config = config.unwrap_or_default();

            let observation = config
                .observability
                .observation_path
                .unwrap_or_else(|| PathBuf::from("/var/run/ntpd-rs/observe"));

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
    let mut output =
        match crate::daemon::sockets::read_json::<ObservableState>(&mut stream, &mut msg).await {
            Ok(output) => output,
            Err(e) => {
                eprintln!("Failed to read state from observation socket: {e}");

                return Ok(ExitCode::FAILURE);
            }
        };

    match print {
        Format::Plain => {
            // Sort sources by address and then id (to deal with pools), servers just by address
            output.sources.sort_by_key(|s| (s.name.clone(), s.id));
            output.servers.sort_by_key(|s| s.address);

            println!("Synchronization status:");
            println!(
                "Dispersion: {:.6}s, Delay: {:.6}s",
                output.system.time_snapshot.root_dispersion.to_seconds(),
                output.system.time_snapshot.root_delay.to_seconds()
            );
            println!("Stratum: {}", output.system.stratum);
            println!();
            println!("Sources:");
            for source in &output.sources {
                println!(
                    "{}/{}{} ({}): {:+.6}±{:.6}(±{:.6})s",
                    source.name,
                    source.address,
                    source.nts_cookies.map_or("", |_| " [NTS]"),
                    source.id,
                    source.timedata.offset.to_seconds(),
                    source.timedata.uncertainty.to_seconds(),
                    source.timedata.delay.to_seconds(),
                );
                println!(
                    "    poll interval: {:.0}s, missing polls: {}",
                    source.poll_interval.as_duration().to_seconds(),
                    source.unanswered_polls,
                );
                println!(
                    "    root dispersion: {:.6}s, root delay:{:.6}s",
                    source.timedata.remote_uncertainty.to_seconds(),
                    source.timedata.remote_delay.to_seconds()
                );
                if let Some(nts_cookies) = source.nts_cookies {
                    println!(
                        "    NTS cookies: {}/{} available",
                        nts_cookies,
                        ntp_proto::MAX_COOKIES
                    );
                }
            }
            println!();
            println!("Servers:");
            for server in &output.servers {
                println!(
                    "{}: received {}, accepted {}, errors {}",
                    server.address,
                    server.stats.received_packets.get(),
                    server.stats.accepted_packets.get(),
                    server.stats.response_send_errors.get()
                );
                println!(
                    "    denied {}, nts nak {}, rate limited {}, ignored {}",
                    server.stats.denied_packets.get(),
                    server.stats.nts_nak_packets.get(),
                    server.stats.rate_limited_packets.get(),
                    server.stats.ignored_packets.get()
                );
            }
        }
        Format::Prometheus => {
            let mut buf = String::new();
            if let Err(e) = crate::metrics::format_state(&mut buf, &output) {
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
    use std::path::Path;

    use crate::daemon::{
        config::ObservabilityConfig,
        sockets::{create_unix_socket_with_permissions, write_json},
    };

    use super::*;

    async fn write_socket_helper(
        command: Format,
        socket_name: &str,
    ) -> std::io::Result<Result<ExitCode, std::io::Error>> {
        let config: ObservabilityConfig = Default::default();

        // be careful with copying: tests run concurrently and should use a unique socket name!
        let path = std::env::temp_dir().join(socket_name);
        if path.exists() {
            std::fs::remove_file(&path).unwrap();
        }

        let permissions: std::fs::Permissions =
            PermissionsExt::from_mode(config.observation_permissions);

        let sources_listener = create_unix_socket_with_permissions(&path, permissions)?;

        let fut = super::print_state(command, path);
        let handle = tokio::spawn(fut);

        let value = ObservableState {
            program: Default::default(),
            system: Default::default(),
            sources: vec![],
            servers: vec![],
        };

        let (mut stream, _addr) = sources_listener.accept().await?;
        write_json(&mut stream, &value).await?;

        let result = handle.await.unwrap();

        Ok(result)
    }

    #[tokio::test]
    async fn test_control_socket_source() -> std::io::Result<()> {
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
    async fn test_control_socket_source_invalid_input() -> std::io::Result<()> {
        let config: ObservabilityConfig = Default::default();

        // be careful with copying: tests run concurrently and should use a unique socket name!
        let path = std::env::temp_dir().join("ntp-test-stream-10");
        if path.exists() {
            std::fs::remove_file(&path).unwrap();
        }

        let permissions: std::fs::Permissions =
            PermissionsExt::from_mode(config.observation_permissions);

        let sources_listener = create_unix_socket_with_permissions(&path, permissions)?;

        let fut = super::print_state(Format::Plain, path);
        let handle = tokio::spawn(fut);

        let value = 42u32;

        let (mut stream, _addr) = sources_listener.accept().await?;
        write_json(&mut stream, &value).await?;

        let result = handle.await.unwrap();

        assert_eq!(
            format!("{:?}", result.unwrap()),
            format!("{:?}", ExitCode::FAILURE)
        );

        Ok(())
    }

    const BINARY: &str = "/usr/bin/ntp-ctl";

    #[test]
    fn cli_config() {
        let config_str = "/foo/bar/ntp.toml";
        let config = Path::new(config_str);
        let arguments = &[BINARY, "-c", config_str];

        let options = NtpCtlOptions::try_parse_from(arguments).unwrap();
        assert_eq!(options.config.unwrap().as_path(), config);
    }

    #[test]
    fn cli_format() {
        let arguments = &[BINARY, "-f", "plain"];
        let options = NtpCtlOptions::try_parse_from(arguments).unwrap();
        assert_eq!(options.format, Format::Plain);

        let arguments = &[BINARY, "-f", "prometheus"];
        let options = NtpCtlOptions::try_parse_from(arguments).unwrap();
        assert_eq!(options.format, Format::Prometheus);

        let arguments = &[BINARY, "-f", "yaml"];
        let err = NtpCtlOptions::try_parse_from(arguments).unwrap_err();
        assert_eq!(err, "invalid format option provided: yaml");
    }
}
