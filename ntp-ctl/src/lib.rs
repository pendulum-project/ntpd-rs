#![forbid(unsafe_code)]

use std::{path::PathBuf, process::ExitCode};

use clap::{Parser, Subcommand};
use ntp_daemon::{Config, ConfigUpdate, ObservableState};
use ntp_metrics_exporter::Metrics;

#[derive(Parser)]
#[command(version = "0.2.0", about = "Query and configure the ntpd-rs daemon")]
#[command(arg_required_else_help(true))]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Which configuration file to read the socket paths from
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Path of the observation socket
    #[arg(short, long)]
    observation_socket: Option<PathBuf>,

    /// Path of the configuration socket
    #[arg(short = 's', long)]
    configuration_socket: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Command {
    #[command(about = "Information about the peers the daemon is currently connected with")]
    Peers,
    #[command(about = "Information about the state of the daemon itself")]
    System,
    #[command(
        about = "Information about the state of the daemon and peers in the prometheus export format"
    )]
    Prometheus,
    #[command(about = "Adjust configuration (e.g. loglevel) of the daemon")]
    Config(ConfigUpdate),
    #[command(about = "Validate configuration")]
    Validate,
}

async fn validate(cli: Cli) -> Result<ExitCode, Box<dyn std::error::Error>> {
    match Config::from_args(cli.config, vec![], vec![]).await {
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

pub async fn main() -> Result<ExitCode, Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    if matches!(cli.command, Command::Validate) {
        return validate(cli).await;
    }

    let config = Config::from_args(cli.config, vec![], vec![]).await;

    if let Err(ref e) = config {
        println!("Warning: Unable to load configuration file: {e}");
    }

    let config = config.unwrap_or_default();

    let observation = cli
        .observation_socket
        .or(config.observe.path)
        .unwrap_or_else(|| PathBuf::from("/run/ntpd-rs/observe"));

    let configuration = cli
        .configuration_socket
        .or(config.configure.path)
        .unwrap_or_else(|| PathBuf::from("/run/ntpd-rs/configure"));

    let socket_path = match cli.command {
        Command::Peers | Command::System | Command::Prometheus => observation,
        Command::Config(_) => configuration,
        Command::Validate => unreachable!(),
    };

    Ok(run(cli.command, socket_path).await?)
}

async fn run(command: Command, socket_path: PathBuf) -> Result<ExitCode, std::io::Error> {
    let mut stream = match tokio::net::UnixStream::connect(&socket_path).await {
        Ok(stream) => stream,
        Err(e) => {
            eprintln!("Could not open socket at {}: {}", socket_path.display(), e);
            return Ok(ExitCode::FAILURE);
        }
    };

    match command {
        Command::Peers => {
            let mut msg = Vec::with_capacity(16 * 1024);
            match ntp_daemon::sockets::read_json::<ObservableState>(&mut stream, &mut msg).await {
                Ok(output) => {
                    // Unwrap here is fine as our serializer is infallible.
                    println!("{}", serde_json::to_string_pretty(&output.peers).unwrap());

                    Ok(ExitCode::SUCCESS)
                }
                Err(e) => {
                    eprintln!("Failed to read state from observation socket: {e}");

                    Ok(ExitCode::FAILURE)
                }
            }
        }
        Command::System => {
            let mut msg = Vec::with_capacity(16 * 1024);
            match ntp_daemon::sockets::read_json::<ObservableState>(&mut stream, &mut msg).await {
                Ok(output) => {
                    // Unwrap here is fine as our serializer is infallible.
                    println!("{}", serde_json::to_string_pretty(&output.system).unwrap());

                    Ok(ExitCode::SUCCESS)
                }
                Err(e) => {
                    eprintln!("Failed to read state from observation socket: {e}");

                    Ok(ExitCode::FAILURE)
                }
            }
        }
        Command::Prometheus => {
            let mut msg = Vec::with_capacity(16 * 1024);
            match ntp_daemon::sockets::read_json::<ObservableState>(&mut stream, &mut msg).await {
                Ok(output) => {
                    let metrics = Metrics::default();
                    metrics.fill(&output);
                    let registry = metrics.registry();
                    let mut buf = String::new();

                    if let Err(e) = prometheus_client::encoding::text::encode(&mut buf, &registry) {
                        eprintln!("Failed to encode prometheus data: {e}");

                        return Ok(ExitCode::FAILURE);
                    }

                    println!("{buf}");

                    Ok(ExitCode::SUCCESS)
                }
                Err(e) => {
                    eprintln!("Failed to read state from observation socket: {e}");

                    Ok(ExitCode::FAILURE)
                }
            }
        }
        Command::Config(config_update) => {
            match ntp_daemon::sockets::write_json(&mut stream, &config_update).await {
                Ok(_) => Ok(ExitCode::SUCCESS),
                Err(e) => {
                    eprintln!("Failed to update configuration: {e}");

                    Ok(ExitCode::FAILURE)
                }
            }
        }
        Command::Validate => unreachable!(), //run should never be called for validate
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::prelude::PermissionsExt;

    use ntp_daemon::{
        config::ObserveConfig,
        sockets::{create_unix_socket, read_json, write_json},
    };

    use super::*;

    async fn write_socket_helper(
        command: Command,
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

        let fut = super::run(command, path);
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
        let result = write_socket_helper(Command::Peers, "ntp-test-stream-6").await?;

        assert_eq!(
            format!("{:?}", result.unwrap()),
            format!("{:?}", ExitCode::SUCCESS)
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_control_socket_system() -> std::io::Result<()> {
        // be careful with copying: tests run concurrently and should use a unique socket name!
        let result = write_socket_helper(Command::System, "ntp-test-stream-7").await?;

        assert_eq!(
            format!("{:?}", result.unwrap()),
            format!("{:?}", ExitCode::SUCCESS)
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_control_socket_prometheus() -> std::io::Result<()> {
        // be careful with copying: tests run concurrently and should use a unique socket name!
        let result = write_socket_helper(Command::Prometheus, "ntp-test-stream-8").await?;

        assert_eq!(
            format!("{:?}", result.unwrap()),
            format!("{:?}", ExitCode::SUCCESS)
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_control_socket_config() -> std::io::Result<()> {
        let config: ObserveConfig = Default::default();

        // be careful with copying: tests run concurrently and should use a unique socket name!
        let path = std::env::temp_dir().join("ntp-test-stream-9");
        if path.exists() {
            std::fs::remove_file(&path).unwrap();
        }

        let peers_listener = create_unix_socket(&path)?;

        let permissions: std::fs::Permissions = PermissionsExt::from_mode(config.mode);
        std::fs::set_permissions(&path, permissions)?;

        let update = ConfigUpdate {
            log_filter: Some("foo".to_string()),
            panic_threshold: Some(0.123),
        };

        let fut = super::run(Command::Config(update.clone()), path);
        let handle = tokio::spawn(fut);

        let (mut stream, _addr) = peers_listener.accept().await?;
        let mut msg = Vec::with_capacity(16 * 1024);
        let actual_update = read_json::<ConfigUpdate>(&mut stream, &mut msg).await?;

        let result = handle.await.unwrap();

        assert_eq!(
            format!("{:?}", result.unwrap()),
            format!("{:?}", ExitCode::SUCCESS)
        );

        assert_eq!(update, actual_update);

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

        let fut = super::run(Command::Peers, path);
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
