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

enum PrintState {
    Peers,
    System,
    Prometheus,
}

async fn validate(cli: Cli) -> std::io::Result<ExitCode> {
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

pub async fn main() -> std::io::Result<ExitCode> {
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

    match cli.command {
        Command::Peers => print_state(PrintState::Peers, observation).await,
        Command::System => print_state(PrintState::System, observation).await,
        Command::Prometheus => print_state(PrintState::Prometheus, observation).await,
        Command::Config(config_update) => update_config(configuration, config_update).await,
        Command::Validate => unreachable!(),
    }
}

async fn print_state(
    print: PrintState,
    observe_socket: PathBuf,
) -> Result<ExitCode, std::io::Error> {
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
        PrintState::Peers => {
            // Unwrap here is fine as our serializer is infallible.
            println!("{}", serde_json::to_string_pretty(&output.peers).unwrap());
        }
        PrintState::System => {
            // Unwrap here is fine as our serializer is infallible.
            println!("{}", serde_json::to_string_pretty(&output.system).unwrap());
        }
        PrintState::Prometheus => {
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

async fn update_config(
    configuration_socket: PathBuf,
    config_update: ConfigUpdate,
) -> Result<ExitCode, std::io::Error> {
    let mut stream = match tokio::net::UnixStream::connect(&configuration_socket).await {
        Ok(stream) => stream,
        Err(e) => {
            eprintln!(
                "Could not open socket at {}: {e}",
                configuration_socket.display(),
            );
            return Ok(ExitCode::FAILURE);
        }
    };

    match ntp_daemon::sockets::write_json(&mut stream, &config_update).await {
        Ok(_) => Ok(ExitCode::SUCCESS),
        Err(e) => {
            eprintln!("Failed to update configuration: {e}");

            Ok(ExitCode::FAILURE)
        }
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
        command: PrintState,
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
        let result = write_socket_helper(PrintState::Peers, "ntp-test-stream-6").await?;

        assert_eq!(
            format!("{:?}", result.unwrap()),
            format!("{:?}", ExitCode::SUCCESS)
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_control_socket_system() -> std::io::Result<()> {
        // be careful with copying: tests run concurrently and should use a unique socket name!
        let result = write_socket_helper(PrintState::System, "ntp-test-stream-7").await?;

        assert_eq!(
            format!("{:?}", result.unwrap()),
            format!("{:?}", ExitCode::SUCCESS)
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_control_socket_prometheus() -> std::io::Result<()> {
        // be careful with copying: tests run concurrently and should use a unique socket name!
        let result = write_socket_helper(PrintState::Prometheus, "ntp-test-stream-8").await?;

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

        let fut = super::update_config(path, update.clone());
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

        let fut = super::print_state(PrintState::Peers, path);
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
