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
}

pub async fn main() -> Result<ExitCode, Box<dyn std::error::Error>> {
    let cli = Cli::parse();

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
        Command::Peers | Command::System | Command::Prometheus => &observation,
        Command::Config(_) => &configuration,
    };

    let mut stream = match tokio::net::UnixStream::connect(socket_path).await {
        Ok(stream) => stream,
        Err(e) => {
            eprintln!("Could not open socket at {}: {}", socket_path.display(), e);
            return Ok(ExitCode::FAILURE);
        }
    };

    match cli.command {
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
            let mut stream = tokio::net::UnixStream::connect(observation).await?;

            let mut msg = Vec::with_capacity(16 * 1024);
            match ntp_daemon::sockets::read_json::<ObservableState>(&mut stream, &mut msg).await {
                Ok(output) => {
                    let metrics = Metrics::default();
                    metrics.fill(&output);
                    let registry = metrics.registry();
                    let mut buf = String::new();
                    prometheus_client::encoding::text::encode(&mut buf, &registry)?;
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
    }
}
