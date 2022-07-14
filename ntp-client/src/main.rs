#![forbid(unsafe_code)]

mod prometheus;

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use ntp_daemon::{Config, ConfigUpdate, ObservableState};
use prometheus::DisplayPrometheus;

#[derive(Parser)]
#[clap(version = "0.1.0", about = "Query and configure the NTPD-rs daemon")]
#[clap(arg_required_else_help(true))]
struct Cli {
    #[clap(subcommand)]
    command: Command,

    /// Which configuration file to read the socket paths from
    #[clap(short, long)]
    config: Option<PathBuf>,

    /// Path of the observation socket
    #[clap(short, long)]
    observation_socket: Option<PathBuf>,

    /// Path of the configuration socket
    #[clap(short = 's', long)]
    configuration_socket: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Command {
    #[clap(about = "Information about the peers the daemon is currently connected with")]
    Peers,
    #[clap(about = "Information about the state of the daemon itself")]
    System,
    #[clap(
        about = "Information about the state of the daemon and peers in the prometheus export format"
    )]
    Prometheus,
    #[clap(about = "Adjust configuration (e.g. loglevel) of the daemon")]
    Config(ConfigUpdate),
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let cli = Cli::parse();

    let config = Config::from_args(cli.config, vec![]).await;

    if let Err(ref e) = config {
        println!("Warning: Unable to load configuration file: {}", e);
    }

    let config = config.unwrap_or_default();

    let observation = match cli.observation_socket {
        Some(path) => path,
        None => match config.observe.path {
            Some(path) => path,
            None => "/run/ntpd-rs/observe".into(),
        },
    };

    let configuration = match cli.configuration_socket {
        Some(path) => path,
        None => match config.configure.path {
            Some(path) => path,
            None => "/run/ntpd-rs/configure".into(),
        },
    };

    let exit_code = match cli.command {
        Command::Peers => {
            let mut stream = tokio::net::UnixStream::connect(observation).await?;

            let mut msg = Vec::with_capacity(16 * 1024);
            let output: ObservableState =
                ntp_daemon::sockets::read_json(&mut stream, &mut msg).await?;

            println!("{}", serde_json::to_string_pretty(&output.peers)?);

            0
        }
        Command::System => {
            let mut stream = tokio::net::UnixStream::connect(observation).await?;

            let mut msg = Vec::with_capacity(16 * 1024);
            let output: ObservableState =
                ntp_daemon::sockets::read_json(&mut stream, &mut msg).await?;

            println!("{}", serde_json::to_string_pretty(&output.system)?);

            0
        }
        Command::Prometheus => {
            let mut stream = tokio::net::UnixStream::connect(observation).await?;

            let mut msg = Vec::with_capacity(16 * 1024);
            let output: ObservableState =
                ntp_daemon::sockets::read_json(&mut stream, &mut msg).await?;

            println!("{}", prometheus::PEER_TYPE_HEADERS);

            for peer in output.peers.iter() {
                peer.write_prometheus(&mut std::io::stdout(), &[])?;
            }

            output
                .system
                .write_prometheus(&mut std::io::stdout(), &[])?;

            0
        }
        Command::Config(config_update) => {
            let mut stream = tokio::net::UnixStream::connect(configuration).await?;

            ntp_daemon::sockets::write_json(&mut stream, &config_update).await?;

            0
        }
    };

    std::process::exit(exit_code);
}
