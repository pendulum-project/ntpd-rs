#![forbid(unsafe_code)]

use clap::{Parser, Subcommand};
use ntp_daemon::{ConfigUpdate, ObservableState};

#[derive(Parser)]
#[clap(version = "0.1.0", about = "Query and configure the NTPD-rs daemon")]
#[clap(arg_required_else_help(true))]
struct Cli {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    #[clap(about = "Information about the peers the daemon is currently connected with")]
    Peers,
    #[clap(about = "Information about the state of the daemon itself")]
    System,
    #[clap(about = "Adjust configuration (e.g. loglevel) of the daemon")]
    Config(ConfigUpdate),
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let cli = Cli::parse();

    let exit_code = match cli.command {
        Command::Peers => {
            let mut stream = tokio::net::UnixStream::connect("/run/ntpd-rs/observe").await?;

            let mut msg = Vec::with_capacity(16 * 1024);
            let output: ObservableState =
                ntp_daemon::sockets::read_json(&mut stream, &mut msg).await?;

            println!("{}", serde_json::to_string_pretty(&output.peers)?);

            0
        }
        Command::System => {
            let mut stream = tokio::net::UnixStream::connect("/run/ntpd-rs/observe").await?;

            let mut msg = Vec::with_capacity(16 * 1024);
            let output: ObservableState =
                ntp_daemon::sockets::read_json(&mut stream, &mut msg).await?;

            println!("{}", serde_json::to_string_pretty(&output.system)?);

            0
        }
        Command::Config(config_update) => {
            let mut stream = tokio::net::UnixStream::connect("/run/ntpd-rs/configure").await?;

            ntp_daemon::sockets::write_json(&mut stream, &config_update).await?;

            0
        }
    };

    std::process::exit(exit_code);
}
