use clap::{Parser, Subcommand};
use ntp_daemon::ObservableState;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[clap(version = "0.1.0", about = "Query and configure the NTPD-rs daemon")]
#[clap(arg_required_else_help(true))]
struct Cli {
    #[clap(subcommand)]
    command: Command,
}

fn parse_env_filter(input: &str) -> Result<EnvFilter, tracing_subscriber::filter::ParseError> {
    EnvFilter::builder().with_regex(false).parse(input)
}

#[derive(Subcommand)]
enum Command {
    #[clap(about = "Information about the peers the daemon is currently connected with")]
    Peers,
    #[clap(about = "Information about the state of the daemon itself")]
    System,
    #[clap(about = "Adjust configuration (e.g. loglevel) of the daemon")]
    Config {
        /// Change the log filter
        #[clap(long, short, global = true, parse(try_from_str = parse_env_filter), env = "NTP_LOG")]
        log_filter: Option<EnvFilter>,
    },
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

            dbg!(output.peers);

            0
        }
        Command::System => {
            let mut stream = tokio::net::UnixStream::connect("/run/ntpd-rs/observe").await?;

            let mut msg = Vec::with_capacity(16 * 1024);
            let output: ObservableState =
                ntp_daemon::sockets::read_json(&mut stream, &mut msg).await?;

            dbg!(output.system);

            0
        }
        Command::Config { log_filter } => {
            if let Some(log_filter) = log_filter {
                let mut stream = tokio::net::UnixStream::connect("/run/ntpd-rs/configure").await?;

                // convert to string because `EnvFilter` is not `Serialize`. But we did validate it
                // already, so any parse errors are reported in the client and invalid filters
                // don't make it into the daemon
                let msg = ntp_daemon::config::dynamic::Configure::LogLevel {
                    filter: log_filter.to_string(),
                };

                ntp_daemon::sockets::write_json(&mut stream, &msg).await?;
            }

            0
        }
    };

    std::process::exit(exit_code);
}
