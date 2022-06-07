use clap::{Arg, Command};
use ntp_daemon::ObservablePeerState;
use ntp_proto::SystemSnapshot;

pub const CMD_PEERS: &str = "peers";
pub const CMD_SYSTEM: &str = "system";
pub const CMD_CONFIG: &str = "config";

pub const FLAG_LOG_FILTER: &str = "log-filter";

fn build_app<'a>() -> Command<'a> {
    Command::new("client")
        // .version(concatcp!(VERSION, "\n"))
        // .about("Runs the given .roc file, if there are no compilation errors.\nUse one of the SUBCOMMANDS below to do something else!")
        .subcommand(
            Command::new(CMD_PEERS)
                .about("Information about the peers the daemon is currently connected with"),
        )
        .subcommand(
            Command::new(CMD_SYSTEM).about("Information about the state of the daemon itself"),
        )
        .subcommand(
            Command::new(CMD_CONFIG)
                .about("Adjust configuration (e.g. loglevel) of the daemon")
                .arg(
                    Arg::new(FLAG_LOG_FILTER)
                        .long(FLAG_LOG_FILTER)
                        .help("Change the log filter")
                        .default_value("error")
                        .required(false),
                ),
        )
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let matches = build_app().get_matches();

    let exit_code = match matches.subcommand() {
        None => return build_app().print_help(),
        Some((CMD_PEERS, _matches)) => {
            let mut stream = tokio::net::UnixStream::connect("/run/ntpd-rs/observe").await?;

            ntp_daemon::sockets::write_json(&mut stream, &ntp_daemon::Observe::Peers).await?;

            let mut msg = Vec::with_capacity(16 * 1024);
            let output: Vec<ObservablePeerState> =
                ntp_daemon::sockets::read_json(&mut stream, &mut msg).await?;

            dbg!(output);

            0
        }
        Some((CMD_SYSTEM, _matches)) => {
            let mut stream = tokio::net::UnixStream::connect("/run/ntpd-rs/observe").await?;

            ntp_daemon::sockets::write_json(&mut stream, &ntp_daemon::Observe::System).await?;

            let mut msg = Vec::with_capacity(16 * 1024);
            let output: SystemSnapshot =
                ntp_daemon::sockets::read_json(&mut stream, &mut msg).await?;

            dbg!(output);

            0
        }
        Some((CMD_CONFIG, matches)) => {
            if let Some(filter) = matches.value_of(FLAG_LOG_FILTER) {
                let mut stream = tokio::net::UnixStream::connect("/run/ntpd-rs/configure").await?;

                let msg = ntp_daemon::config::dynamic::Configure::LogLevel {
                    filter: filter.to_owned(),
                };

                ntp_daemon::sockets::write_json(&mut stream, &msg).await?;
            }

            0
        }
        _ => unreachable!(),
    };

    std::process::exit(exit_code);
}
