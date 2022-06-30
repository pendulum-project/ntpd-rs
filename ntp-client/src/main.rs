#![forbid(unsafe_code)]

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use ntp_daemon::{Config, ConfigUpdate, ObservablePeerState, ObservableState};
use ntp_proto::{NtpDuration, PeerStatistics, PollInterval, SystemSnapshot};
use serde::Serialize;

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
    #[clap(about = "Adjust configuration (e.g. loglevel) of the daemon")]
    Config(ConfigUpdate),
}

trait DisplayPrometheus {
    fn write_prometheus(
        &self,
        f: &mut impl std::io::Write,
        labels: &[(&str, &str)],
    ) -> std::io::Result<()>;

    fn format(
        &self,
        f: &mut impl std::io::Write,
        namespace: Option<&str>,
        name: &str,
        labels: &[(&str, &str)],
        value: impl std::fmt::Display,
    ) -> std::io::Result<()> {
        if let Some(namespace) = namespace {
            write!(f, "{namespace}_")?;
        }

        write!(f, "{name} ")?;

        if !labels.is_empty() {
            write!(f, "{{")?;

            let mut it = labels.iter().peekable();

            while let Some((key, value)) = it.next() {
                write!(f, "{key} = \"{value}\"")?;

                if it.peek().is_some() {
                    write!(f, ", ")?;
                }
            }

            write!(f, "}} ")?;
        }

        writeln!(f, "{value}")
    }
}

impl DisplayPrometheus for SystemSnapshot {
    fn write_prometheus(
        &self,
        f: &mut impl std::io::Write,
        labels: &[(&str, &str)],
    ) -> std::io::Result<()> {
        writeln!(f, "# TYPE ntp_system_poll_interval gauge")?;

        self.format(
            f,
            Some("ntp_system"),
            "poll_interval",
            labels,
            self.poll_interval.as_duration().to_seconds(),
        )?;

        writeln!(f, "# TYPE ntp_system_precision gauge")?;

        self.format(
            f,
            Some("ntp_system"),
            "precision",
            labels,
            self.precision.to_seconds(),
        )?;

        writeln!(f, "# TYPE ntp_system_leap_indicator gauge")?;
        let mut labels = labels.to_owned();
        let leap_indicator = format!("{:?}", self.leap_indicator);
        labels.push(("type", &leap_indicator));
        self.format(
            f,
            Some("ntp_system"),
            "leap_indicator",
            &labels,
            self.leap_indicator as u8,
        )?;

        Ok(())
    }
}

impl DisplayPrometheus for ObservablePeerState {
    fn write_prometheus(
        &self,
        f: &mut impl std::io::Write,
        _labels: &[(&str, &str)],
    ) -> std::io::Result<()> {
        match self {
            ObservablePeerState::Nothing => (),
            ObservablePeerState::Observable {
                statistics,
                reachability,
                uptime,
                poll_interval,
                peer_id,
            } => {
                let peer_id = u32::from_be_bytes(peer_id.to_bytes());
                let peer_id = format!("{}", peer_id);
                let labels = &[("peer_id", peer_id.as_str())] as &[_];
                statistics.write_prometheus(f, labels)?;

                self.format(
                    f,
                    Some("ntp_peer"),
                    "uptime",
                    labels,
                    uptime.as_secs() as f64 + uptime.subsec_nanos() as f64 * 1e-9,
                )?;

                self.format(
                    f,
                    Some("ntp_peer"),
                    "poll_interval",
                    labels,
                    poll_interval.as_secs() as f64 + poll_interval.subsec_nanos() as f64 * 1e-9,
                )?;

                self.format(
                    f,
                    Some("ntp_peer"),
                    "reachability_status",
                    labels,
                    reachability.is_reachable() as u8,
                )?;

                let result = if reachability.is_reachable() {
                    "success"
                } else {
                    "timeout"
                };
                let labels = &[("peer_id", peer_id.as_str()), ("result", result)] as &[_];
                self.format(
                    f,
                    Some("ntp_peer"),
                    "reachability_unanswered_polls",
                    labels,
                    reachability.unanswered_polls(),
                )?;
            }
        }

        Ok(())
    }
}

impl DisplayPrometheus for PeerStatistics {
    fn write_prometheus(
        &self,
        f: &mut impl std::io::Write,
        _labels: &[(&str, &str)],
    ) -> std::io::Result<()> {
        let PeerStatistics {
            offset,
            delay,
            dispersion,
            jitter,
        } = self;

        writeln!(f, "ntp_peer_offset {}", offset.to_seconds())?;
        writeln!(f, "ntp_peer_delay {}", delay.to_seconds())?;
        writeln!(f, "ntp_peer_dispersion {}", dispersion.to_seconds())?;
        writeln!(f, "ntp_peer_jitter {}", *jitter)?;

        Ok(())
    }
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

            // println!("{}", serde_json::to_string_pretty(&output.peers)?);

            for peer in output.peers.iter() {
                peer.write_prometheus(&mut std::io::stdout(), &[])?;
            }

            0
        }
        Command::System => {
            let mut stream = tokio::net::UnixStream::connect(observation).await?;

            let mut msg = Vec::with_capacity(16 * 1024);
            let output: ObservableState =
                ntp_daemon::sockets::read_json(&mut stream, &mut msg).await?;

            // println!("{}", serde_json::to_string_pretty(&output.system)?);

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
