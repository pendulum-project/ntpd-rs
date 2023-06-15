//! This crate contains the OpenMetrics/Prometheus metrics exporter for ntpd-rs, but
//! is not intended as a public interface at this time. It follows the same version
//! as the main ntpd-rs crate, but that version is not intended to give any
//! stability guarantee. Use at your own risk.
//!
//! Please visit the [ntpd-rs](https://github.com/pendulum-project/ntpd-rs) project
//! for more information.
#![forbid(unsafe_code)]

mod metrics;

pub use metrics::Metrics;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

use std::{fmt::Write, net::SocketAddr, path::PathBuf};

use clap::Parser;
use ntp_daemon::{Config, ObservableState};

#[derive(Parser)]
#[command(version = "0.2.0", about = "Serve ntpd-rs openmetrics via http")]
struct Cli {
    /// Which configuration file to read the socket paths from
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Path of the observation socket
    #[arg(short, long)]
    observation_socket: Option<PathBuf>,

    #[arg(short = 'l', long = "listen", default_value = "127.0.0.1:9975")]
    listen_socket: SocketAddr,
}

pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    let config = Config::from_args(cli.config, vec![], vec![]).await;

    if let Err(ref e) = config {
        println!("Warning: Unable to load configuration file: {e}");
    }

    let config = config.unwrap_or_default();

    let observation_socket_path = match cli.observation_socket {
        Some(path) => path,
        None => match config.observe.path {
            Some(path) => path,
            None => "/run/ntpd-rs/observe".into(),
        },
    };

    println!("starting ntp-metrics-exporter on {}", &cli.listen_socket);

    let listener = TcpListener::bind(cli.listen_socket).await?;

    loop {
        let (mut tcp_stream, _) = listener.accept().await?;

        let mut stream = tokio::net::UnixStream::connect(&observation_socket_path).await?;
        let mut msg = Vec::with_capacity(16 * 1024);
        let output: ObservableState = ntp_daemon::sockets::read_json(&mut stream, &mut msg).await?;
        let metrics = Metrics::default();
        metrics.fill(&output);
        let registry = metrics.registry();

        let mut content = String::with_capacity(4 * 1024);
        prometheus_client::encoding::text::encode(&mut content, &registry)?;

        let mut buf = String::with_capacity(4 * 1024);

        // headers
        buf.push_str("HTTP/1.1 200 OK\r\n");
        buf.push_str("content-type: text/plain\r\n");
        write!(buf, "content-length: {}\r\n\r\n", content.len()).unwrap();

        // actual content
        buf.push_str(&content);

        tcp_stream.write_all(buf.as_bytes()).await.unwrap();
    }
}
