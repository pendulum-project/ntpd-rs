#![forbid(unsafe_code)]

use clap::Parser;
use ntp_daemon::config::{CmdArgs, Config};
use ntp_daemon::Peers;
use std::{error::Error, sync::Arc};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = CmdArgs::parse();
    let has_log_override = args.log_filter.is_some();
    let log_filter = args.log_filter.unwrap_or_else(|| EnvFilter::new("info"));

    // Setup some basic tracing now so we are able
    // to log errors when loading the full configuration.
    let finish_tracing_init = ntp_daemon::tracing::init(log_filter);

    let mut config = Config::from_args(args.config, args.peers).await?;

    // Sentry has a guard we need to keep alive, so store it.
    // The compiler will optimize this away when not using sentry.
    let _guard = finish_tracing_init(&mut config, has_log_override)?;

    let peers_reader = Arc::new(tokio::sync::RwLock::new(Peers::default()));
    let peers_writer = peers_reader.clone();

    let socket_directory = config.sockets;

    let main_loop_handle = tokio::spawn(async move {
        ntp_daemon::spawn(&config.system, &config.peers, peers_writer).await
    });

    let peer_state_handle =
        ntp_daemon::observer::spawn(socket_directory, peers_reader.clone()).await;

    // exit if any of the tasks has completed
    tokio::select! {
        done = main_loop_handle => Ok(done??),
        done = peer_state_handle => Ok(done??),
    }
}
