#![forbid(unsafe_code)]

use clap::Parser;
use ntp_daemon::config::{CmdArgs, Config};
use ntp_daemon::{Observe, Peers};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::{error::Error, sync::Arc};
use tokio::net::UnixListener;
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
        tokio::spawn(peer_state_observer(socket_directory, peers_reader.clone()));

    // exit if any of the tasks has completed
    tokio::select! {
        done = main_loop_handle => Ok(done??),
        done = peer_state_handle => Ok(done??),
    }
}

async fn peer_state_observer(
    socket_directory: PathBuf,
    peers_reader: Arc<tokio::sync::RwLock<Peers>>,
) -> std::io::Result<()> {
    let socket_directory = &socket_directory;

    // create the path if it does not exist
    std::fs::create_dir_all(socket_directory)?;

    let observe_socket_path = socket_directory.join("observe");
    std::fs::remove_file(&observe_socket_path)?;
    let peers_listener = UnixListener::bind(&observe_socket_path)?;

    // this binary needs to run as root to be able to adjust the system clock.
    // by default, the socket inherits root permissions, but the client should not need
    // elevated permissions to read from the socket. So we explicitly set the permissions
    let permissions: std::fs::Permissions = PermissionsExt::from_mode(0o777);
    std::fs::set_permissions(&observe_socket_path, permissions)?;

    let mut observed = Vec::with_capacity(8);
    let mut msg = Vec::with_capacity(16 * 1024);

    loop {
        let (mut stream, _addr) = peers_listener.accept().await?;

        let operation: Observe = ntp_daemon::sockets::read_json(&mut stream, &mut msg).await?;

        match operation {
            Observe::Peers => {
                {
                    let state = peers_reader.read().await;

                    observed.clear();
                    observed.extend(state.observe());
                }

                ntp_daemon::sockets::write_json(&mut stream, &observed).await?;
            }
            Observe::System => todo!(),
        }
    }
}
