#![forbid(unsafe_code)]

use clap::Parser;
use ntp_daemon::config::{CmdArgs, Config};
use std::ops::Deref;
use std::os::unix::fs::PermissionsExt;
use std::{error::Error, sync::Arc};
use tokio::io::AsyncWriteExt;
use tokio::net::{UnixListener, UnixStream};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = CmdArgs::parse();
    let has_log_override = args.log_filter.is_some();
    let log_filter = args.log_filter.unwrap_or_else(|| EnvFilter::new("info"));

    // Setup some basic tracing now so we are
    // able to log errors when loading the full
    // configuration.
    let finish_tracing_init = ntp_daemon::tracing::init(log_filter);

    let mut config = Config::from_args(args.config, args.peers).await?;

    // Sentry has a guard we need to keep alive,
    // so store it. The compiler will optimize
    // this away when not using sentry.
    let _guard = finish_tracing_init(&mut config, has_log_override)?;

    let peers_reader = Arc::new(tokio::sync::RwLock::new(Vec::new()));
    let peers_writer = peers_reader.clone();

    std::fs::remove_dir_all("/run/ntpd-rs")?;
    std::fs::create_dir("/run/ntpd-rs")?;

    let peers_listener = UnixListener::bind("/run/ntpd-rs/observe")?;

    // this binary needs to run as root to be able to adjust the system clock
    // directories inherit root permissions, but the client should not need elevated
    // permissions to read from the socket. So we explicitly set the permissions
    let permissions: std::fs::Permissions = PermissionsExt::from_mode(0o777);

    std::fs::set_permissions("/run/ntpd-rs", permissions.clone())?;
    std::fs::set_permissions("/run/ntpd-rs/observe", permissions)?;

    let handle = tokio::spawn(async move {
        ntp_daemon::spawn(&config.system, &config.peers, peers_writer).await
    });

    // to prevent the handle being consumed in the first loop iteration
    tokio::pin!(handle);

    loop {
        tokio::select! {
            done = (&mut handle) => {
                return Ok(done??);
            }
            accept = peers_listener.accept() => {
                let (stream, _addr) = accept?;

                let buffer = {
                    let state = peers_reader.read().await;

                    serde_json::to_vec(state.deref()).unwrap()
                };

                write_to_unix_socket(stream, &buffer).await?;
            }
        }
    }
}

async fn write_to_unix_socket(mut stream: UnixStream, bytes: &[u8]) -> std::io::Result<()> {
    loop {
        // Wait for the socket to be writable
        stream.writable().await?;

        // Try to write data, this may still fail with `WouldBlock`
        // if the readiness event is a false positive.
        match stream.try_write(bytes) {
            Ok(_) => {
                return stream.shutdown().await;
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                continue;
            }
            Err(e) => {
                return Err(e);
            }
        }
    }
}
