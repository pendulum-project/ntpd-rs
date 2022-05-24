#![forbid(unsafe_code)]

use ntp_proto::SystemConfig;
use std::error::Error;

#[cfg(feature = "sentry")]
fn init_tracing() -> sentry::ClientInitGuard {
    use tracing_subscriber::{prelude::*, EnvFilter};

    let guard = sentry::init(sentry::ClientOptions {
        // Set this a to lower value in production
        traces_sample_rate: 1.0,
        ..sentry::ClientOptions::default()
    });

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_filter(EnvFilter::from_default_env()))
        .with(sentry_tracing::layer())
        .init();

    guard
}

#[cfg(not(feature = "sentry"))]
fn init_tracing() {
    tracing_subscriber::fmt::init();
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Sentry has a guard we need to keep alive,
    // so store it. The compiler will optimize
    // this away when not using sentry.
    let _guard = init_tracing();

    let config = SystemConfig::default();

    let peer_addresses = [
        "0.pool.ntp.org:123",
        "1.pool.ntp.org:123",
        "2.pool.ntp.org:123",
        "3.pool.ntp.org:123",
    ];

    ntp_daemon::spawn(&config, &peer_addresses).await
}
