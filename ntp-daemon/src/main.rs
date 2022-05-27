#![forbid(unsafe_code)]

use clap::Parser;
use ntp_daemon::config::{CmdArgs, Config};
use std::error::Error;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = CmdArgs::parse();
    let has_log_override = args.log_filter.is_some();
    let log_filter = args.log_filter.unwrap_or_else(|| EnvFilter::new("info"));

    // Sentry has a guard we need to keep alive,
    // so store it. The compiler will optimize
    // this away when not using sentry.
    let (_guard, reload_handle) = ntp_daemon::tracing::init(log_filter);

    let config = Config::from_args(args.config, args.peers).await?;

    if let Some(log_filter) = config.log_filter {
        if has_log_override {
            info!("Log filter override from command line arguments is active")
        } else {
            reload_handle.modify(|l| *l.filter_mut() = log_filter)?;
        }
    }

    ntp_daemon::spawn(&config.system, &config.peers).await
}
