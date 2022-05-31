#![forbid(unsafe_code)]

use clap::Parser;
use ntp_daemon::config::{CmdArgs, Config};
use std::error::Error;
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

    ntp_daemon::spawn(&config.system, &config.peers).await
}
