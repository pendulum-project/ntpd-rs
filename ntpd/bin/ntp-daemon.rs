#![forbid(unsafe_code)]

use std::process;

#[tokio::main]
async fn main() {
    let result = ntpd::daemon_main().await;
    process::exit(if result.is_ok() { 0 } else { 1 });
}
