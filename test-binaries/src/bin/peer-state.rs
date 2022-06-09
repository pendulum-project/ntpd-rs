use ntp_daemon::ObservableState;
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut stream = tokio::net::UnixStream::connect("/run/ntpd-rs/observe").await?;

    let mut msg = Vec::with_capacity(16 * 1024);
    let output: ObservableState = ntp_daemon::sockets::read_json(&mut stream, &mut msg).await?;

    dbg!(output);

    Ok(())
}
