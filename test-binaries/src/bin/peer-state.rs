use ntp_daemon::ObservablePeerState;
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut stream = tokio::net::UnixStream::connect("/run/ntpd-rs/observe").await?;

    ntp_daemon::sockets::write_json(&mut stream, &ntp_daemon::Observe::Peers).await?;

    let mut msg = Vec::with_capacity(16 * 1024);
    let output: Vec<ObservablePeerState> =
        ntp_daemon::sockets::read_json(&mut stream, &mut msg).await?;

    dbg!(output);

    Ok(())
}
