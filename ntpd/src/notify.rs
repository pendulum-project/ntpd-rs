// Code for notifying systemd that a daemon is ready. Originally based on the sd-notify crate by lnicola.

use tokio::net::UnixDatagram;

const NOTIFY_SOCKET: &str = "NOTIFY_SOCKET";

pub(crate) async fn notify_ready() -> std::io::Result<()> {
    let Some(socket_path) = std::env::var_os(NOTIFY_SOCKET) else {
        return Ok(());
    };
    let sock = UnixDatagram::unbound()?;
    sock.connect(&socket_path)?;
    let msg = b"READY=1";
    let len = sock.send(msg).await?;
    if len != msg.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::WriteZero,
            "incomplete write",
        ));
    }
    Ok(())
}
