use libc::{in_addr, sockaddr_storage};

use super::RawSocket;

impl RawSocket {
    pub(crate) fn enable_destination_ipv4(&self) -> std::io::Result<()> {
        // Noop, fallback to local address.
        Ok(())
    }

    pub(crate) fn send_from_v4(&self, msg: &[u8], addr: in_addr) -> std::io::Result<()> {
        // Fallback, ignore the from
        self.send(msg)
    }

    pub(crate) fn send_from_to_v4(
        &self,
        msg: &[u8],
        from: in_addr,
        to: sockaddr_storage,
    ) -> std::io::Result<()> {
        // Fallback, ignore the from
        self.send_to(msg, to)
    }
}
