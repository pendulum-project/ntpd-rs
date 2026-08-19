use crate::raw_socket::RawSocket;

use crate::interface::InterfaceName;

use super::InterfaceTimestampMode;

pub(super) fn configure_timestamping(
    _socket: &RawSocket,
    _interface: Option<InterfaceName>,
    mode: InterfaceTimestampMode,
    _bind_phc: Option<u32>,
) -> std::io::Result<()> {
    match mode {
        InterfaceTimestampMode::None => Ok(()),
        _ => Err(std::io::ErrorKind::Unsupported.into()),
    }
}
