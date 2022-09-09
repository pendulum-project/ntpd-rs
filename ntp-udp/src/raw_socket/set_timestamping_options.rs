use std::os::unix::prelude::AsRawFd;

use super::{cerr, TimestampingConfig};

pub(crate) fn set_timestamping_options(
    udp_socket: &std::net::UdpSocket,
    timestamping: TimestampingConfig,
) -> std::io::Result<()> {
    let fd = udp_socket.as_raw_fd();

    let mut options = 0;

    if timestamping.rx_software || timestamping.tx_software {
        // enable software timestamping
        options |= libc::SOF_TIMESTAMPING_SOFTWARE
    }

    if timestamping.rx_software {
        // we want receive timestamps
        options |= libc::SOF_TIMESTAMPING_RX_SOFTWARE
    }

    if timestamping.tx_software {
        // - we want send timestamps
        // - return just the timestamp, don't send the full message along
        // - tag the timestamp with an ID
        options |= libc::SOF_TIMESTAMPING_TX_SOFTWARE
            | libc::SOF_TIMESTAMPING_OPT_TSONLY
            | libc::SOF_TIMESTAMPING_OPT_ID;
    }

    unsafe {
        cerr(libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TIMESTAMPING,
            &options as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        ))?
    };

    Ok(())
}
