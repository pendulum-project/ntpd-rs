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

    // for documentation on SO_TIMESTAMPING see
    // https://www.kernel.org/doc/Documentation/networking/timestamping.txt
    // Safety:
    // we have a reference to the socket, so fd is a valid file descriptor for the duration of the call
    // SOL_SOCKET + SO_TIMESTAMPING expect a *u32 as value (see section 1.3.4. of above), which &options
    // is. Furthermore, we own options hence the pointer is valid for the duration of the call.
    // option_len is set to the size of u32, which is the size for which the value pointer is valid.
    unsafe {
        cerr(libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TIMESTAMPING,
            &options as *const _ as *const libc::c_void,
            std::mem::size_of::<u32>() as libc::socklen_t,
        ))?
    };

    Ok(())
}
