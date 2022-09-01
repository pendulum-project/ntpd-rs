#![forbid(unsafe_code)]

use std::{io, net::SocketAddr};

use ntp_proto::NtpTimestamp;
use tokio::io::unix::AsyncFd;
use tracing::{debug, instrument, trace, warn};

use crate::{fetch_send_timestamp_help, recv, set_timestamping_options, TimestampingConfig};

enum Timestamping {
    Configure(TimestampingConfig),
    #[allow(dead_code)]
    AllSupported,
}

pub struct UdpSocket {
    io: AsyncFd<std::net::UdpSocket>,
    send_counter: u32,
    timestamping: TimestampingConfig,
}

impl UdpSocket {
    #[instrument(level = "debug", skip(peer_addr))]
    pub async fn client(listen_addr: SocketAddr, peer_addr: SocketAddr) -> io::Result<UdpSocket> {
        // disable tx timestamping for now (outside of tests)
        let timestamping = TimestampingConfig {
            rx_software: true,
            tx_software: false,
        };

        Self::client_with_timestamping(
            listen_addr,
            peer_addr,
            Timestamping::Configure(timestamping),
        )
        .await
    }

    async fn client_with_timestamping(
        listen_addr: SocketAddr,
        peer_addr: SocketAddr,
        timestamping: Timestamping,
    ) -> io::Result<UdpSocket> {
        let socket = tokio::net::UdpSocket::bind(listen_addr).await?;
        debug!(
            local_addr = debug(socket.local_addr().unwrap()),
            "client socket bound"
        );

        socket.connect(peer_addr).await?;
        debug!(
            local_addr = debug(socket.local_addr().unwrap()),
            peer_addr = debug(socket.peer_addr().unwrap()),
            "client socket connected"
        );

        let socket = socket.into_std()?;

        let timestamping = match timestamping {
            Timestamping::Configure(config) => config,
            Timestamping::AllSupported => TimestampingConfig::all_supported(&socket)?,
        };

        set_timestamping_options(&socket, timestamping)?;

        Ok(UdpSocket {
            io: AsyncFd::new(socket)?,
            send_counter: 0,
            timestamping,
        })
    }

    #[instrument(level = "debug")]
    pub async fn server(listen_addr: SocketAddr) -> io::Result<UdpSocket> {
        let socket = tokio::net::UdpSocket::bind(listen_addr).await?;
        debug!(
            local_addr = debug(socket.local_addr().unwrap()),
            "server socket bound"
        );

        let socket = socket.into_std()?;

        // our supported kernel versions always have receive timestamping. Send timestamping for a
        // server connection is not relevant, so we don't even bother with checking if it is supported
        let timestamping = TimestampingConfig {
            rx_software: true,
            tx_software: false,
        };

        set_timestamping_options(&socket, timestamping)?;

        Ok(UdpSocket {
            io: AsyncFd::new(socket)?,
            send_counter: 0,
            timestamping,
        })
    }

    #[instrument(level = "trace", skip(self, buf), fields(
        local_addr = debug(self.as_ref().local_addr().unwrap()),
        peer_addr = debug(self.as_ref().peer_addr()),
        buf_size = buf.len(),
    ))]
    pub async fn send(&mut self, buf: &[u8]) -> io::Result<(usize, Option<NtpTimestamp>)> {
        let send_size = self.send_help(buf).await?;
        let expected_counter = self.send_counter;
        self.send_counter = self.send_counter.wrapping_add(1);

        if self.timestamping.tx_software {
            // the send timestamp may never come set a very short timeout to prevent hanging forever.
            // We automatically fall back to a less accurate timestamp when this function returns None
            let timeout = std::time::Duration::from_millis(10);

            match tokio::time::timeout(timeout, self.fetch_send_timestamp(expected_counter)).await {
                Err(_) => {
                    warn!("Packet without timestamp");
                    Ok((send_size, None))
                }
                Ok(send_timestamp) => Ok((send_size, Some(send_timestamp?))),
            }
        } else {
            trace!("send timestamping not supported");
            Ok((send_size, None))
        }
    }

    async fn send_help(&self, buf: &[u8]) -> io::Result<usize> {
        trace!(size = buf.len(), "sending bytes");
        loop {
            let mut guard = self.io.writable().await?;
            match guard.try_io(|inner| inner.get_ref().send(buf)) {
                Ok(result) => match result {
                    Err(e) => {
                        debug!(error = debug(&e), "error sending data");
                        return Err(e);
                    }
                    Ok(size) => {
                        trace!(sent = size, "sent bytes");
                        return Ok(size);
                    }
                },
                Err(_would_block) => {
                    trace!("blocked after becoming writable, retrying");
                    continue;
                }
            }
        }
    }

    async fn fetch_send_timestamp(&self, expected_counter: u32) -> io::Result<NtpTimestamp> {
        trace!("waiting for timestamp socket to become readable to fetch a send timestamp");
        loop {
            // here we wait for the socket to become writable again, even though what we want to do
            // is read from the error queue.
            //
            // We found that waiting for `readable()` is unreliable, and does not seem to actually
            // fire when the timestamping message is available. To our understanding, the socked
            // becomes `writable()` when it has sent all its packets. So in practice this is also
            // the moment when the timestamp message is available in the error queue.
            let mut guard = self.io.writable().await?;
            match guard.try_io(|inner| fetch_send_timestamp_help(inner.get_ref(), expected_counter))
            {
                Ok(Ok(Some(send_timestamp))) => {
                    return Ok(send_timestamp);
                }
                Ok(Ok(None)) => {
                    continue;
                }
                Ok(Err(e)) => {
                    warn!(error = debug(&e), "Error fetching timestamp");
                    return Err(e);
                }
                Err(_would_block) => {
                    trace!("timestamp blocked after becoming readable, retrying");
                    continue;
                }
            }
        }
    }

    #[instrument(level = "trace", skip(self, buf), fields(
        local_addr = debug(self.as_ref().local_addr().unwrap()),
        buf_size = buf.len(),
    ))]
    pub async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        trace!(size = buf.len(), ?addr, "sending bytes");
        loop {
            let mut guard = self.io.writable().await?;
            match guard.try_io(|inner| inner.get_ref().send_to(buf, &addr)) {
                Ok(result) => {
                    match &result {
                        Ok(size) => trace!(sent = size, "sent bytes"),
                        Err(e) => debug!(error = debug(e), "error sending data"),
                    }
                    return result;
                }
                Err(_would_block) => {
                    trace!("blocked after becoming writable, retrying");
                    continue;
                }
            }
        }
    }

    #[instrument(level = "trace", skip(self, buf), fields(
        local_addr = debug(self.as_ref().local_addr().unwrap()),
        peer_addr = debug(self.as_ref().peer_addr().ok()),
        buf_size = buf.len(),
    ))]
    pub async fn recv(
        &self,
        buf: &mut [u8],
    ) -> io::Result<(usize, SocketAddr, Option<NtpTimestamp>)> {
        loop {
            trace!("waiting for socket to become readable");
            let mut guard = self.io.readable().await?;
            let result = match guard.try_io(|inner| recv(inner.get_ref(), buf)) {
                Err(_would_block) => {
                    trace!("blocked after becoming readable, retrying");
                    continue;
                }
                Ok(result) => result,
            };
            match &result {
                Ok((size, addr, ts)) => {
                    trace!(size, ts = debug(ts), addr = debug(addr), "received message")
                }
                Err(e) => debug!(error = debug(e), "error receiving data"),
            }
            return result;
        }
    }
}

impl AsRef<std::net::UdpSocket> for UdpSocket {
    fn as_ref(&self) -> &std::net::UdpSocket {
        self.io.get_ref()
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn test_timestamping_reasonable() {
        tokio_test::block_on(async {
            let mut a = UdpSocket::client_with_timestamping(
                SocketAddr::from((Ipv4Addr::LOCALHOST, 8000)),
                SocketAddr::from((Ipv4Addr::LOCALHOST, 8001)),
                Timestamping::AllSupported,
            )
            .await
            .unwrap();
            let b = UdpSocket::client(
                SocketAddr::from((Ipv4Addr::LOCALHOST, 8001)),
                SocketAddr::from((Ipv4Addr::LOCALHOST, 8000)),
            )
            .await
            .unwrap();

            tokio::spawn(async move {
                a.send(&[1; 48]).await.unwrap();
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                a.send(&[2; 48]).await.unwrap();
            });

            let mut buf = [0; 48];
            let (s1, _, t1) = b.recv(&mut buf).await.unwrap();
            let (s2, _, t2) = b.recv(&mut buf).await.unwrap();
            assert_eq!(s1, 48);
            assert_eq!(s2, 48);

            let t1 = t1.unwrap();
            let t2 = t2.unwrap();
            let delta = t2 - t1;

            assert!(delta.to_seconds() > 0.15 && delta.to_seconds() < 0.25);
        });
    }

    #[test]
    fn test_send_timestamp() {
        tokio_test::block_on(async {
            let mut a = UdpSocket::client_with_timestamping(
                SocketAddr::from((Ipv4Addr::LOCALHOST, 8012)),
                SocketAddr::from((Ipv4Addr::LOCALHOST, 8013)),
                Timestamping::AllSupported,
            )
            .await
            .unwrap();
            let b = UdpSocket::client(
                SocketAddr::from((Ipv4Addr::LOCALHOST, 8013)),
                SocketAddr::from((Ipv4Addr::LOCALHOST, 8012)),
            )
            .await
            .unwrap();

            let (ssend, tsend) = a.send(&[1; 48]).await.unwrap();
            let mut buf = [0; 48];
            let (srecv, _, trecv) = b.recv(&mut buf).await.unwrap();

            assert_eq!(ssend, 48);
            assert_eq!(srecv, 48);

            let tsend = tsend.unwrap();
            let trecv = trecv.unwrap();
            let delta = trecv - tsend;
            assert!(delta.to_seconds().abs() < 0.2);
        });
    }
}
