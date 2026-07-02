use std::{future::pending, sync::RwLock};

use statime_csptp::{CsptpManager, InternalState, ServerRecvResult, ServerSocket, serve};
use statime_netptp::{NetworkManager, OpenSocket, PtpAddressFamily};
use statime_wire::Timestamp;
use tokio::task::JoinHandle;

use crate::daemon::config::CsptpServerConfig;

struct ServerSocketWrapper<A: PtpAddressFamily>(OpenSocket<A>);

impl<A: PtpAddressFamily> ServerSocket for ServerSocketWrapper<A> {
    type Addr = A;

    type Error = std::io::Error;

    async fn recv(
        &mut self,
        buf: &mut [u8],
    ) -> Result<statime_csptp::ServerRecvResult<Self::Addr>, Self::Error> {
        loop {
            let result = self.0.recv().await?;

            if let Some(ts) = result.timestamp {
                let bytes_read = result.bytes_read.len().min(buf.len());
                buf[..bytes_read].copy_from_slice(&result.bytes_read[..bytes_read]);
                break Ok(ServerRecvResult {
                    bytes_read,
                    remote_addr: result.remote_addr,
                    local_addr: result.local_addr,
                    timestamp: Timestamp::new(
                        (ts.seconds as u64)
                            .wrapping_add((ts.nanos / 1_000_000_000).into())
                            // Compensate for difference between UTC and TAI
                            .wrapping_add(37)
                            % (1 << 48),
                        ts.nanos % 1_000_000_000,
                    )
                    .unwrap(),
                });
            }
        }
    }

    async fn send_event(
        &mut self,
        buf: &[u8],
        from: Self::Addr,
        to: Self::Addr,
    ) -> Result<statime_wire::Timestamp, Self::Error> {
        if let Some(ts) = self.0.send_event(buf, Some(from), to).await? {
            // This unwrap will never fail as the conditions are guaranteed by the arithmatic on the ts fields.
            Ok(Timestamp::new(
                (ts.seconds as u64)
                    .wrapping_add((ts.nanos / 1_000_000_000).into())
                    // Compensate for difference between UTC and TAI
                    .wrapping_add(37)
                    % (1 << 48),
                ts.nanos % 1_000_000_000,
            )
            .unwrap())
        } else {
            Err(std::io::Error::other("missing send timestamp"))
        }
    }

    async fn send_general(
        &mut self,
        buf: &[u8],
        from: Self::Addr,
        to: Self::Addr,
    ) -> Result<(), Self::Error> {
        self.0.send_general(buf, Some(from), to).await
    }
}

#[non_exhaustive]
pub(crate) struct CsptpServerTask {}

impl CsptpServerTask {
    pub(crate) fn spawn<A: PtpAddressFamily>(
        csptp_manager: &'static CsptpManager<RwLock<InternalState>>,
        network: NetworkManager<A>,
        _config: CsptpServerConfig,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            let interface = network.open_general();
            let socket = interface.listen_socket();
            tracing::warn!("Spawned server");
            serve(ServerSocketWrapper(socket), pending(), csptp_manager).await;
        })
    }
}
