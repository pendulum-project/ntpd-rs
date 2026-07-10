use std::{future::pending, sync::RwLock};

use ntp_proto::{ClockId, SourceController};
use statime_csptp::{ClientRecvResult, ClientSocket, CsptpManager, CsptpSource, InternalState};
use statime_netptp::{NetworkManager, PtpAddressFamily};
use statime_wire::Timestamp;

use crate::daemon::config::CsptpSourceConfig;

struct SocketWrapper<A: PtpAddressFamily>(statime_netptp::ConnectedSocket<A>);

impl<A: PtpAddressFamily> ClientSocket for SocketWrapper<A> {
    type Error = std::io::Error;

    async fn recv(&mut self, buf: &mut [u8]) -> Result<ClientRecvResult, Self::Error> {
        let result = self.0.recv().await?;

        let bytes_read = result.bytes_read.len().min(buf.len());
        buf[..bytes_read].copy_from_slice(&result.bytes_read[..bytes_read]);

        // This unwrap will never fail as the conditions are guaranteed.
        Ok(ClientRecvResult {
            bytes_read,
            // This unwrap will never fail as the conditions are guaranteed by the arithmatic on the ts fields.
            timestamp: result.timestamp.map(|ts| {
                Timestamp::new(
                    (ts.seconds as u64)
                        .wrapping_add((ts.nanos / 1_000_000_000).into())
                        // Compensate for difference between UTC and TAI
                        .wrapping_add(37)
                        % (1 << 48),
                    ts.nanos % 1_000_000_000,
                )
                .unwrap()
            }),
        })
    }

    async fn send_event(&mut self, buf: &[u8]) -> Result<Timestamp, Self::Error> {
        if let Some(ts) = self.0.send_event(buf).await? {
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
}

#[non_exhaustive]
pub(crate) struct CsptpSourceTask {}

impl CsptpSourceTask {
    #[expect(
        clippy::needless_pass_by_value,
        reason = "False positive on config, it is actually consumed in the move into the tokio spawn"
    )]
    pub fn spawn<A: PtpAddressFamily + Sync + Send, Controller: SourceController>(
        index: ClockId,
        addr: A,
        config: CsptpSourceConfig,
        controller: Controller,
        manager: &'static CsptpManager<RwLock<InternalState>>,
        network: NetworkManager<A>,
    ) {
        tokio::spawn(async move {
            let interface = network.open_general();
            let mut source = CsptpSource::new(
                ClockId::SYSTEM,
                index,
                statime_csptp::CsptpSourceConfig {
                    poll_interval: config.poll_interval,
                    response_interval: config.response_interval,
                    domain: config.domain,
                },
                manager,
                controller,
            );

            source
                .run(
                    pending(),
                    || {
                        Ok::<_, std::convert::Infallible>(SocketWrapper(
                            interface.connected_socket(None, addr),
                        ))
                    },
                    |duration| tokio::time::sleep(duration),
                    rand::thread_rng,
                )
                .await;
        });
    }
}
