use std::{marker::PhantomData, pin::Pin, time::Duration};

use ntp_proto::NtpClock;
#[cfg(target_os = "linux")]
use timestamped_socket::interface::InterfaceName;
use tracing::{info, instrument, Instrument, Span};

use tokio::time::{Instant, Sleep};

use super::{ntp_source::Wait, spawn::SourceId};

pub(crate) struct SockSourceTask<C: 'static + NtpClock + Send, T: Wait> {
    _wait: PhantomData<T>,
    index: SourceId,
    clock: C,
    interface: Option<InterfaceName>,
    name: String,
}

impl<C, T> SockSourceTask<C, T>
where
    C: 'static + NtpClock + Send + Sync,
    T: Wait,
{
    async fn run(&mut self, mut poll_wait: Pin<&mut T>) {
        loop {
            // temporary: prints "sock!" every second
            info!("sock!");
            poll_wait
                .as_mut()
                .reset(Instant::now() + Duration::from_secs(1));
            poll_wait.as_mut().await;
        }
    }
}

impl<C> SockSourceTask<C, Sleep>
where
    C: 'static + NtpClock + Send + Sync,
{
    #[allow(clippy::too_many_arguments)]
    #[instrument(level = tracing::Level::ERROR, name = "Ntp Source", skip(clock))]
    pub fn spawn(
        index: SourceId,
        name: String,
        interface: Option<InterfaceName>,
        clock: C,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(
            (async move {
                let poll_wait = tokio::time::sleep(std::time::Duration::default());
                tokio::pin!(poll_wait);

                let mut process = SockSourceTask {
                    _wait: PhantomData,
                    index,
                    name,
                    clock,
                    interface,
                };

                process.run(poll_wait).await;
            })
            .instrument(Span::current()),
        )
    }
}
