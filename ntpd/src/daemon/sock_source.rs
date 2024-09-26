use std::{marker::PhantomData, pin::Pin, time::Duration};

use ntp_proto::{
    Measurement, NtpClock, NtpDuration, NtpInstant, NtpLeapIndicator, ReferenceId,
    SockSourceSnapshot, SockSourceUpdate, SourceController,
};
#[cfg(target_os = "linux")]
use tracing::{error, info, instrument, Instrument, Span};

use tokio::time::{Instant, Sleep};

use crate::daemon::{exitcode, ntp_source::MsgForSystem};

use super::{
    ntp_source::{SourceChannels, Wait},
    spawn::SourceId,
};

pub(crate) struct SockSourceTask<
    C: 'static + NtpClock + Send,
    Controller: SourceController,
    T: Wait,
> {
    _wait: PhantomData<T>,
    index: SourceId,
    socket_path: String,
    clock: C,
    channels: SourceChannels<Controller::ControllerMessage, Controller::SourceMessage>,
    controller: Controller,
}

impl<C, Controller: SourceController, T> SockSourceTask<C, Controller, T>
where
    C: 'static + NtpClock + Send + Sync,
    T: Wait,
{
    async fn run(&mut self, mut poll_wait: Pin<&mut T>) {
        loop {
            // temporary: prints "sock!" every second
            info!("sock! {}", self.socket_path);
            poll_wait
                .as_mut()
                .reset(Instant::now() + Duration::from_secs(1));
            poll_wait.as_mut().await;

            let time = match self.clock.now() {
                Ok(time) => time,
                Err(e) => {
                    error!(error = ?e, "There was an error retrieving the current time");
                    std::process::exit(exitcode::NOPERM);
                }
            };

            let measurement = Measurement {
                delay: None,
                offset: NtpDuration::from_seconds(3.), // TODO: get from socket
                localtime: time,                       // TODO: use tv from socket?
                monotime: NtpInstant::now(),

                stratum: 0,
                root_delay: NtpDuration::ZERO,
                root_dispersion: NtpDuration::ZERO,
                leap: NtpLeapIndicator::NoWarning, // TODO: get from socket
                precision: 1,                      // TODO: compute on startup?
            };

            let controller_message = self.controller.handle_measurement(measurement);
            println!("{:?}", controller_message);

            let update = SockSourceUpdate {
                snapshot: SockSourceSnapshot {
                    source_id: ReferenceId::SOCK,
                    stratum: 0,
                },
                message: controller_message,
            };
            self.channels
                .msg_for_system_sender
                .send(MsgForSystem::SockSourceUpdate(self.index, update))
                .await
                .ok();
        }
    }
}

impl<C, Controller: SourceController> SockSourceTask<C, Controller, Sleep>
where
    C: 'static + NtpClock + Send + Sync,
{
    #[allow(clippy::too_many_arguments)]
    #[instrument(level = tracing::Level::ERROR, name = "Ntp Source", skip(clock, controller))]
    pub fn spawn(
        index: SourceId,
        socket_path: String,
        clock: C,
        channels: SourceChannels<Controller::ControllerMessage, Controller::SourceMessage>,
        controller: Controller,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(
            (async move {
                let poll_wait = tokio::time::sleep(std::time::Duration::default());
                tokio::pin!(poll_wait);

                let mut process = SockSourceTask {
                    _wait: PhantomData,
                    index,
                    socket_path,
                    clock,
                    channels,
                    controller,
                };

                process.run(poll_wait).await;
            })
            .instrument(Span::current()),
        )
    }
}
