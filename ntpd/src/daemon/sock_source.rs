use std::{marker::PhantomData, pin::Pin, time::Duration};

use ntp_proto::{
    Measurement, NtpClock, NtpDuration, NtpInstant, NtpLeapIndicator, SourceController,
};
#[cfg(target_os = "linux")]
use tracing::{error, info, instrument, Instrument, Span};

use tokio::time::{Instant, Sleep};

use crate::daemon::exitcode;

use super::ntp_source::Wait;

pub(crate) struct SockSourceTask<
    C: 'static + NtpClock + Send,
    Controller: SourceController,
    T: Wait,
> {
    _wait: PhantomData<T>,
    socket_path: String,
    clock: C,
    controller: Controller,
}

impl<C, Controller: SourceController, T> SockSourceTask<C, Controller, T>
where
    C: 'static + NtpClock + Send + Sync,
    T: Wait,
{
    async fn run(&mut self, mut poll_wait: Pin<&mut T>) {
        let mut delta: f64 = 0.; // temporary offset just to experiment
        loop {
            // temporary: prints "sock!" every second
            info!("sock! {}", self.socket_path);
            poll_wait
                .as_mut()
                .reset(Instant::now() + Duration::from_secs(1));
            poll_wait.as_mut().await;

            delta += 1.;
            let time = match self.clock.now() {
                Ok(time) => time,
                Err(e) => {
                    error!(error = ?e, "There was an error retrieving the current time");
                    std::process::exit(exitcode::NOPERM);
                }
            };

            let measurement = Measurement {
                delay: None,
                offset: NtpDuration::from_seconds(delta), // TODO: get from socket
                localtime: time,                          // TODO: use tv from socket?
                monotime: NtpInstant::now(),

                stratum: 1,
                root_delay: NtpDuration::ZERO,
                root_dispersion: NtpDuration::ZERO,
                leap: NtpLeapIndicator::NoWarning, // TODO: get from socket
                precision: 1,                      // TODO: compute on startup?
            };
            let controller_message = self.controller.handle_measurement(measurement);
            println!("{:?}", controller_message); // TODO: handle controller message
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
        socket_path: String,
        clock: C,
        controller: Controller,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(
            (async move {
                let poll_wait = tokio::time::sleep(std::time::Duration::default());
                tokio::pin!(poll_wait);

                let mut process = SockSourceTask {
                    _wait: PhantomData,
                    socket_path,
                    clock,
                    controller,
                };

                process.run(poll_wait).await;
            })
            .instrument(Span::current()),
        )
    }
}
