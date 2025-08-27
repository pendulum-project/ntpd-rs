use std::path::PathBuf;
use std::time::Duration;

use ntp_proto::{
    Measurement, NtpClock, NtpDuration, NtpInstant, NtpLeapIndicator, OneWaySource,
    OneWaySourceSnapshot, OneWaySourceUpdate, ReferenceId, SourceController, SystemSourceUpdate,
};
use ptp_time::PtpDevice;
use tokio::sync::mpsc;
use tokio::time::Instant;
use tracing::{Instrument, Span, debug, error, instrument, warn};

use crate::daemon::{exitcode, ntp_source::MsgForSystem};

use super::{ntp_source::SourceChannels, spawn::SourceId};

struct PtpDeviceFetchTask {
    ptp: PtpDevice,
    fetch_sender: mpsc::Sender<Result<ptp_time::PtpData, String>>,
    poll_receiver: mpsc::Receiver<()>,
}

impl PtpDeviceFetchTask {
    fn run(&mut self) {
        loop {
            // Wait for poll request from coordinator
            if self.poll_receiver.blocking_recv().is_none() {
                break; // Channel closed, exit
            }

            match self.ptp.fetch_blocking() {
                Err(e) => {
                    let error_msg = format!("PTP device error: {}", e);
                    error!("{}", error_msg);
                    if self.fetch_sender.blocking_send(Err(error_msg)).is_err() {
                        break;
                    }
                }
                Ok(data) => {
                    if self.fetch_sender.blocking_send(Ok(data)).is_err() {
                        break;
                    }
                }
            }
        }
    }
}

pub(crate) struct PtpSourceTask<
    C: 'static + NtpClock + Send,
    Controller: SourceController<MeasurementDelay = ()>,
> {
    index: SourceId,
    clock: C,
    channels: SourceChannels<Controller::ControllerMessage, Controller::SourceMessage>,
    path: PathBuf,
    source: OneWaySource<Controller>,
    fetch_receiver: mpsc::Receiver<Result<ptp_time::PtpData, String>>,
    poll_sender: mpsc::Sender<()>,
    // Removed fixed poll_interval - now using controller-driven adaptive polling
}

impl<C, Controller: SourceController<MeasurementDelay = ()>> PtpSourceTask<C, Controller>
where
    C: 'static + NtpClock + Send + Sync,
{
    async fn run(&mut self) {
        // Use minimum poll interval (0.5s) for PTP polling
        let poll_interval = Duration::from_millis(500); // 2^-1 = 0.5s minimum
        let mut poll_timer = tokio::time::interval(poll_interval);
        poll_timer.tick().await; // Skip first immediate tick

        loop {
            enum SelectResult<Controller: SourceController> {
                Timer,
                PtpRecv(Option<Result<ptp_time::PtpData, String>>),
                SystemUpdate(
                    Result<
                        SystemSourceUpdate<Controller::ControllerMessage>,
                        tokio::sync::broadcast::error::RecvError,
                    >,
                ),
            }

            let selected: SelectResult<Controller> = tokio::select! {
                _ = poll_timer.tick() => {
                    SelectResult::Timer
                },
                result = self.fetch_receiver.recv() => {
                    SelectResult::PtpRecv(result)
                },
                result = self.channels.system_update_receiver.recv() => {
                    SelectResult::SystemUpdate(result)
                }
            };

            match selected {
                SelectResult::Timer => {
                    debug!("PTP poll timer triggered");
                    // Send poll request to blocking thread
                    if self.poll_sender.send(()).await.is_err() {
                        warn!("PTP device fetch task terminated, attempting to restart source");
                        self.channels
                            .msg_for_system_sender
                            .send(MsgForSystem::NetworkIssue(self.index))
                            .await
                            .ok();
                        break;
                    }
                }
                SelectResult::PtpRecv(result) => match result {
                    Some(Ok(data)) => {
                        debug!("received {:?}", data);

                        let time = match self.clock.now() {
                            Ok(time) => time,
                            Err(e) => {
                                error!(error = ?e, "There was an error retrieving the current time");
                                continue;
                            }
                        };

                        // Convert PTP timestamp to NTP duration (seconds)
                        let offset_seconds = match data.timestamp() {
                            Some(ts) => {
                                let ptp_time = ts.to_seconds();
                                let local_time = time.to_seconds();
                                local_time - ptp_time
                            }
                            None => {
                                warn!("PTP device returned no timestamp");
                                continue;
                            }
                        };

                        let measurement = Measurement {
                            delay: (),
                            offset: NtpDuration::from_seconds(offset_seconds),
                            localtime: time,
                            monotime: NtpInstant::now(),
                            stratum: 0,
                            root_delay: NtpDuration::ZERO,
                            root_dispersion: NtpDuration::ZERO,
                            leap: NtpLeapIndicator::NoWarning,
                            precision: 0,
                        };

                        let controller_message = self.source.handle_measurement(measurement);

                        let update = OneWaySourceUpdate {
                            snapshot: OneWaySourceSnapshot {
                                source_id: ReferenceId::PTP,
                                stratum: 0,
                            },
                            message: controller_message,
                        };

                        self.channels
                            .msg_for_system_sender
                            .send(MsgForSystem::OneWaySourceUpdate(self.index, update))
                            .await
                            .ok();

                        self.channels
                            .source_snapshots
                            .write()
                            .expect("Unexpected poisoned mutex")
                            .insert(
                                self.index,
                                self.source.observe(
                                    "PTP device".to_string(),
                                    self.path.display().to_string(),
                                    self.index,
                                ),
                            );
                    }
                    Some(Err(error_msg)) => {
                        error!("PTP device error: {}", error_msg);
                        self.channels
                            .msg_for_system_sender
                            .send(MsgForSystem::NetworkIssue(self.index))
                            .await
                            .ok();
                        break;
                    }
                    None => {
                        warn!("PTP device fetch task terminated, attempting to restart source");
                        self.channels
                            .msg_for_system_sender
                            .send(MsgForSystem::NetworkIssue(self.index))
                            .await
                            .ok();
                        break;
                    }
                },
                SelectResult::SystemUpdate(result) => match result {
                    Ok(update) => {
                        self.source.handle_message(update.message);
                    }
                    Err(e) => {
                        error!("Error receiving system update: {:?}", e)
                    }
                },
            };
        }
    }

    #[allow(clippy::too_many_arguments)]
    #[instrument(level = tracing::Level::ERROR, name = "Ptp Source", skip(clock, channels, source))]
    pub fn spawn(
        index: SourceId,
        device_path: PathBuf,
        clock: C,
        channels: SourceChannels<Controller::ControllerMessage, Controller::SourceMessage>,
        source: OneWaySource<Controller>,
    ) -> tokio::task::JoinHandle<()> {
        // Handle device opening errors gracefully
        let ptp = match PtpDevice::new(device_path.clone()) {
            Ok(ptp) => ptp,
            Err(e) => {
                error!(error = ?e, "Failed to open PTP device at {:?}", device_path);
                // Send a NetworkIssue message to trigger system coordinator recovery
                tokio::spawn(async move {
                    channels
                        .msg_for_system_sender
                        .send(MsgForSystem::NetworkIssue(index))
                        .await
                        .ok();
                });
                // Return immediately without spawning the task, so it can be restarted by the system
                return tokio::spawn(async {});
            }
        };

        // Check capabilities - we want to ensure it supports blocking calls
        if !ptp.can_wait() {
            error!("PTP device at {:?} does not support blocking calls", device_path);
            // Send a NetworkIssue message to trigger system coordinator recovery
            tokio::spawn(async move {
                channels
                    .msg_for_system_sender
                    .send(MsgForSystem::NetworkIssue(index))
                    .await
                    .ok();
            });
            return tokio::spawn(async {});
        }

        let (fetch_sender, fetch_receiver) = mpsc::channel(1);
        let (poll_sender, poll_receiver) = mpsc::channel(1);

        tokio::task::spawn_blocking(move || {
            let mut process = PtpDeviceFetchTask { 
                ptp, 
                fetch_sender,
                poll_receiver,
            };

            process.run();
        });

        tokio::spawn(
            (async move {
                let mut process = PtpSourceTask {
                    index,
                    clock,
                    channels,
                    path: device_path,
                    source,
                    fetch_receiver,
                    poll_sender,
                };

                process.run().await;
            })
            .instrument(Span::current()),
        )
    }
}
