use std::path::PathBuf;
use std::time::Duration;

use ntp_proto::{
    Measurement, NtpClock, NtpDuration, NtpInstant, NtpLeapIndicator, OneWaySource,
    OneWaySourceSnapshot, OneWaySourceUpdate, ReferenceId, SourceController, SystemSourceUpdate,
};
use ptp_time::{PtpDevice, ptp::ptp_sys_offset_precise};
use tokio::sync::mpsc;
use tracing::{Instrument, Span, debug, error, info, instrument, warn};

use crate::daemon::ntp_source::MsgForSystem;

use super::{ntp_source::SourceChannels, spawn::SourceId};

struct PtpDeviceFetchTask {
    ptp: PtpDevice,
    fetch_sender: mpsc::Sender<Result<ptp_sys_offset_precise, String>>,
    poll_receiver: mpsc::Receiver<()>,
    device_path: PathBuf,
}

impl PtpDeviceFetchTask {
    fn run(&mut self) {
        info!("PTP device fetch task started for {:?}", self.device_path);

        loop {
            // Wait for poll request from coordinator
            if self.poll_receiver.blocking_recv().is_none() {
                info!("PTP device fetch task terminating: coordinator disconnected");
                break; // Channel closed, exit
            }

            match self.ptp.get_sys_offset_precise() {
                Err(e) => {
                    let error_msg = format!("PTP device error: {}", e);
                    error!("{}", error_msg);
                    if self.fetch_sender.blocking_send(Err(error_msg)).is_err() {
                        info!("PTP device fetch task terminating: coordinator disconnected");
                        break;
                    }
                }
                Ok(data) => {
                    if self.fetch_sender.blocking_send(Ok(data)).is_err() {
                        info!("PTP device fetch task terminating: coordinator disconnected");
                        break;
                    }
                }
            }
        }

        info!("PTP device fetch task terminated for {:?}", self.device_path);
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
    fetch_receiver: mpsc::Receiver<Result<ptp_sys_offset_precise, String>>,
    poll_sender: mpsc::Sender<()>,
    poll_interval: Duration,
}

impl<C, Controller: SourceController<MeasurementDelay = ()>> PtpSourceTask<C, Controller>
where
    C: 'static + NtpClock + Send + Sync,
{
    async fn run(&mut self) {
        let mut poll_timer = tokio::time::interval(self.poll_interval);
        poll_timer.tick().await; // Skip first immediate tick

        loop {
            enum SelectResult<Controller: SourceController> {
                Timer,
                PtpRecv(Option<Result<ptp_sys_offset_precise, String>>),
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
                        let ptp_device_time = data.device.sec as f64 + (data.device.nsec as f64 / 1_000_000_000.0);
                        let sys_realtime = data.sys_realtime.sec as f64 + (data.sys_realtime.nsec as f64 / 1_000_000_000.0);
                        let offset_seconds = sys_realtime - ptp_device_time;

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
        poll_interval: Duration,
        clock: C,
        channels: SourceChannels<Controller::ControllerMessage, Controller::SourceMessage>,
        source: OneWaySource<Controller>,
    ) -> tokio::task::JoinHandle<()> {
        // Handle device opening errors gracefully
        let ptp = match PtpDevice::new(device_path.clone()) {
            Ok(ptp) => {
                info!("Successfully opened PTP device at {:?}", device_path);
                ptp
            }
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
                // Return a dummy task that completes immediately
                return tokio::spawn(async {
                    info!("PTP source task terminated due to device unavailability");
                });
            }
        };

        let (fetch_sender, fetch_receiver) = mpsc::channel(1);
        let (poll_sender, poll_receiver) = mpsc::channel(1);
        let device_path_clone = device_path.clone();

        tokio::task::spawn_blocking(move || {
            let mut process = PtpDeviceFetchTask {
                ptp,
                fetch_sender,
                poll_receiver,
                device_path: device_path_clone,
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
                    poll_interval,
                };

                process.run().await;
            })
            .instrument(Span::current()),
        )
    }
}
