use std::path::PathBuf;
use std::time::Duration;

use ntp_proto::{
    Measurement, NtpClock, NtpDuration, NtpInstant, NtpLeapIndicator, OneWaySource,
    OneWaySourceSnapshot, OneWaySourceUpdate, ReferenceId, SourceController, SystemSourceUpdate,
};
use ptp_time::PtpDevice;
use tokio::sync::mpsc;
use tracing::{Instrument, Span, debug, error, instrument, warn};

use crate::daemon::{exitcode, ntp_source::MsgForSystem};

use super::{ntp_source::SourceChannels, spawn::SourceId};

struct PtpDeviceFetchTask {
    ptp: PtpDevice,
    fetch_sender: mpsc::Sender<ptp_time::PtpData>,
}

impl PtpDeviceFetchTask {
    fn run(&self) {
        loop {
            match self.ptp.fetch_blocking() {
                Err(e) => {
                    error!("PTP device error: {}", e);
                    // Send an error message to the system coordinator
                    // This will allow the system to handle device unavailability properly
                    break;
                }
                Ok(data) => {
                    if let Err(e) = self.fetch_sender.blocking_send(data) {
                        error!("Failed to send PTP data: {}", e);
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
    fetch_receiver: mpsc::Receiver<ptp_time::PtpData>,
}

impl<C, Controller: SourceController<MeasurementDelay = ()>> PtpSourceTask<C, Controller>
where
    C: 'static + NtpClock + Send + Sync,
{
    async fn run(&mut self) {
        loop {
            enum SelectResult<Controller: SourceController> {
                PtpRecv(Option<ptp_time::PtpData>),
                SystemUpdate(
                    Result<
                        SystemSourceUpdate<Controller::ControllerMessage>,
                        tokio::sync::broadcast::error::RecvError,
                    >,
                ),
            }

            let selected: SelectResult<Controller> = tokio::select! {
                result = self.fetch_receiver.recv() => {
                    SelectResult::PtpRecv(result)
                },
                result = self.channels.system_update_receiver.recv() => {
                    SelectResult::SystemUpdate(result)
                }
            };

            match selected {
                SelectResult::PtpRecv(result) => match result {
                    Some(data) => {
                        debug!("received {:?}", data);

                        let time = match self.clock.now() {
                            Ok(time) => time,
                            Err(e) => {
                                error!(error = ?e, "There was an error retrieving the current time");
                                // For time retrieval errors, we should try to continue rather than exit
                                // This allows for graceful degradation if clock access has issues
                                continue;
                            }
                        };

                        // Convert PTP timestamp to NTP duration (seconds)
                        let offset_seconds = match data.timestamp() {
                            Some(ts) => {
                                // Calculate offset from PTP timestamp to local time
                                // For PTP, we typically want the offset from the reference clock
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
                    None => {
                        // Channel closed - this indicates the PTP device fetch task has terminated
                        warn!("PTP device fetch task terminated, attempting to restart source");

                        // Send a NetworkIssue message to trigger system coordinator recovery
                        self.channels
                            .msg_for_system_sender
                            .send(MsgForSystem::NetworkIssue(self.index))
                            .await
                            .ok();

                        // Break out of the loop to terminate this task
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

        tokio::task::spawn_blocking(|| {
            let process = PtpDeviceFetchTask { ptp, fetch_sender };

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
                };

                process.run().await;
            })
            .instrument(Span::current()),
        )
    }
}
