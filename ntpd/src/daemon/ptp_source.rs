use std::path::PathBuf;

use ntp_proto::{
    Measurement, NtpClock, NtpDuration, NtpInstant, NtpLeapIndicator, OneWaySource,
    OneWaySourceSnapshot, OneWaySourceUpdate, ReferenceId, SourceController, SystemSourceUpdate,
};
use ptp_time::{PtpDevice, ptp::{ptp_sys_offset_precise, ptp_sys_offset_extended, ptp_sys_offset}};
use tokio::sync::mpsc;
use tracing::{Instrument, Span, debug, error, info, instrument, warn};

use crate::daemon::ntp_source::MsgForSystem;

use super::{ntp_source::SourceChannels, spawn::SourceId};

#[derive(Debug, Clone)]
enum TimestampCapability {
    Precise,
    Extended,
    Standard,
}

enum PtpTimestamp {
    Precise(ptp_sys_offset_precise),
    Extended(ptp_sys_offset_extended),
    Standard(ptp_sys_offset),
}

impl PtpTimestamp {
    // Convert PTP timestamp to NTP duration (seconds)
    fn calculate_offset(&self) -> Option<f64> {
        match self {
            PtpTimestamp::Precise(precise) => {
                let ptp_time = precise.device.sec as f64 + (precise.device.nsec as f64 / 1_000_000_000.0);
                let sys_time = precise.sys_realtime.sec as f64 + (precise.sys_realtime.nsec as f64 / 1_000_000_000.0);
                Some(sys_time - ptp_time)
            }
            PtpTimestamp::Extended(extended) => {
                if extended.n_samples > 0 {
                    let ptp_time = extended.ts[0][1].sec as f64 + (extended.ts[0][1].nsec as f64 / 1_000_000_000.0);
                    let sys_time = extended.ts[0][0].sec as f64 + (extended.ts[0][0].nsec as f64 / 1_000_000_000.0);
                    Some(sys_time - ptp_time)
                } else {
                    None
                }
            }
            PtpTimestamp::Standard(standard) => {
                if standard.n_samples > 0 {
                    let ptp_time = standard.ts[1].sec as f64 + (standard.ts[1].nsec as f64 / 1_000_000_000.0);
                    let sys_time = standard.ts[0].sec as f64 + (standard.ts[0].nsec as f64 / 1_000_000_000.0);
                    Some(sys_time - ptp_time)
                } else {
                    None
                }
            }
        }
    }
}

impl std::fmt::Debug for PtpTimestamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PtpTimestamp::Precise(precise) => {
                f.debug_struct("Precise")
                    .field("offset", &format_args!("{:.9}s", self.calculate_offset().unwrap_or(0.0)))
                    .field("device", &format_args!("{}.{:09}", precise.device.sec, precise.device.nsec))
                    .field("sys_realtime", &format_args!("{}.{:09}", precise.sys_realtime.sec, precise.sys_realtime.nsec))
                    .finish()
            }
            PtpTimestamp::Extended(extended) => {
                f.debug_struct("Extended")
                    .field("offset", &format_args!("{:.9}s", self.calculate_offset().unwrap_or(0.0)))
                    .field("n_samples", &extended.n_samples)
                    .field("samples", &extended.ts.iter().take(extended.n_samples as usize).map(|ts|
                        format!("sys:{}.{:09} dev:{}.{:09}", ts[0].sec, ts[0].nsec, ts[1].sec, ts[1].nsec)
                    ).collect::<Vec<_>>())
                    .finish()
            }
            PtpTimestamp::Standard(standard) => {
                f.debug_struct("Standard")
                    .field("offset", &format_args!("{:.9}s", self.calculate_offset().unwrap_or(0.0)))
                    .field("n_samples", &standard.n_samples)
                    .field("sys_time", &format_args!("{}.{:09}", standard.ts[0].sec, standard.ts[0].nsec))
                    .field("dev_time", &format_args!("{}.{:09}", standard.ts[1].sec, standard.ts[1].nsec))
                    .finish()
            }
        }
    }
}

struct PtpDeviceFetchTask {
    ptp: PtpDevice,
    fetch_sender: mpsc::Sender<Result<PtpTimestamp, String>>,
    poll_receiver: mpsc::Receiver<()>,
    device_path: PathBuf,
    capability: TimestampCapability,
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

            let result = match self.capability {
                TimestampCapability::Precise => {
                    self.ptp.get_sys_offset_precise().map(PtpTimestamp::Precise)
                }
                TimestampCapability::Extended => {
                    self.ptp.get_sys_offset_extended().map(PtpTimestamp::Extended)
                }
                TimestampCapability::Standard => {
                    self.ptp.get_sys_offset().map(PtpTimestamp::Standard)
                }
            };

            match result {
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
    fetch_receiver: mpsc::Receiver<Result<PtpTimestamp, String>>,
    poll_sender: mpsc::Sender<()>,
    poll_interval: ntp_proto::PollInterval,
    stratum: u8,
    delay: f64,
}

impl<C, Controller: SourceController<MeasurementDelay = ()>> PtpSourceTask<C, Controller>
where
    C: 'static + NtpClock + Send + Sync,
{
    async fn run(&mut self) {
        let mut poll_timer = tokio::time::interval(self.poll_interval.as_system_duration());
        poll_timer.tick().await; // Skip first immediate tick

        loop {
            enum SelectResult<Controller: SourceController> {
                Timer,
                PtpRecv(Option<Result<PtpTimestamp, String>>),
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

                        let offset_seconds = match data.calculate_offset() {
                            Some(offset) => offset,
                            None => {
                                warn!("Timestamp has no samples");
                                continue;
                            }
                        };

                        let measurement = Measurement {
                            delay: (),
                            offset: NtpDuration::from_seconds(offset_seconds),
                            localtime: time,
                            monotime: NtpInstant::now(),
                            stratum: self.stratum,
                            root_delay: NtpDuration::from_seconds(self.delay),
                            root_dispersion: NtpDuration::ZERO,
                            leap: NtpLeapIndicator::NoWarning,
                            precision: 0,
                        };

                        let controller_message = self.source.handle_measurement(measurement);

                        let update = OneWaySourceUpdate {
                            snapshot: OneWaySourceSnapshot {
                                source_id: ReferenceId::PTP,
                                stratum: self.stratum,
                            },
                            message: controller_message,
                        };

                        self.channels
                            .msg_for_system_sender
                            .send(MsgForSystem::OneWaySourceUpdate(self.index, update))
                            .await
                            .ok();

                        // Create custom ObservableSourceState with correct poll interval
                        let mut observable_state = self.source.observe(
                            "PTP device".to_string(),
                            self.path.display().to_string(),
                            self.index,
                        );
                        observable_state.poll_interval = self.poll_interval;

                        self.channels
                            .source_snapshots
                            .write()
                            .expect("Unexpected poisoned mutex")
                            .insert(self.index, observable_state);
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
        poll_interval: ntp_proto::PollInterval,
        clock: C,
        channels: SourceChannels<Controller::ControllerMessage, Controller::SourceMessage>,
        source: OneWaySource<Controller>,
        stratum: u8,
        delay: f64,
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

        // Detect timestamp capabilities at initialization
        let capability = detect_timestamp_capability(&ptp);

        let (fetch_sender, fetch_receiver) = mpsc::channel(1);
        let (poll_sender, poll_receiver) = mpsc::channel(1);
        let device_path_clone = device_path.clone();

        tokio::task::spawn_blocking(move || {
            let mut process = PtpDeviceFetchTask {
                ptp,
                fetch_sender,
                poll_receiver,
                device_path: device_path_clone,
                capability,
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
                    stratum,
                    delay,
                };

                process.run().await;
            })
            .instrument(Span::current()),
        )
    }
}

fn detect_timestamp_capability(ptp: &PtpDevice) -> TimestampCapability {
    // Try precise timestamps first
    if ptp.get_sys_offset_precise().is_ok() {
        info!("PTP device supports precise timestamps");
        return TimestampCapability::Precise;
    }

    // Fall back to extended timestamps
    if ptp.get_sys_offset_extended().is_ok() {
        info!("PTP device supports extended timestamps");
        return TimestampCapability::Extended;
    }

    // Fall back to standard timestamps
    info!("PTP device using standard timestamps");
    TimestampCapability::Standard
}
