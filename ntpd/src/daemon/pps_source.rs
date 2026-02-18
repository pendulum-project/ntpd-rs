use std::path::PathBuf;

use ntp_proto::{
    ClockId, Measurement, NtpDuration, NtpLeapIndicator, OneWaySource, OneWaySourceSnapshot,
    OneWaySourceUpdate, ReferenceId, SourceController, SystemSourceUpdate,
};
use pps_time::PpsDevice;
use tokio::sync::mpsc;
use tracing::{Instrument, Span, debug, error, instrument, warn};

use crate::daemon::{ntp_source::MsgForSystem, util::convert_unix_timestamp};

use super::ntp_source::SourceChannels;

struct PpsDeviceFetchTask {
    pps: PpsDevice,
    fetch_sender: mpsc::Sender<pps_time::pps::pps_fdata>,
}

impl PpsDeviceFetchTask {
    fn run(&self) {
        loop {
            match self.pps.fetch_blocking() {
                Err(e) => error!("PPS error: {}", e),
                Ok(data) => self.fetch_sender.blocking_send(data).unwrap(),
            }
        }
    }
}

pub(crate) struct PpsSourceTask<Controller: SourceController> {
    index: ClockId,
    channels: SourceChannels<Controller::ControllerMessage, Controller::SourceMessage>,
    path: PathBuf,
    source: OneWaySource<Controller>,
    fetch_receiver: mpsc::Receiver<pps_time::pps::pps_fdata>,
}

impl<Controller: SourceController> PpsSourceTask<Controller> {
    async fn run(&mut self) {
        loop {
            enum SelectResult<Controller: SourceController> {
                PpsRecv(Option<pps_time::pps::pps_fdata>),
                SystemUpdate(
                    Result<
                        SystemSourceUpdate<Controller::ControllerMessage>,
                        tokio::sync::broadcast::error::RecvError,
                    >,
                ),
            }

            let selected: SelectResult<Controller> = tokio::select! {
                result = self.fetch_receiver.recv() => {
                    SelectResult::PpsRecv(result)
                },
                result = self.channels.system_update_receiver.recv() => {
                    SelectResult::SystemUpdate(result)
                }
            };

            match selected {
                SelectResult::PpsRecv(result) => match result {
                    Some(data) => {
                        debug!("received {:?}", data);

                        let measurement = Measurement {
                            sender_id: self.index,
                            receiver_id: ClockId::SYSTEM,
                            sender_ts: convert_unix_timestamp(data.info.assert_tu.sec as _, 0),
                            receiver_ts: convert_unix_timestamp(
                                data.info.assert_tu.sec as _,
                                data.info.assert_tu.nsec as _,
                            ),

                            stratum: 0,
                            root_delay: NtpDuration::ZERO,
                            root_dispersion: NtpDuration::ZERO,
                            leap: NtpLeapIndicator::NoWarning,
                            precision: 0,
                        };

                        let controller_message = self.source.handle_measurement(measurement);

                        let update = OneWaySourceUpdate {
                            snapshot: OneWaySourceSnapshot {
                                source_id: ReferenceId::PPS,
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
                                    "PPS device".to_string(),
                                    self.path.display().to_string(),
                                    self.index,
                                ),
                            );
                    }
                    None => {
                        warn!("Did not receive any new PPS data");
                        continue;
                    }
                },
                SelectResult::SystemUpdate(result) => match result {
                    Ok(update) => {
                        self.source.handle_message(update.message);
                    }
                    Err(e) => {
                        error!("Error receiving system update: {:?}", e);
                    }
                },
            }
        }
    }

    #[instrument(level = tracing::Level::ERROR, name = "Pps Source", skip(channels, source))]
    pub fn spawn(
        index: ClockId,
        device_path: PathBuf,
        channels: SourceChannels<Controller::ControllerMessage, Controller::SourceMessage>,
        source: OneWaySource<Controller>,
    ) -> tokio::task::JoinHandle<()> {
        let pps = PpsDevice::new(device_path.clone()).expect("Could not open PPS device");
        let cap = pps.get_cap().expect("Could not get PPS capabilities");
        if cap & pps_time::pps::PPS_CANWAIT == 0 {
            panic!("PPS device does not support blocking calls")
        }

        let (fetch_sender, fetch_receiver) = mpsc::channel(1);

        tokio::task::spawn_blocking(|| {
            let process = PpsDeviceFetchTask { pps, fetch_sender };

            process.run();
        });

        tokio::spawn(
            (async move {
                let mut process = PpsSourceTask {
                    index,
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
