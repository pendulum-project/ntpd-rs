use std::path::PathBuf;

use ntp_proto::{ClockId, ObservableSourceState, PollInterval};
use pps_time::PpsDevice;
use statime_base::{Direction, Duration, Link, Measurement, Timestamp};
use tokio::sync::mpsc;
use tracing::{Instrument, Span, debug, error, instrument, warn};

use crate::daemon::clock::utc_to_tai;

#[derive(Debug, PartialEq, Clone)]
pub struct PpsSourceConfig {
    pub path: PathBuf,
    pub precision: Duration,
    pub accuracy: Duration,
}

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

pub(crate) struct PpsSourceTask<Controller: Link> {
    source: Controller,
    fetch_receiver: mpsc::Receiver<pps_time::pps::pps_fdata>,
    config: PpsSourceConfig,
}

impl<Controller: Link + Send + 'static> PpsSourceTask<Controller> {
    async fn run(&mut self) {
        loop {
            enum SelectResult {
                PpsRecv(Option<pps_time::pps::pps_fdata>),
            }

            let selected: SelectResult = tokio::select! {
                result = self.fetch_receiver.recv() => {
                    SelectResult::PpsRecv(result)
                },
            };

            match selected {
                SelectResult::PpsRecv(result) => match result {
                    Some(data) => {
                        debug!("received {:?}", data);

                        let recv_timestamp =
                            utc_to_tai(Timestamp::from_seconds_nanos_since_unix_epoch(
                                data.info.assert_tu.sec as _,
                                data.info.assert_tu.nsec as _,
                            ));

                        let measurement = Measurement {
                            send_timestamp: utc_to_tai(
                                Timestamp::from_seconds_nanos_since_unix_epoch(
                                    data.info.assert_tu.sec as _,
                                    0,
                                ),
                            ),
                            recv_timestamp,
                            uncertainty: self.config.accuracy,
                        };

                        self.source
                            .external_data_update(self.config.precision, None, true)
                            .expect("Unable to update external source data.");
                        self.source
                            .measurement(measurement, Direction::Reverse)
                            .expect("Unable to handle measurement.");
                    }
                    None => {
                        warn!("Did not receive any new PPS data");
                    }
                },
            }
        }
    }

    #[instrument(level = tracing::Level::ERROR, name = "Pps Source", skip(source))]
    pub fn spawn(source: Controller, config: PpsSourceConfig) -> tokio::task::JoinHandle<()> {
        let pps = PpsDevice::new(config.path.clone()).expect("Could not open PPS device");
        let cap = pps.get_cap().expect("Could not get PPS capabilities");
        assert!(
            cap & pps_time::pps::PPS_CANWAIT != 0,
            "PPS device does not support blocking calls"
        );

        let (fetch_sender, fetch_receiver) = mpsc::channel(1);

        tokio::task::spawn_blocking(|| {
            let process = PpsDeviceFetchTask { pps, fetch_sender };

            process.run();
        });

        tokio::spawn(
            (async move {
                let mut process = PpsSourceTask {
                    source,
                    fetch_receiver,
                    config,
                };

                process.run().await;
            })
            .instrument(Span::current()),
        )
    }
}
