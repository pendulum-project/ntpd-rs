use ntp_proto::{ClockId, ObservableSourceState, PollInterval};
use pps_time::PpsDevice;
use statime_base::{Direction, Duration, Link, Measurement, Timestamp};
use tokio::sync::mpsc;
use tracing::{Instrument, Span, debug, error, instrument, warn};

use crate::daemon::{clock::utc_to_tai, config::PpsSourceConfig};

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

pub(crate) struct PpsSourceTask<Controller: Link> {
    index: ClockId,
    channels: SourceChannels,
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
                            uncertainty: Duration::from_f64_seconds(self.config.accuracy),
                        };

                        self.source
                            .external_data_update(
                                Duration::from_f64_seconds(self.config.precision),
                                None,
                                true,
                            )
                            .expect("Unable to update external source data.");
                        self.source
                            .measurement(measurement, Direction::Reverse)
                            .expect("Unable to handle measurement.");

                        self.channels
                            .source_snapshots
                            .write()
                            .expect("Unexpected poisoned mutex")
                            .insert(
                                self.index,
                                ObservableSourceState {
                                    unanswered_polls: 0,
                                    poll_interval: PollInterval::from_byte(0),
                                    nts_cookies: None,
                                    name: "PPS device".to_string(),
                                    address: self.config.path.display().to_string(),
                                    id: self.index,
                                },
                            );
                    }
                    None => {
                        warn!("Did not receive any new PPS data");
                    }
                },
            }
        }
    }

    #[instrument(level = tracing::Level::ERROR, name = "Pps Source", skip(channels, source))]
    pub fn spawn(
        index: ClockId,
        channels: SourceChannels,
        source: Controller,
        config: PpsSourceConfig,
    ) -> tokio::task::JoinHandle<()> {
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
                    index,
                    channels,
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
