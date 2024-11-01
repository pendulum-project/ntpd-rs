use std::{fmt::Display, path::Path};

use ntp_proto::{
    Measurement, NtpClock, NtpDuration, NtpInstant, NtpLeapIndicator, OneWaySource,
    OneWaySourceSnapshot, OneWaySourceUpdate, ReferenceId, SourceController, SystemSourceUpdate,
};
use tracing::debug;
use tracing::{error, instrument, Instrument, Span};

use tokio::net::UnixDatagram;

use crate::daemon::{exitcode, ntp_source::MsgForSystem};

use super::{ntp_source::SourceChannels, spawn::SourceId};

// Based on https://gitlab.com/gpsd/gpsd/-/blob/master/gpsd/timehint.c#L268
#[derive(Debug)]
struct SockSample {
    // tv_sec: i64,
    // tv_usec: i64,
    offset: f64,
    pulse: i32,
    leap: i32,
    magic: i32,
}

const SOCK_MAGIC: i32 = 0x534f434b;
const SOCK_SAMPLE_SIZE: usize = 40;

#[derive(Debug)]
enum SampleError {
    IOError(std::io::Error),
    SliceError(std::array::TryFromSliceError),
    WrongSize(usize),
    WrongMagic(i32),
    WrongPulse(i32),
}

impl Display for SampleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SampleError::IOError(e) => f.write_str(&e.to_string()),
            SampleError::SliceError(e) => f.write_str(&e.to_string()),
            SampleError::WrongSize(s) => f.write_fmt(format_args!("Invalid size {s}")),
            SampleError::WrongMagic(m) => f.write_fmt(format_args!("Invalid magic {m}")),
            SampleError::WrongPulse(p) => f.write_fmt(format_args!("Invalid pulse {p}")),
        }
    }
}

fn deserialize_sample(
    result: Result<usize, std::io::Error>,
    buf: [u8; SOCK_SAMPLE_SIZE],
) -> Result<SockSample, SampleError> {
    let size = result.map_err(SampleError::IOError)?;
    if size != SOCK_SAMPLE_SIZE {
        return Err(SampleError::WrongSize(size));
    }

    let sample = SockSample {
        // tv_sec: i64::from_le_bytes(buf[0..8].try_into()?),
        // tv_usec: i64::from_le_bytes(buf[8..16].try_into()?),
        offset: f64::from_le_bytes(buf[16..24].try_into().map_err(SampleError::SliceError)?),
        pulse: i32::from_le_bytes(buf[24..28].try_into().map_err(SampleError::SliceError)?),
        leap: i32::from_le_bytes(buf[28..32].try_into().map_err(SampleError::SliceError)?),
        // skip padding (4 bytes)
        magic: i32::from_le_bytes(buf[36..40].try_into().map_err(SampleError::SliceError)?),
    };

    if sample.magic != SOCK_MAGIC {
        return Err(SampleError::WrongMagic(sample.magic));
    }

    if sample.pulse != 0 {
        return Err(SampleError::WrongPulse(sample.pulse));
    }

    Ok(sample)
}

pub(crate) struct SockSourceTask<
    C: 'static + NtpClock + Send,
    Controller: SourceController<MeasurementDelay = ()>,
> {
    index: SourceId,
    socket: UnixDatagram,
    clock: C,
    channels: SourceChannels<Controller::ControllerMessage, Controller::SourceMessage>,
    source: OneWaySource<Controller>,
}

fn create_socket(socket_path: String) -> std::io::Result<UnixDatagram> {
    let path = Path::new(&socket_path).to_path_buf();
    if path.exists() {
        debug!("Removing previous socket file");
        std::fs::remove_file(&path)?;
    }
    debug!("Creating socket at {:?}", path);
    let socket = UnixDatagram::bind(path)?;
    Ok(socket)
}

impl<C, Controller: SourceController<MeasurementDelay = ()>> SockSourceTask<C, Controller>
where
    C: 'static + NtpClock + Send + Sync,
{
    async fn run(&mut self) {
        loop {
            let mut buf = [0; SOCK_SAMPLE_SIZE];

            enum SelectResult<Controller: SourceController> {
                SockRecv(Result<usize, std::io::Error>),
                SystemUpdate(
                    Result<
                        SystemSourceUpdate<Controller::ControllerMessage>,
                        tokio::sync::broadcast::error::RecvError,
                    >,
                ),
            }

            let selected: SelectResult<Controller> = tokio::select! {
                result = self.socket.recv(&mut buf) => {
                    SelectResult::SockRecv(result)
                },
                result = self.channels.system_update_receiver.recv() => {
                    SelectResult::SystemUpdate(result)
                }
            };

            match selected {
                SelectResult::SockRecv(result) => match deserialize_sample(result, buf) {
                    Ok(sample) => {
                        debug!("received {:?}", sample);
                        let leap = match sample.leap {
                            0 => NtpLeapIndicator::NoWarning,
                            1 => NtpLeapIndicator::Leap61,
                            2 => NtpLeapIndicator::Leap59,
                            _ => NtpLeapIndicator::Unknown,
                        };

                        let time = match self.clock.now() {
                            Ok(time) => time,
                            Err(e) => {
                                error!(error = ?e, "There was an error retrieving the current time");
                                std::process::exit(exitcode::NOPERM);
                            }
                        };

                        let measurement = Measurement {
                            delay: (),
                            offset: NtpDuration::from_seconds(sample.offset),
                            localtime: time,
                            monotime: NtpInstant::now(),

                            stratum: 0,
                            root_delay: NtpDuration::ZERO,
                            root_dispersion: NtpDuration::ZERO,
                            leap,
                            precision: 0, // TODO: compute on startup?
                        };

                        let controller_message = self.source.handle_measurement(measurement);

                        let update = OneWaySourceUpdate {
                            snapshot: OneWaySourceSnapshot {
                                source_id: ReferenceId::SOCK,
                                stratum: 0,
                            },
                            message: controller_message,
                        };
                        self.channels
                            .msg_for_system_sender
                            .send(MsgForSystem::OneWaySourceUpdate(self.index, update))
                            .await
                            .ok();
                    }
                    Err(e) => {
                        error!("Error deserializing sample: {}", e);
                        continue;
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
    #[instrument(level = tracing::Level::ERROR, name = "Sock Source", skip(clock, channels, source))]
    pub fn spawn(
        index: SourceId,
        socket_path: String,
        clock: C,
        channels: SourceChannels<Controller::ControllerMessage, Controller::SourceMessage>,
        source: OneWaySource<Controller>,
    ) -> tokio::task::JoinHandle<()> {
        let socket = create_socket(socket_path).expect("Could not create socket");
        tokio::spawn(
            (async move {
                let mut process = SockSourceTask {
                    index,
                    socket,
                    clock,
                    channels,
                    source,
                };

                process.run().await;
            })
            .instrument(Span::current()),
        )
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        os::unix::net::UnixDatagram,
        sync::{Arc, RwLock},
    };

    use ntp_proto::{
        AlgorithmConfig, KalmanClockController, NtpClock, NtpDuration, NtpLeapIndicator,
        NtpTimestamp, ReferenceId, SourceDefaultsConfig, SynchronizationConfig,
    };
    use tokio::sync::mpsc;

    use crate::daemon::{
        ntp_source::{MsgForSystem, SourceChannels},
        sock_source::{create_socket, SampleError, SockSourceTask, SOCK_MAGIC},
        spawn::SourceId,
        util::EPOCH_OFFSET,
    };

    use super::deserialize_sample;

    #[derive(Debug, Clone, Default)]
    struct TestClock {}

    impl NtpClock for TestClock {
        type Error = std::time::SystemTimeError;

        fn now(&self) -> std::result::Result<NtpTimestamp, Self::Error> {
            let cur =
                std::time::SystemTime::now().duration_since(std::time::SystemTime::UNIX_EPOCH)?;

            Ok(NtpTimestamp::from_seconds_nanos_since_ntp_era(
                EPOCH_OFFSET.wrapping_add(cur.as_secs() as u32),
                cur.subsec_nanos(),
            ))
        }

        fn set_frequency(&self, _freq: f64) -> Result<NtpTimestamp, Self::Error> {
            self.now()
            //ignore
        }

        fn get_frequency(&self) -> Result<f64, Self::Error> {
            Ok(0.0)
        }

        fn step_clock(&self, _offset: NtpDuration) -> Result<NtpTimestamp, Self::Error> {
            panic!("Shouldn't be called by source");
        }

        fn disable_ntp_algorithm(&self) -> Result<(), Self::Error> {
            Ok(())
            //ignore
        }

        fn error_estimate_update(
            &self,
            _est_error: NtpDuration,
            _max_error: NtpDuration,
        ) -> Result<(), Self::Error> {
            panic!("Shouldn't be called by source");
        }

        fn status_update(&self, _leap_status: NtpLeapIndicator) -> Result<(), Self::Error> {
            Ok(())
            //ignore
        }
    }

    #[tokio::test]
    async fn test_read_sock() {
        let (_system_update_sender, system_update_receiver) = tokio::sync::broadcast::channel(1);
        let (msg_for_system_sender, mut msg_for_system_receiver) = mpsc::channel(1);

        let index = SourceId::new();
        let clock = TestClock {};
        let mut system: ntp_proto::System<_, KalmanClockController<_, _>> = ntp_proto::System::new(
            clock.clone(),
            SynchronizationConfig::default(),
            SourceDefaultsConfig::default(),
            AlgorithmConfig::default(),
            Arc::new([]),
        )
        .unwrap();

        let socket_path = "/tmp/test.sock";
        let _socket = create_socket(socket_path.to_string()).unwrap(); // should be overwritten by SockSource's own socket

        let handle = SockSourceTask::spawn(
            index,
            socket_path.to_string(),
            clock,
            SourceChannels {
                msg_for_system_sender,
                system_update_receiver,
                source_snapshots: Arc::new(RwLock::new(HashMap::new())),
            },
            system.create_sock_source(index, 0.001).unwrap(),
        );

        // Send example data to socket
        let sock = UnixDatagram::unbound().unwrap();
        sock.connect(socket_path).unwrap();
        let buf = [
            127, 136, 245, 102, 0, 0, 0, 0, 33, 129, 4, 0, 0, 0, 0, 0, 125, 189, 182, 209, 254,
            119, 19, 65, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 75, 67, 79, 83,
        ];
        sock.send(&buf).unwrap();

        // Receive system update
        let msg = msg_for_system_receiver.recv().await.unwrap();
        let update = match msg {
            MsgForSystem::OneWaySourceUpdate(source_id, sock_source_update) => {
                assert_eq!(source_id, index);
                sock_source_update
            }
            _ => panic!("wrong message type"),
        };

        assert_eq!(update.snapshot.source_id, ReferenceId::SOCK);
        assert_eq!(update.snapshot.stratum, 0);

        handle.abort();
    }

    #[test]
    fn test_deserialize_sample() {
        // Example sock sample
        let buf = [
            127, 136, 245, 102, 0, 0, 0, 0, 33, 129, 4, 0, 0, 0, 0, 0, 125, 189, 182, 209, 254,
            119, 19, 65, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 75, 67, 79, 83,
        ];
        let sample = deserialize_sample(Ok(buf.len()), buf).unwrap();
        assert_eq!(sample.offset, 318975.704798661);
        assert_eq!(sample.pulse, 0);
        assert_eq!(sample.leap, 0);
        assert_eq!(sample.magic, SOCK_MAGIC);

        // Wrong magic value
        let buf = [
            127, 136, 245, 102, 0, 0, 0, 0, 33, 129, 4, 0, 0, 0, 0, 0, 125, 189, 182, 209, 254,
            119, 19, 65, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0,
        ];
        assert!(matches!(
            dbg!(deserialize_sample(Ok(buf.len()), buf)),
            Err(SampleError::WrongMagic(_))
        ));

        // Wrong pulse value
        let buf = [
            127, 136, 245, 102, 0, 0, 0, 0, 33, 129, 4, 0, 0, 0, 0, 0, 125, 189, 182, 209, 254,
            119, 19, 65, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 75, 67, 79, 83,
        ];
        assert!(matches!(
            dbg!(deserialize_sample(Ok(buf.len()), buf)),
            Err(SampleError::WrongPulse(_))
        ));

        // Wrong data size
        let buf = [
            127, 136, 245, 102, 0, 0, 0, 0, 33, 129, 4, 0, 0, 0, 0, 0, 125, 189, 182, 209, 254,
            119, 19, 65, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 75, 67, 79, 0,
        ];
        assert!(matches!(
            dbg!(deserialize_sample(Ok(buf.len() - 1), buf)),
            Err(SampleError::WrongSize(_))
        ));
    }
}
