use std::{fmt::Display, path::Path};

use ntp_proto::{ClockId, ObservableSourceState, PollInterval};
use statime_base::{Clock, Direction, Duration, LeapStatus, Link, Measurement, TAI};
use tracing::debug;
use tracing::{Instrument, Span, error, instrument};

use tokio::net::UnixDatagram;

use crate::daemon::config::SockSourceConfig;
use crate::daemon::exitcode;

use super::ntp_source::SourceChannels;

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

pub(crate) struct SockSourceTask<C: 'static + Clock<TAI> + Send, Controller: Link> {
    index: ClockId,
    socket: UnixDatagram,
    clock: C,
    channels: SourceChannels,
    source: Controller,
    config: SockSourceConfig,
}

fn create_socket<T: AsRef<Path>>(path: T) -> std::io::Result<UnixDatagram> {
    let path = path.as_ref();
    if path.exists() {
        debug!("Removing previous socket file");
        std::fs::remove_file(path)?;
    }
    debug!("Creating socket at {:?}", path);
    let socket = UnixDatagram::bind(path)?;
    Ok(socket)
}

impl<C, Controller: Link + Send + 'static> SockSourceTask<C, Controller>
where
    C: 'static + Clock<TAI> + Send + Sync,
{
    async fn run(&mut self) {
        loop {
            enum SelectResult {
                SockRecv(Result<usize, std::io::Error>),
            }

            let mut buf = [0; SOCK_SAMPLE_SIZE];

            let selected: SelectResult = tokio::select! {
                result = self.socket.recv(&mut buf) => {
                    SelectResult::SockRecv(result)
                },
            };

            match selected {
                SelectResult::SockRecv(result) => match deserialize_sample(result, buf) {
                    Ok(sample) => {
                        debug!("received {:?}", sample);
                        let leap = match sample.leap {
                            0 => Some(LeapStatus::None),
                            1 => Some(LeapStatus::Leap61),
                            2 => Some(LeapStatus::Leap59),
                            _ => None,
                        };

                        let time = match self.clock.now() {
                            Ok(time) => time,
                            Err(e) => {
                                error!(error = ?e, "There was an error retrieving the current time");
                                std::process::exit(exitcode::NOPERM);
                            }
                        };

                        let measurement = Measurement {
                            send_timestamp: time - Duration::from_f64_seconds(sample.offset),
                            recv_timestamp: time,
                            uncertainty: Duration::from_f64_seconds(self.config.precision),
                        };

                        self.source
                            .external_data_update(
                                Duration::from_f64_seconds(self.config.precision),
                                leap,
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
                                    name: "GPSd socket".to_string(),
                                    address: self.config.path.display().to_string(),
                                    id: self.index,
                                },
                            );
                    }
                    Err(e) => {
                        error!("Error deserializing sample: {}", e);
                    }
                },
            }
        }
    }

    #[instrument(level = tracing::Level::ERROR, name = "Sock Source", skip(clock, channels, source))]
    pub fn spawn(
        index: ClockId,
        clock: C,
        channels: SourceChannels,
        source: Controller,
        config: SockSourceConfig,
    ) -> tokio::task::JoinHandle<()> {
        let socket = create_socket(&config.path).expect("Could not create socket");
        tokio::spawn(
            (async move {
                let mut process = SockSourceTask {
                    index,
                    socket,
                    clock,
                    channels,
                    source,
                    config,
                };

                process.run().await;
            })
            .instrument(Span::current()),
        )
    }
}

#[cfg(test)]
#[allow(clippy::float_cmp, reason = "Test code")]
mod tests {
    use std::{
        collections::HashMap,
        os::unix::net::UnixDatagram,
        sync::{Arc, RwLock},
    };

    use ntp_proto::ClockId;
    use statime_base::{Clock, Duration, Link, LinkId, TAI, Timestamp};
    use tokio::sync::mpsc;

    use crate::{
        daemon::{
            config::SockSourceConfig,
            ntp_source::SourceChannels,
            sock_source::{SOCK_MAGIC, SampleError, SockSourceTask, create_socket},
        },
        test::alloc_port,
    };

    use super::deserialize_sample;

    #[derive(Debug, Clone, Default)]
    struct TestClock {}

    impl Clock<TAI> for TestClock {
        fn now(&self) -> Result<statime_base::Timestamp<TAI>, statime_base::ClockError> {
            let cur = std::time::SystemTime::now()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .unwrap();

            Ok(Timestamp::UNIX_EPOCH + Duration::from_f64_seconds(cur.as_secs_f64()))
        }

        fn set_frequency(
            &self,
            _freq: f64,
        ) -> Result<statime_base::Timestamp<TAI>, statime_base::ClockError> {
            unimplemented!("should not be called")
        }

        fn get_frequency(&self) -> Result<f64, statime_base::ClockError> {
            unimplemented!("should not be called")
        }

        fn max_frequency(&self) -> Result<f64, statime_base::ClockError> {
            unimplemented!("should not be called")
        }

        fn step_clock(
            &self,
            _offset: Duration,
        ) -> Result<statime_base::Timestamp<TAI>, statime_base::ClockError> {
            unimplemented!("should not be called")
        }

        fn error_estimate_update(
            &self,
            _est_error: Duration,
            _max_error: Duration,
        ) -> Result<(), statime_base::ClockError> {
            unimplemented!("should not be called")
        }

        fn leap_update(
            &self,
            _leap_status: statime_base::LeapStatus,
        ) -> Result<(), statime_base::ClockError> {
            unimplemented!("should not be called")
        }

        fn synchronization_update(
            &self,
            _synchronized: bool,
        ) -> Result<(), statime_base::ClockError> {
            unimplemented!("should not be called")
        }
    }

    struct TestController(LinkId);

    impl Link for TestController {
        type Error = std::convert::Infallible;

        fn measurement(
            &self,
            _measurement: statime_base::Measurement,
            _direction: statime_base::Direction,
        ) -> Result<(), Self::Error> {
            Ok(())
        }

        fn external_data_update(
            &self,
            _root_delay: statime_base::Duration,
            _leap_status: Option<statime_base::LeapStatus>,
            _usable: bool,
        ) -> Result<(), Self::Error> {
            Ok(())
        }

        fn active(&self) -> Result<bool, Self::Error> {
            Ok(true)
        }

        fn importance(&self) -> Result<Option<f64>, Self::Error> {
            Ok(Some(0.5))
        }

        fn desired_poll_interval(&self) -> Result<statime_base::Duration, Self::Error> {
            Ok(Duration::ZERO)
        }

        fn id(&self) -> statime_base::LinkId {
            self.0
        }
    }

    #[tokio::test]
    async fn test_read_sock() {
        let (msg_for_system_sender, _) = mpsc::channel(1);

        let index = ClockId::new();
        let clock = TestClock {};

        let socket_path = std::env::temp_dir().join(format!("ntp-test-stream-{}", alloc_port()));
        let _socket = create_socket(&socket_path).unwrap(); // should be overwritten by SockSource's own socket

        let handle = SockSourceTask::spawn(
            index,
            clock,
            SourceChannels {
                msg_for_system_sender,
                source_snapshots: Arc::new(RwLock::new(HashMap::new())),
            },
            TestController(
                LinkId::new(statime_base::ClockId::new(), statime_base::ClockId::new()).unwrap(),
            ),
            SockSourceConfig {
                path: socket_path.clone(),
                precision: 0.1,
                accuracy: 0.1,
            },
        );

        // Send example data to socket
        let sock = UnixDatagram::unbound().unwrap();
        sock.connect(socket_path).unwrap();
        let buf = [
            127, 136, 245, 102, 0, 0, 0, 0, 33, 129, 4, 0, 0, 0, 0, 0, 125, 189, 182, 209, 254,
            119, 19, 65, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 75, 67, 79, 83,
        ];
        sock.send(&buf).unwrap();

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
