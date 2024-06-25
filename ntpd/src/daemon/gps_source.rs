use std::io;
use std::{future::Future, marker::PhantomData, pin::Pin};
use tokio::time::{Instant, Sleep};

use ntp_proto::{
    GpsSource, GpsSourceActionIterator, NtpClock, NtpDuration, NtpInstant, NtpTimestamp,
};

use tracing::{error, instrument, warn, Instrument, Span};

use crate::daemon::ntp_source::MsgForSystem;

use super::gps_without_gpsd::Gps;

use super::{config::TimestampMode, exitcode, ntp_source::SourceChannels, spawn::SourceId};

/// Trait needed to allow injecting of futures other than `tokio::time::Sleep` for testing
pub trait Wait: Future<Output = ()> {
    fn reset(self: Pin<&mut Self>, deadline: Instant);
}

impl Wait for Sleep {
    fn reset(self: Pin<&mut Self>, deadline: Instant) {
        self.reset(deadline);
    }
}

pub(crate) struct GpsSourceTask<C: 'static + NtpClock + Send, T: Wait> {
    _wait: PhantomData<T>,
    index: SourceId,
    clock: C,
    channels: SourceChannels,

    source: GpsSource,

    /// we don't store the real origin timestamp in the packet, because that would leak our
    /// system time to the network (and could make attacks easier). So instead there is some
    /// garbage data in the origin_timestamp field, and we need to track and pass along the
    /// actual origin timestamp ourselves.
    /// Timestamp of the last packet that we sent
    last_send_timestamp: Option<NtpTimestamp>,
    gps: Gps,
}

impl<C, T> GpsSourceTask<C, T>
where
    C: 'static + NtpClock + Send + Sync,
    T: Wait,
{
    async fn run(&mut self, mut poll_wait: Pin<&mut T>) {
        loop {
            enum SelectResult {
                Timer,
                Recv(io::Result<Option<(f64, NtpTimestamp)>>),
            }
            let selected = tokio::select! {
                () = &mut poll_wait => {
                    SelectResult::Timer
                },
                result = self.gps.current_data() => {
                    if result.is_err() {
                        SelectResult::Recv(Err(result.unwrap_err()))
                    } else {
                        SelectResult::Recv(result)
                    }
                }
            };

            let actions = match selected {
                SelectResult::Recv(result) => {
                    match result {
                        Ok(Some(data)) => {
                            // Process GPS data
                            println!("Offset between GPS time and system time: {:.6} seconds and the gps time is {:?}", data.0, data.1);
                            match accept_gps_time(result) {
                                AcceptResult::Accept((offset, timestamp)) => {
                                    println!("offset: {:?}", offset);
                                    self.source.handle_incoming(
                                        NtpInstant::now(),
                                        offset,
                                        timestamp,
                                        self.gps.measurement_noise,
                                    )
                                }
                                AcceptResult::Ignore => GpsSourceActionIterator::default(),
                            }
                        }
                        Ok(None) => {
                            // Handle the case where no data is available
                            println!("No GPS data available");
                            GpsSourceActionIterator::default()
                        }
                        Err(e) => {
                            // Handle the error
                            eprintln!("Error processing GPS data: {}", e);
                            GpsSourceActionIterator::default()
                        }
                    }
                }
                SelectResult::Timer => {
                    // tracing::debug!("wait completed");
                    // let system_snapshot = *self.channels.system_snapshot_receiver.borrow();
                    // self.source.handle_timer(system_snapshot);
                    GpsSourceActionIterator::default()
                }
            };

            for action in actions {
                match action {
                    ntp_proto::GpsSourceAction::Send() => {
                        match self.clock.now() {
                            Err(e) => {
                                // we cannot determine the origin_timestamp
                                error!(error = ?e, "There was an error retrieving the current time");

                                // report as no permissions, since this seems the most likely
                                std::process::exit(exitcode::NOPERM);
                            }
                            Ok(ts) => {
                                self.last_send_timestamp = Some(ts);
                            }
                        }
                    }
                    ntp_proto::GpsSourceAction::UpdateSystem(update) => {
                        self.channels
                            .msg_for_system_sender
                            .send(MsgForSystem::GpsSourceUpdate(self.index, update))
                            .await
                            .ok();
                    }
                    ntp_proto::GpsSourceAction::SetTimer(timeout) => {
                        poll_wait.as_mut().reset(Instant::now() + timeout)
                    }
                    ntp_proto::GpsSourceAction::Reset => {
                        self.channels
                            .msg_for_system_sender
                            .send(MsgForSystem::Unreachable(self.index))
                            .await
                            .ok();
                        return;
                    }
                    ntp_proto::GpsSourceAction::Demobilize => {
                        self.channels
                            .msg_for_system_sender
                            .send(MsgForSystem::MustDemobilize(self.index))
                            .await
                            .ok();
                        return;
                    }
                }
            }
        }
    }
}

impl<C> GpsSourceTask<C, Sleep>
where
    C: 'static + NtpClock + Send + Sync,
{
    #[allow(clippy::too_many_arguments)]
    #[instrument(skip(clock, channels))]
    pub fn spawn(
        index: SourceId,
        clock: C,
        timestamp_mode: TimestampMode,
        channels: SourceChannels,
        gps: Gps,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(
            (async move {
                let (source, initial_actions) = GpsSource::new();
                let poll_wait = tokio::time::sleep(std::time::Duration::default());
                tokio::pin!(poll_wait);
                for action in initial_actions {
                    match action {
                        ntp_proto::GpsSourceAction::Send() => {
                            unreachable!("Should not be sending messages from startup")
                        }
                        ntp_proto::GpsSourceAction::UpdateSystem(_) => {
                            unreachable!("Should not be updating system from startup")
                        }
                        ntp_proto::GpsSourceAction::SetTimer(timeout) => {
                            poll_wait.as_mut().reset(Instant::now() + timeout)
                        }
                        ntp_proto::GpsSourceAction::Reset => {
                            unreachable!("Should not be resetting from startup")
                        }
                        ntp_proto::GpsSourceAction::Demobilize => {
                            todo!("Should not be demobilizing from startup")
                        }
                    }
                }

                let last_send_timestamp = clock.clone().now().ok();
                let mut process = GpsSourceTask {
                    _wait: PhantomData,
                    index,
                    clock,
                    channels,
                    source,
                    gps,
                    last_send_timestamp,
                };

                process.run(poll_wait).await;
            })
            .instrument(Span::current()),
        )
    }
}

#[derive(Debug)]
enum AcceptResult {
    Accept((NtpDuration, NtpTimestamp)),
    Ignore,
}

pub fn from_seconds(seconds: f64) -> NtpDuration {
    let whole_seconds = seconds as i64;
    let fraction = seconds.fract();
    let ntp_fraction = (fraction * (1u64 << 32) as f64) as u32;

    println!(
        "Seconds: {}, Whole seconds: {}, Fraction: {}",
        seconds, whole_seconds, ntp_fraction
    );

    NtpDuration::from_seconds(seconds)
}

fn parse_gps_time(
    data: &Option<(f64, NtpTimestamp)>,
) -> Result<(NtpDuration, NtpTimestamp), Box<dyn std::error::Error>> {
    if let Some(offset) = data {
        let ntp_duration = from_seconds(offset.0);
        Ok((ntp_duration, offset.1))
    } else {
        Err("Failed to parse GPS time".into())
    }
}

fn accept_gps_time(result: io::Result<Option<(f64, NtpTimestamp)>>) -> AcceptResult {
    match result {
        Ok(data) => {
            println!("data: {:?}", data);
            match parse_gps_time(&data) {
                Ok((gps_duration, gps_timestamp)) => {
                    AcceptResult::Accept((gps_duration, gps_timestamp))
                }
                Err(_) => AcceptResult::Ignore,
            }
        }
        Err(receive_error) => {
            warn!(?receive_error, "could not receive GPS data");

            AcceptResult::Ignore
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ntp_proto::NtpTimestamp;

    #[tokio::test]
    async fn test_accept_gps_time_with_valid_data() {
        let gps_timestamp = NtpTimestamp::from_fixed_int(1_614_505_748);
        let result = Ok(Some((123.456789, gps_timestamp)));
        let accept_result = accept_gps_time(result);

        if let AcceptResult::Accept((duration, timestamp)) = accept_result {
            assert_eq!(duration.to_seconds(), 123.45678902847152);
            assert_eq!(timestamp, gps_timestamp);
        } else {
            panic!("Expected Accept result");
        }
    }

    #[tokio::test]
    async fn test_accept_gps_time_with_invalid_data() {
        let result: io::Result<Option<(f64, NtpTimestamp)>> = Ok(None);
        let accept_result = accept_gps_time(result);

        if let AcceptResult::Ignore = accept_result {
            // Expected outcome
        } else {
            panic!("Expected Ignore result");
        }
    }

    #[tokio::test]
    async fn test_accept_gps_time_with_error() {
        let result: io::Result<Option<(f64, NtpTimestamp)>> =
            Err(io::Error::new(io::ErrorKind::Other, "error"));
        let accept_result = accept_gps_time(result);

        if let AcceptResult::Ignore = accept_result {
            // Expected outcome
        } else {
            panic!("Expected Ignore result");
        }
    }

    #[tokio::test]
    async fn test_parse_gps_time_with_valid_data() {
        let gps_timestamp = NtpTimestamp::from_fixed_int(1_614_505_748);
        let data = Some((123.456789, gps_timestamp));
        let result = parse_gps_time(&data);

        assert!(result.is_ok());
        let (duration, timestamp) = result.unwrap();
        assert_eq!(duration.to_seconds(), 123.45678902847152);
        assert_eq!(timestamp, gps_timestamp);
    }

    #[tokio::test]
    async fn test_parse_gps_time_with_invalid_data() {
        let data: Option<(f64, NtpTimestamp)> = None;
        let result = parse_gps_time(&data);

        assert!(result.is_err());
    }

    #[test]
    fn test_from_seconds() {
        let seconds = 123.456789;
        let duration = from_seconds(seconds);
        assert_eq!(duration.to_seconds(), 123.45678902847152);
    }
}
