use std::time::Duration;
use std::{future::Future, marker::PhantomData, pin::Pin};
use tokio::time::{Instant, Sleep};
use ntp_proto::{NtpClock, NtpInstant, NtpTimestamp, NtpDuration, PpsSource, PpsSourceActionIterator};
use tracing::{error, info, instrument, warn, Instrument, Span};
use super::pps_polling::Pps;
use super::pps_polling::AcceptResult;
use std::io;


use crate::daemon::ntp_source::MsgForSystem;
use super::{config::TimestampMode, exitcode, ntp_source::SourceChannels, spawn::SourceId};

// Trait needed to allow injecting of futures other than `tokio::time::Sleep` for testing
pub trait Wait: Future<Output = ()> {
    fn reset(self: Pin<&mut Self>, deadline: Instant);
}

impl Wait for Sleep {
    fn reset(self: Pin<&mut Self>, deadline: Instant) {
        self.reset(deadline);
    }
}

pub(crate) struct PpsSourceTask<C: 'static + NtpClock + Send, T: Wait> {
    _wait: PhantomData<T>,
    index: SourceId,
    clock: C,
    channels: SourceChannels,
    source: PpsSource,
    last_send_timestamp: Option<NtpTimestamp>,
    pps:Pps,
}

impl<C, T> PpsSourceTask<C, T>
where
    C: 'static + NtpClock + Send + Sync,
    T: Wait,
{
    async fn run(&mut self, mut poll_wait: Pin<&mut T>) {
        loop {

            // Enum to handle the selection of either a Timer or PPS Signal event
            enum SelectResult {
                Timer,
                Recv(io::Result<Option<(f64, NtpTimestamp)>>),
            }
            
            let selected = tokio::select! {
                () = &mut poll_wait => {
                    SelectResult::Timer
                },
                result = self.pps.poll_pps_signal() => {
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
                            match accept_pps_time(result) {
                                AcceptResult::Accept(offset, ntp_timestamp) => {
                                    self.source.handle_incoming(NtpInstant::now(), offset, ntp_timestamp, self.pps.measurement_noise)
                                }
                                AcceptResult::Ignore => PpsSourceActionIterator::default(),
                            }
                        }
                        Ok(None) => {
                            // Handle the case where no data is available
                            PpsSourceActionIterator::default()
                        }
                        Err(e) => {
                            // Handle the error
                            PpsSourceActionIterator::default()
                        }
                    }
                }
                SelectResult::Timer => {
                    // tracing::debug!("wait completed");
                    // let system_snapshot = *self.channels.system_snapshot_receiver.borrow();
                    // self.source.handle_timer(system_snapshot);
                    PpsSourceActionIterator::default()
                }
            };

            for action in actions {
                match action {
                    ntp_proto::PpsSourceAction::Send() => {
                        match self.clock.now() {
                            Err(e) => {
                                error!(error = ?e, "There was an error retrieving the current time");
                                std::process::exit(exitcode::NOPERM);
                            }
                            Ok(ts) => {
                                self.last_send_timestamp = Some(ts);
                            }
                        }
                    }
                    ntp_proto::PpsSourceAction::UpdateSystem(update) => {
                        self.channels
                            .msg_for_system_sender
                            .send(MsgForSystem::PpsSourceUpdate(self.index, update))
                            .await
                            .ok();
                    }
                    ntp_proto::PpsSourceAction::SetTimer(timeout) => {
                        poll_wait.as_mut().reset(Instant::now() + timeout);
                    }
                    ntp_proto::PpsSourceAction::Reset => {
                        self.channels
                            .msg_for_system_sender
                            .send(MsgForSystem::Unreachable(self.index))
                            .await
                            .ok();
                        return;
                    }
                    ntp_proto::PpsSourceAction::Demobilize => {
                        self.channels
                            .msg_for_system_sender
                            .send(MsgForSystem::MustDemobilize(self.index))
                            .await
                            .ok();
                        return;
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(1000)).await;
        }
    }
}


impl<C> PpsSourceTask<C, Sleep>
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
        pps: Pps,
    ) -> tokio::task::JoinHandle<()> {
        info!("spawning pps source");
        tokio::spawn(
            (async move {
                let (source, initial_actions)  = PpsSource::new();
                let poll_wait = tokio::time::sleep(std::time::Duration::default());
                tokio::pin!(poll_wait);

                for action in initial_actions {
                    match action {
                        ntp_proto::PpsSourceAction::Send() => {
                            unreachable!("Should not be sending messages from startup")
                        }
                        ntp_proto::PpsSourceAction::UpdateSystem(_) => {
                            unreachable!("Should not be updating system from startup")
                        }
                        ntp_proto::PpsSourceAction::SetTimer(timeout) => {
                            poll_wait.as_mut().reset(Instant::now() + timeout)
                        }
                        ntp_proto::PpsSourceAction::Reset => {
                            unreachable!("Should not be resetting from startup")
                        }
                        ntp_proto::PpsSourceAction::Demobilize => {
                            unreachable!("Should not be demobilizing from startup")
                        }
                    }
                }

                let last_send_timestamp = clock.clone().now().ok();
                let mut process = PpsSourceTask {
                    _wait: PhantomData,
                    index,
                    clock,
                    channels,
                    source,
                    pps,
                    last_send_timestamp,
                };

                process.run(poll_wait).await;
            })
            .instrument(Span::current()),
        )
    }
}


    /// Result handling for PPS polling.
    pub fn accept_pps_time(result: io::Result<Option<(f64, NtpTimestamp)>>) -> AcceptResult {
        match result {
            Ok(Some(data)) => {
                match parse_pps_time(data) {
                    Ok((pps_duration, pps_timestamp)) => AcceptResult::Accept(pps_duration, pps_timestamp),
                    Err(_) => AcceptResult::Ignore,
                }
            }
            Ok(None) => {
                AcceptResult::Ignore
            }
            Err(receive_error) => {
                AcceptResult::Ignore
            }
        }
    }

    fn parse_pps_time(data: (f64, NtpTimestamp)) -> Result<(NtpDuration, NtpTimestamp), Box<dyn std::error::Error>> {
        let ntp_duration = from_seconds(data.0);
        Ok((ntp_duration, data.1))
    }

    pub fn from_seconds(seconds: f64) -> NtpDuration {
        let whole_seconds = seconds as i64;
        let fraction = seconds.fract();
        let ntp_fraction = (fraction * (1u64 << 32) as f64) as u32;
    
        NtpDuration::from_seconds(seconds)
    }
    #[cfg(test)]
mod tests {
    use super::*;
    use ntp_proto::{NtpTimestamp, NtpDuration};
    use std::io;

    // Assuming `AcceptResult` is defined somewhere in your module and doesn't implement `PartialEq`
    #[derive(Debug, PartialEq)]
    pub enum TestAcceptResult {
        Accept(NtpDuration, NtpTimestamp),
        Ignore,
    }

    // A conversion function if your actual `AcceptResult` doesn't match the test enum
    fn convert_accept_result(result: AcceptResult) -> TestAcceptResult {
        match result {
            AcceptResult::Accept(duration, timestamp) => TestAcceptResult::Accept(duration, timestamp),
            AcceptResult::Ignore => TestAcceptResult::Ignore,
        }
    }

    #[test]
    fn test_accept_pps_time_with_valid_data() {
        let timestamp = NtpTimestamp::default();
        let duration = 1.0;
        let result = Ok(Some((duration, timestamp)));

        let expected_duration = NtpDuration::from_seconds(duration);
        let expected = TestAcceptResult::Accept(expected_duration, timestamp);

        assert_eq!(convert_accept_result(accept_pps_time(result)), expected);
    }

    #[test]
    fn test_accept_pps_time_with_none_data() {
        let result = Ok(None);
        let expected = TestAcceptResult::Ignore;

        assert_eq!(convert_accept_result(accept_pps_time(result)), expected);
    }

    #[test]
    fn test_accept_pps_time_with_error() {
        let result: io::Result<Option<(f64, NtpTimestamp)>> = Err(io::Error::new(io::ErrorKind::Other, "test error"));
        let expected = TestAcceptResult::Ignore;

        assert_eq!(convert_accept_result(accept_pps_time(result)), expected);
    }

    #[test]
    fn test_parse_pps_time() {
        let timestamp = NtpTimestamp::default();
        let duration = 1.0;

        let result = parse_pps_time((duration, timestamp)).unwrap();
        let expected_duration = NtpDuration::from_seconds(duration);

        assert_eq!(result, (expected_duration, timestamp));
    }

    #[test]
    fn test_from_seconds() {
        let duration = 1.5;
        let ntp_duration = from_seconds(duration);

        assert_eq!(ntp_duration, NtpDuration::from_seconds(duration));
    }
}
