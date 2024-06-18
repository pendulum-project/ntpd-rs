use std::{future::Future, marker::PhantomData, pin::Pin};
use tokio::time::{Instant, Sleep};
use ntp_proto::{NtpClock, NtpInstant, NtpTimestamp, NtpDuration, PpsSource, PpsSourceActionIterator, PpsSourceAction};
use tracing::{debug, error, info, instrument, warn, Instrument, Span};
use super::pps_polling::Pps;
use super::pps_polling::AcceptResult;
use tokio::io;

//alex


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
                Recv(io::Result<Option<f64>>),
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
                            println!("Offset between PPS time and system time: {:.6} seconds", data);
                            match accept_pps_time(result) {
                                AcceptResult::Accept(offset) => {
                                    println!("offset: {:?}", offset);
                                    self.source.handle_incoming(NtpInstant::now(), offset)
                                }
                                AcceptResult::Ignore => PpsSourceActionIterator::default(),
                            }
                        }
                        Ok(None) => {
                            // Handle the case where no data is available
                            println!("No PPS data available");
                            PpsSourceActionIterator::default()
                        }
                        Err(e) => {
                            // Handle the error
                            eprintln!("Error processing PPS data: {}", e);
                            PpsSourceActionIterator::default()
                        }
                        AcceptResult::Ignore => PpsSourceActionIterator::default(),

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
    pub fn accept_pps_time(result: io::Result<Option<f64>>) -> AcceptResult {
        match result {
            Ok(Some(data)) => {
                println!("data: {:?}", data);
                match parse_pps_time(data) {
                    Ok(pps_duration) => AcceptResult::Accept(pps_duration),
                    Err(_) => AcceptResult::Ignore,
                }
            }
            Ok(None) => {
                println!("No PPS data received");
                AcceptResult::Ignore
            }
            Err(receive_error) => {
                println!("Could not receive PPS signal: {:?}", receive_error);
                AcceptResult::Ignore
            }
        }
    }

    fn parse_pps_time(data: &Option<f64>) -> Result<NtpDuration, Box<dyn std::error::Error>> {
        if let Some(offset) = data {
            let ntp_duration = from_seconds(*offset);
            Ok(ntp_duration)
        } else {
            Err("Failed to parse GPS time".into())
        }
    }

//     // Calculate the fractional part of the NTP timestamp
//     let fraction = ((nanos as u64 * NTP_SCALE_FRAC) / 1_000_000_000) as u64;

//     // Combine NTP seconds and fraction to form the complete NTP timestamp
//     let timestamp = (ntp_seconds << 32) | fraction;

//     println!("Unix Timestamp: {}, Nanos: {}, NTP Seconds: {}, Fraction: {}", unix_timestamp, nanos, ntp_seconds, fraction);
//     println!("Combined NTP Timestamp: {:#018X}", timestamp);

//     NtpTimestamp::from_fixed_int(timestamp)
// }

    pub fn from_seconds(seconds: f64) -> NtpDuration {
        let whole_seconds = seconds as i64;
        let fraction = seconds.fract();
        let ntp_fraction = (fraction * (1u64 << 32) as f64) as u32;
    
        println!("Seconds: {}, Whole seconds: {}, Fraction: {}", seconds, whole_seconds, ntp_fraction);
    
        NtpDuration::from_seconds(seconds)
    }
