use std::{future::Future, marker::PhantomData, pin::Pin};
use tokio::time::{Instant, Sleep};
use ntp_proto::{NtpClock, NtpInstant, NtpTimestamp, PpsSourceActionIterator, PpsSource};
use tracing::{debug, error, info, instrument, warn, Instrument, Span};
use super::pps_polling::PPS;


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
    pps: Pps,
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
                PpsSignal(Result<NtpTimestamp, String>),
            }
            
            let selected = tokio::select! {
                () = &mut poll_wait => {
                    SelectResult::Timer
                },
                result = poll_pps_signal(self.index.as_raw_fd()) => {
                    SelectResult::PpsSignal(result)
                },
            };

            let actions = match selected {
                SelectResult::PpsSignal(result) => {
                    match accept_pps_time(result) {
                        AcceptResult::Accept(recv_timestamp) => {
                            let send_timestamp = match self.last_send_timestamp {
                                Some(ts) => ts,
                                None => {
                                    debug!(
                                        "we received a PPS signal without having sent one; discarding"
                                    );
                                    continue;
                                }
                            };

                            self.source.handle_incoming(
                                NtpInstant::now(),
                                send_timestamp,
                                recv_timestamp,
                            )
                        }
                        AcceptResult::Ignore => PpsSourceActionIterator::default(),

                    }
                }
                SelectResult::Timer => {
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

pub fn from_unix_timestamp(unix_timestamp: u64, nanos: u32) -> NtpTimestamp {
    const UNIX_TO_NTP_OFFSET: u64 = 2_208_988_800; // Offset in seconds between Unix epoch and NTP epoch
    const NTP_SCALE_FRAC: u64 = 4_294_967_296; // 2^32 for scaling nanoseconds to fraction

    // Calculate NTP seconds
    let ntp_seconds = unix_timestamp + UNIX_TO_NTP_OFFSET;

    // Calculate the fractional part of the NTP timestamp
    let fraction = ((nanos as u64 * NTP_SCALE_FRAC) / 1_000_000_000) as u64;

    // Combine NTP seconds and fraction to form the complete NTP timestamp
    let timestamp = (ntp_seconds << 32) | fraction;

    println!("Unix Timestamp: {}, Nanos: {}, NTP Seconds: {}, Fraction: {}", unix_timestamp, nanos, ntp_seconds, fraction);
    println!("Combined NTP Timestamp: {:#018X}", timestamp);

    NtpTimestamp::from_fixed_int(timestamp)
}
