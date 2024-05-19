use std::{future::Future, marker::PhantomData, net::SocketAddr, pin::Pin};
use tokio::time::{Instant, Sleep};
use gpsd_client::*;

use ntp_proto::{
    NtpClock, NtpInstant, NtpTimestamp,
     GpsSourceActionIterator, GpsSource
};
#[cfg(target_os = "linux")]

use timestamped_socket::socket::{ Connected, Socket};

use tracing::{debug, error, instrument, warn, Instrument, Span};
use chrono::DateTime;

use crate::daemon::ntp_source::MsgForSystem;

use super::{config::TimestampMode, exitcode, ntp_source::SourceChannels, spawn::SourceId, util::convert_net_timestamp};

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
    channels:SourceChannels,

    source: GpsSource,

    // we don't store the real origin timestamp in the packet, because that would leak our
    // system time to the network (and could make attacks easier). So instead there is some
    // garbage data in the origin_timestamp field, and we need to track and pass along the
    // actual origin timestamp ourselves.
    /// Timestamp of the last packet that we sent
    last_send_timestamp: Option<NtpTimestamp>,
    gps: GPS,
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
                Recv(Result<GPSData, GPSError>),
            }
           
            let selected = tokio::select! {
                () = &mut poll_wait => {
                    SelectResult::Timer
                },
                result = async{self.gps.current_data()} => SelectResult::Recv(result)
               
               
            };

            let actions = match selected {
                SelectResult::Recv(result) => {
                    tracing::debug!("accept gps time stamp");
                    match accept_gps_time::<C>(result) {
                        AcceptResult::Accept(recv_timestamp) => {
                            let send_timestamp = match self.last_send_timestamp {
                                Some(ts) => ts,
                                None => {
                                    debug!(
                                        "we received a message without having sent one; discarding"
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
                       
                        AcceptResult::Ignore => GpsSourceActionIterator::default(),
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
                    ntp_proto::GpsSourceAction::Send(packet) => {

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
        gps: GPS,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(
            (async move {
               
                let (source, initial_actions)  = GpsSource::new();
                let poll_wait = tokio::time::sleep(std::time::Duration::default());
                tokio::pin!(poll_wait);

                for action in initial_actions {
                    match action {
                        ntp_proto::GpsSourceAction::Send(_) => {
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


                let mut process = GpsSourceTask {
                    _wait: PhantomData,
                    index,
                    clock,
                    channels,
                    source,
                    gps,
                    last_send_timestamp: None,
                };

                process.run(poll_wait).await;
            })
            .instrument(Span::current()),
        )
    }
}

#[derive(Debug)]
enum AcceptResult {
    Accept(NtpTimestamp),
    Ignore,
}

fn accept_gps_time<'a, C: NtpClock>(
    result: Result<GPSData, GPSError>,
) -> AcceptResult {
    match result {
        Ok(data) => {

            match parse_gps_time(&data) {
                Ok(gps_time) => AcceptResult::Accept(gps_time),
                Err(_) => AcceptResult::Ignore,
            }
        }
        Err(receive_error) => {
            warn!(?receive_error, "could not receive GPS data");

            // Here you might want to handle specific errors from the GPS library,
            // for now we'll just log and ignore them
            AcceptResult::Ignore
        }
    }
}

fn parse_gps_time(data: &GPSData) -> Result<NtpTimestamp, Box<dyn std::error::Error>> {
    // Implement the logic to parse GPS time from the GPSData struct.
    // This is a placeholder implementation.
    let unix_timestamp = match DateTime::parse_from_rfc3339(&data.time) {
        Ok(dt) => Some(dt.timestamp() as u64),
        Err(_) => None,
    };

    // Handle the Option<u64>
    let ntp_timestamp = match unix_timestamp {
        Some(ts) => from_unix_timestamp(ts),
        None => return Err("Failed to parse GPS time".into()),
    };

    //let ntpTimestamp = from_unix_timestamp(unix_timestamp);


 // Replace this with actual parsing logic
    Ok(ntp_timestamp)
}

pub fn from_unix_timestamp(unix_timestamp: u64) -> NtpTimestamp {
    const UNIX_TO_NTP_OFFSET: u64 = 2_208_988_800; // Offset in seconds between Unix epoch and NTP epoch
    // Calculate NTP seconds
    let ntp_seconds = unix_timestamp + UNIX_TO_NTP_OFFSET;

    // Calculate the fractional part of the NTP timestamp
    let fraction = 0u32;

    // Combine NTP seconds and fraction to form the complete NTP timestamp
    let timestamp = ((ntp_seconds as u64) << 32) | (fraction as u64);

    println!("Unix Timestamp: {}, NTP Seconds: {}, Fraction: {}", unix_timestamp, ntp_seconds, fraction);
    println!("Combined NTP Timestamp: {:#018X}", timestamp);

    NtpTimestamp::from_fixed_int(timestamp)
}
