use std::io;
use std::{future::Future, marker::PhantomData, pin::Pin};
use tokio::time::{Instant, Sleep};

use ntp_proto::{
    GpsSource, GpsSourceActionIterator, NtpClock, NtpDuration, NtpInstant, NtpTimestamp
};

use tracing::{error, info, instrument, warn, Instrument, Span};

use crate::daemon::ntp_source::MsgForSystem;

use super::gps_without_gpsd::GPS;

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
        // info!("running gps source task:");
        loop {
            enum SelectResult {
                Timer,
                Recv(io::Result<Option<f64>>),
            }
            let selected = tokio::select! {
                () = &mut poll_wait => {
                    SelectResult::Timer
                },
                // result = self.gps.current_data() => SelectResult::Recv(result)
                result = self.gps.current_data() => {
                    if result.is_err() {
                        SelectResult::Recv(Err(result.unwrap_err()))
                    } else {
                        SelectResult::Recv(result)
                    }
                }
                // result = match gps.current_data() {
                //     Ok(Some(offset)) => SelectResult::Recv(result),
                //     // Ok(None) => continue,
                //     Err(e) => {
                //         eprintln!("Error processing GPS data: {}", e);
                //     }
                // }

            };

            let actions = match selected {
                SelectResult::Recv(result) => {
                    //tracing::debug!("accept gps time stamp");
                    // match result {
                    //     Ok(None) => continue,
                    //     Err(e) => info!("there was an error"),
                    //     Some(result) => {
                    //     //    match accept_gps_time::<>(result) {
                    //     //         AcceptResult::Accept(offset) => {
                    //     //             //info!("gps time has result");
                    //     //             // let send_timestamp = match self.last_send_timestamp {
                    //     //             //     Some(ts) => ts,
                    //     //             //     None => {
                    //     //             //         debug!(
                    //     //             //             "we received a message without having sent one; discarding"
                    //     //             //         );
                    //     //             //         continue;
                    //     //             //     }
                    //     //             // };
                    //     //             println!("offset: {:?}", offset);
                    //     //             self.source.handle_incoming(
                    //     //                 NtpInstant::now(),
                    //     //                 offset,
                    //     //             )
                    //     //         }
                            
                    //     //         AcceptResult::Ignore => GpsSourceActionIterator::default(),
                    //     //     }
                    //     GpsSourceActionIterator::default()
                    //     }
                    // }
                    match result {
                        Ok(Some(data)) => {
                            // Process GPS data
                            println!("Offset between GPS time and system time: {:.6} seconds", data);
                            match accept_gps_time::<>(result) {
                                            AcceptResult::Accept(offset) => {
                                                println!("offset: {:?}", offset);
                                                self.source.handle_incoming(NtpInstant::now(),offset,) 
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
            
            // info!("retrieved actions");
            for action in actions {
                match action {
                    ntp_proto::GpsSourceAction::Send() => {
                        //info!("some timer things")
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
                        //info!("update source action")
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
        info!("spawning gps source?");
        tokio::spawn(
            (async move {
               
                let (source, initial_actions)  = GpsSource::new();
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
    Accept(NtpDuration),
    Ignore,
}

pub fn from_seconds(seconds: f64) -> NtpDuration {
    let whole_seconds = seconds as i64;
    let fraction = seconds.fract();
    let ntp_fraction = (fraction * (1u64 << 32) as f64) as u32;

    println!("Seconds: {}, Whole seconds: {}, Fraction: {}", seconds, whole_seconds, ntp_fraction);

    NtpDuration::from_seconds(seconds)
}

fn parse_gps_time(data: &Option<f64>) -> Result<NtpDuration, Box<dyn std::error::Error>> {
    if let Some(offset) = data {
        let ntp_duration = from_seconds(*offset);
        Ok(ntp_duration)
    } else {
        Err("Failed to parse GPS time".into())
    }
}

fn accept_gps_time(
    result: io::Result<Option<f64>>,
) -> AcceptResult {
    match result {
        Ok(data) => {
            println!("data: {:?}", data);
            match parse_gps_time(&data) {
                Ok(gps_duration) => AcceptResult::Accept(gps_duration),
                Err(_) => AcceptResult::Ignore,
            }
        }
        Err(receive_error) => {
            warn!(?receive_error, "could not receive GPS data");

            AcceptResult::Ignore
        }
    }
}

// fn parse_gps_time(data: &std::option::Option<f64>) -> Result<NtpDuration, Box<dyn std::error::Error>> {
//     // Implement the logic to parse GPS time from the GPSData struct.
//     // This is a placeholder implementation.
//     info!(data);
//     println!("in parse_gps_time: data = {:?}", data);
//     let unix_timestamp =  Some(data.unwrap() as i64);
//     // Handle the Option<u64>
//     let ntp_timestamp = match unix_timestamp {
//         Some(ts) => from_unix_timestamp(ts),
//         None => return Err("Failed to parse GPS time".into()),
//     };

//     //let ntpTimestamp = from_unix_timestamp(unix_timestamp);


//  // Replace this with actual parsing logic
//     Ok(ntp_timestamp)
// }

// pub fn from_unix_timestamp(unix_timestamp: i64) -> NtpDuration {
//     const UNIX_TO_NTP_OFFSET: i64 = 2_208_988_800; 
//     let ntp_seconds = unix_timestamp + UNIX_TO_NTP_OFFSET;

//     let fraction = 0u32;

//     let timestamp = (ntp_seconds << 32) | (fraction as i64);

//     NtpDuration::from_fixed_int(timestamp)
// }

