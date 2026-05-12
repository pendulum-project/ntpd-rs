use core::{future::poll_fn, task::Poll, time::Duration};

use ntp_proto::{
    ClockId, Measurement, NtpDuration, NtpLeapIndicator, NtpTimestamp, SourceController,
};
use statime_wire::{TimeInterval, Timestamp};

use crate::{
    CsptpManager, StateMutex,
    messages::{CsptpMessage, CsptpResponseTlv, CsptpStatusTlv, MAX_MESSAGE_SIZE},
};

/// A single CSPTP source.
pub struct CsptpSource<'a, Mutex, Controller> {
    config: CsptpSourceConfig,
    local_clock: ClockId,
    remote_clock: ClockId,
    manager: &'a CsptpManager<Mutex>,
    controller: Controller,
}

#[derive(Debug, Copy, Clone)]
#[expect(
    clippy::enum_variant_names,
    reason = "The common prefix is intentional to have these be descriptive of the state"
)]
enum RequestState {
    WaitingForResponse,
    WaitingForFollowUp {
        request_recv_time: Timestamp,
        response_recv_time: Timestamp,
        request_correction: TimeInterval,
        response_correction: TimeInterval,
        leap_indication: NtpLeapIndicator,
        status: Option<CsptpStatusTlv>,
        ptp_timescale: bool,
        time_traceable: bool,
        frequency_traceable: bool,
    },
    WaitingForResponseHaveFollowUp {
        remote_send_time: Timestamp,
        response_correction: TimeInterval,
    },
}

struct CsptpRawMeasurement {
    request_send_time: Timestamp,
    request_recv_time: Timestamp,
    response_send_time: Timestamp,
    response_recv_time: Timestamp,
    request_correction: TimeInterval,
    response_correction: TimeInterval,
    leap_indication: NtpLeapIndicator,
    status: Option<CsptpStatusTlv>,
    ptp_timescale: bool,
    time_traceable: bool,
    frequency_traceable: bool,
}

// FIXME: Remove this once we have more properly abstracted over timescales in the algorithm layer.
fn convert_to_ntp(ts: Timestamp) -> NtpTimestamp {
    // Epoch offset between NTP and UNIX timescales
    const EPOCH_OFFSET: u32 = (70 * 365 + 17) * 86400;
    // Offset between TAI and UTC
    const UTC_OFFSET: u32 = 37;
    #[expect(clippy::cast_possible_truncation, reason = "Truncation is intentional")]
    NtpTimestamp::from_seconds_nanos_since_ntp_era(
        EPOCH_OFFSET
            .wrapping_add(ts.seconds() as u32)
            .wrapping_sub(UTC_OFFSET),
        ts.nanos(),
    )
}

// FIXME: Remove this once we have more proper time abstractions.
fn add_correction(ts: Timestamp, correction: TimeInterval) -> Timestamp {
    let correction_nanos = correction.0 >> 16;
    let correction_seconds = correction_nanos.div_euclid(1_000_000_000);
    let correction_nanos = correction_nanos.rem_euclid(1_000_000_000);

    let intermediate_nanos = ts.nanos().wrapping_add(
        correction_nanos
            .try_into()
            .expect("Nanosecond correction should already be in a proper range for an u32."),
    );

    let corrected_seconds = ts
        .seconds()
        .wrapping_add_signed(correction_seconds)
        .wrapping_add(intermediate_nanos.div_euclid(1_000_000_000).into());
    let corrected_nanos = intermediate_nanos.rem_euclid(1_000_000_000);

    Timestamp::new(corrected_seconds, corrected_nanos)
        .expect("Calculated nanoseconds should be between 0 and 1_000_000_000")
}

impl<'a, Mutex, Controller> CsptpSource<'a, Mutex, Controller> {
    /// Setup a new csptp source.
    pub fn new(
        local_clock: ClockId,
        remote_clock: ClockId,
        config: CsptpSourceConfig,
        manager: &'a CsptpManager<Mutex>,
        controller: Controller,
    ) -> Self {
        CsptpSource {
            config,
            local_clock,
            remote_clock,
            manager,
            controller,
        }
    }
}

impl<Mutex: StateMutex, Controller: SourceController> CsptpSource<'_, Mutex, Controller> {
    /// Run the port
    ///
    /// # Errors
    ///
    /// Errors during send or recv operations are absorbed. Errors creating the
    /// socket will abort the polling process and be propagated upwards.
    #[allow(
        clippy::missing_panics_doc,
        reason = "Function should never panic unless there is an implementation fault"
    )]
    pub async fn run<Error, Socket: ClientSocket, F: Future<Output = ()>, R: rand::Rng>(
        &mut self,
        shutdown: impl Future<Output = ()>,
        mut create_socket: impl FnMut() -> Result<Socket, Error>,
        mut sleep: impl FnMut(Duration) -> F,
        mut rng: impl FnMut() -> R,
    ) -> Result<(), Error> {
        let mut shutdown = core::pin::pin!(shutdown);

        let mut poller = core::pin::pin!(async {
            let mut poll_interval = core::pin::pin!(sleep(Duration::ZERO));
            let mut sequence_id = 0u16;

            loop {
                poll_interval.as_mut().await;

                let next_poll = rng()
                    .gen_range((self.config.poll_interval * 9)..=(self.config.poll_interval * 11))
                    / 10;
                poll_interval.set(sleep(next_poll));

                let request_id = sequence_id;
                sequence_id = sequence_id.wrapping_add(1);

                let mut request_buffer = [0u8; 8];
                let request =
                    CsptpMessage::new_request(&mut request_buffer, self.config.domain, request_id)
                        .expect(
                            "Should have sufficient space in request_buffer for CSPTP request TLVs",
                        );
                let mut send_buffer = [0u8; MAX_MESSAGE_SIZE];
                let send_size = request
                    .serialize(&mut send_buffer)
                    .expect("Request message should fit send buffer");

                let mut socket = create_socket()?;
                let Ok(send_timestamp) = socket.send_event(&send_buffer[..send_size]).await else {
                    // FIXME: Add logging for this.
                    continue;
                };

                let Some(measurement) = ({
                    let mut response_timeout =
                        core::pin::pin!(sleep(self.config.response_interval));
                    let mut handle_response =
                        core::pin::pin!(self.collect_response(socket, request_id, send_timestamp));
                    poll_fn(|cx| {
                        if response_timeout.as_mut().poll(cx).is_ready() {
                            // FIXME: Log the timeout.
                            Poll::Ready(None)
                        } else if let Poll::Ready(measurement) = handle_response.as_mut().poll(cx) {
                            Poll::Ready(Some(measurement))
                        } else {
                            Poll::Pending
                        }
                    })
                    .await
                }) else {
                    continue;
                };

                self.controller.set_usable(true);
                self.controller.handle_measurement(Measurement {
                    sender_id: self.local_clock,
                    receiver_id: self.remote_clock,
                    sender_ts: convert_to_ntp(add_correction(
                        measurement.request_send_time,
                        measurement.request_correction,
                    )),
                    receiver_ts: convert_to_ntp(measurement.request_recv_time),
                    root_delay: NtpDuration::ZERO,
                    root_dispersion: NtpDuration::ZERO,
                    leap: measurement.leap_indication,
                    precision: 0,
                });
                self.controller.handle_measurement(Measurement {
                    sender_id: self.remote_clock,
                    receiver_id: self.local_clock,
                    sender_ts: convert_to_ntp(add_correction(
                        measurement.response_send_time,
                        measurement.response_correction,
                    )),
                    receiver_ts: convert_to_ntp(measurement.response_recv_time),
                    root_delay: NtpDuration::ZERO,
                    root_dispersion: NtpDuration::ZERO,
                    leap: measurement.leap_indication,
                    precision: 0,
                });
                if let Some(status) = measurement.status {
                    self.manager.state.with_mut(|state| {
                        if state.active_source == Some(self.remote_clock) {
                            state.csptp_state.grandmaster_identity = status.grandmaster_identity;
                            state.csptp_state.grandmaster_priority_1 = status.grandmaster_priority1;
                            state.csptp_state.grandmaster_priority_2 = status.grandmaster_priority2;
                            state.csptp_state.grandmaster_clock_quality =
                                status.grandmaster_clock_quality;
                            state.csptp_state.steps_removed = status.steps_removed + 1;
                            state.csptp_state.ptp_timescale = measurement.ptp_timescale;
                            state.csptp_state.time_traceable = measurement.time_traceable;
                            state.csptp_state.frequency_traceable = measurement.frequency_traceable;
                        }
                    });
                }
            }
        });

        poll_fn(|cx| {
            // Shutdown has priority, that needs to be polled first.
            if shutdown.as_mut().poll(cx).is_ready() {
                Poll::Ready(Ok(()))
            } else if let Poll::Ready(result) = poller.as_mut().poll(cx) {
                Poll::Ready(result)
            } else {
                Poll::Pending
            }
        })
        .await
    }

    #[expect(
        clippy::too_many_lines,
        reason = "This is mostly shifting data around, which is a bit verbose but not all that complicated."
    )]
    async fn collect_response(
        &mut self,
        mut socket: impl ClientSocket,
        request_id: u16,
        send_timestamp: Timestamp,
    ) -> CsptpRawMeasurement {
        let mut state = RequestState::WaitingForResponse;

        loop {
            let mut recv_buffer = [0u8; MAX_MESSAGE_SIZE];
            let Ok(recv_result) = socket.recv(&mut recv_buffer).await else {
                // FIXME: Add logging for this.
                continue;
            };
            let packet = &recv_buffer[..recv_result.bytes_read];

            let Ok(message) = CsptpMessage::deserialize(packet) else {
                // FIXME: Add logging for this.
                continue;
            };

            if message.header.domain_number != self.config.domain
                || message.header.sequence_id != request_id
            {
                // FIXME: Add logging for this.
                continue;
            }

            let measurement = match message.body {
                statime_wire::MessageBody::Sync(sync_message) => {
                    let Some(response_tlv) = message
                        .suffix
                        .tlvs()
                        .find_map(|tlv| CsptpResponseTlv::try_from(&tlv))
                    else {
                        // Someone is sending us requests for some reason, ignore those.
                        // FIXME: Add logging for this.
                        continue;
                    };

                    let Some(recv_timestamp) = recv_result.timestamp else {
                        // Ignore sync with missing timestamp. This may be caused by
                        // someone sending sync messages over the general port.
                        // FIXME: Add logging for this.
                        continue;
                    };

                    let leap_indication = if message.header.leap59 {
                        NtpLeapIndicator::Leap59
                    } else if message.header.leap61 {
                        NtpLeapIndicator::Leap61
                    } else {
                        NtpLeapIndicator::NoWarning
                    };

                    let status = message
                        .suffix
                        .tlvs()
                        .find_map(|tlv| CsptpStatusTlv::try_from(&tlv));

                    if message.header.two_step_flag {
                        match state {
                            RequestState::WaitingForResponse => {
                                // Need a follow_up, so wait for that.
                                state = RequestState::WaitingForFollowUp {
                                    request_recv_time: response_tlv.req_ingress_timestamp,
                                    response_recv_time: recv_timestamp,
                                    request_correction: response_tlv.req_correction_field,
                                    response_correction: message.header.correction_field,
                                    leap_indication,
                                    status,
                                    ptp_timescale: message.header.ptp_timescale,
                                    time_traceable: message.header.time_tracable,
                                    frequency_traceable: message.header.frequency_tracable,
                                };
                                continue;
                            }
                            RequestState::WaitingForFollowUp { .. } => {
                                // Duplicate sync, ignore
                                // FIXME: Add logging for this.
                                continue;
                            }
                            RequestState::WaitingForResponseHaveFollowUp {
                                remote_send_time,
                                response_correction,
                            } => CsptpRawMeasurement {
                                request_send_time: send_timestamp,
                                request_recv_time: response_tlv.req_ingress_timestamp,
                                response_send_time: remote_send_time,
                                response_recv_time: recv_timestamp,
                                request_correction: response_tlv.req_correction_field,
                                response_correction: TimeInterval(
                                    response_correction
                                        .0
                                        .saturating_add(message.header.correction_field.0),
                                ),
                                leap_indication,
                                status,
                                ptp_timescale: message.header.ptp_timescale,
                                time_traceable: message.header.time_tracable,
                                frequency_traceable: message.header.frequency_tracable,
                            },
                        }
                    } else {
                        CsptpRawMeasurement {
                            request_send_time: send_timestamp,
                            request_recv_time: response_tlv.req_ingress_timestamp,
                            response_send_time: sync_message.origin_timestamp,
                            response_recv_time: recv_timestamp,
                            request_correction: response_tlv.req_correction_field,
                            response_correction: message.header.correction_field,
                            leap_indication,
                            status,
                            ptp_timescale: message.header.ptp_timescale,
                            time_traceable: message.header.time_tracable,
                            frequency_traceable: message.header.frequency_tracable,
                        }
                    }
                }
                statime_wire::MessageBody::FollowUp(follow_up_message) => {
                    match state {
                        RequestState::WaitingForResponse => {
                            // Need the response also, so wait for that.
                            state = RequestState::WaitingForResponseHaveFollowUp {
                                remote_send_time: follow_up_message.precise_origin_timestamp,
                                response_correction: message.header.correction_field,
                            };
                            continue;
                        }
                        RequestState::WaitingForFollowUp {
                            request_recv_time,
                            response_recv_time,
                            request_correction,
                            response_correction,
                            leap_indication,
                            status,
                            ptp_timescale,
                            time_traceable,
                            frequency_traceable,
                        } => CsptpRawMeasurement {
                            request_send_time: send_timestamp,
                            request_recv_time,
                            response_send_time: follow_up_message.precise_origin_timestamp,
                            response_recv_time,
                            request_correction,
                            response_correction: TimeInterval(
                                response_correction
                                    .0
                                    .saturating_add(message.header.correction_field.0),
                            ),
                            leap_indication,
                            status,
                            ptp_timescale,
                            time_traceable,
                            frequency_traceable,
                        },
                        RequestState::WaitingForResponseHaveFollowUp { .. } => {
                            // Duplicate message, ignoring.
                            // FIXME: Add logging for this.
                            continue;
                        }
                    }
                }
                _ => {
                    // FIXME: Add logging for this.
                    continue;
                }
            };

            return measurement;
        }
    }
}

/// Configuration for a single CSPTP source
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct CsptpSourceConfig {
    /// Average interval between requests to the server.
    pub poll_interval: Duration,
    /// Time to wait before declaring that a response from the server won't arrive.
    pub response_interval: Duration,
    /// CSPTP domain to use
    pub domain: u8,
}

impl Default for CsptpSourceConfig {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_millis(1000),
            response_interval: Duration::from_millis(500),
            domain: 128,
        }
    }
}

/// Result from receiving a packet from the server socket.
pub struct ClientRecvResult {
    /// Number of bytes that were read
    pub bytes_read: usize,
    /// Timestamp at which the packet arrived, if known.
    pub timestamp: Option<Timestamp>,
}

/// A general network socket for a CSPTP client.
pub trait ClientSocket {
    /// Type for errors occuring during socket operations.
    type Error: core::fmt::Debug;

    /// Receive a packet from the socket.
    ///
    /// MUST be cancel safe.
    fn recv(
        &mut self,
        buf: &mut [u8],
    ) -> impl Future<Output = Result<ClientRecvResult, Self::Error>>;
    /// Send a packet on the event socket, waiting for a timestamp.
    fn send_event(&mut self, buf: &[u8]) -> impl Future<Output = Result<Timestamp, Self::Error>>;
}
