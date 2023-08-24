pub mod exporter;

use std::{
    net::SocketAddr,
    sync::atomic::{AtomicU64, Ordering},
};

use crate::daemon::{ObservablePeerState, ObservableState};
use ntp_os_clock::DefaultNtpClock;
use ntp_proto::NtpClock;
use prometheus_client::{
    encoding::{EncodeLabelSet, EncodeLabelValue},
    metrics::{counter::Counter, family::Family, gauge::Gauge},
    registry::{Registry, Unit},
};

#[derive(Debug, Clone, PartialEq, Eq, Hash, EncodeLabelSet)]
struct PeerLabels {
    address: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, EncodeLabelSet)]
struct ServerLabels {
    listen_address: WrappedSocketAddr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WrappedSocketAddr(SocketAddr);

impl From<SocketAddr> for WrappedSocketAddr {
    fn from(s: SocketAddr) -> Self {
        WrappedSocketAddr(s)
    }
}

impl EncodeLabelValue for WrappedSocketAddr {
    fn encode(
        &self,
        encoder: &mut prometheus_client::encoding::LabelValueEncoder,
    ) -> Result<(), std::fmt::Error> {
        use std::fmt::Write;

        encoder.write_fmt(format_args!("{}", &self.0))
    }
}

#[derive(Default)]
pub struct Metrics {
    system_poll_interval: Gauge<f64, AtomicU64>,
    system_precision: Gauge<f64, AtomicU64>,
    system_accumulated_steps: Gauge<f64, AtomicU64>,
    system_accumulated_steps_threshold: Gauge<f64, AtomicU64>,
    system_leap_indicator: Gauge,
    peer_last_update: Family<PeerLabels, Gauge<f64, AtomicU64>>,
    peer_poll_interval: Family<PeerLabels, Gauge<f64, AtomicU64>>,
    peer_unanswered_polls: Family<PeerLabels, Gauge>,
    peer_offset: Family<PeerLabels, Gauge<f64, AtomicU64>>,
    peer_uncertainty: Family<PeerLabels, Gauge<f64, AtomicU64>>,
    peer_delay: Family<PeerLabels, Gauge<f64, AtomicU64>>,
    server_received_packets: Family<ServerLabels, Counter>,
    server_accepted_packets: Family<ServerLabels, Counter>,
    server_denied_packets: Family<ServerLabels, Counter>,
    server_ignored_packets: Family<ServerLabels, Counter>,
    server_rate_limited_packets: Family<ServerLabels, Counter>,
    server_response_send_errors: Family<ServerLabels, Counter>,
}

impl Metrics {
    pub fn fill(&self, data: &ObservableState) {
        let clock = DefaultNtpClock::realtime();

        self.system_poll_interval.set(
            data.system
                .time_snapshot
                .poll_interval
                .as_duration()
                .to_seconds(),
        );
        self.system_precision
            .set(data.system.time_snapshot.precision.to_seconds());
        self.system_accumulated_steps
            .set(data.system.time_snapshot.accumulated_steps.to_seconds());
        self.system_accumulated_steps_threshold.set(
            data.system
                .accumulated_steps_threshold
                .map(|v| v.to_seconds())
                .unwrap_or(-1.0),
        );
        self.system_leap_indicator
            .set(data.system.time_snapshot.leap_indicator as i64);

        for peer in &data.peers {
            if let ObservablePeerState::Observable {
                timedata,
                unanswered_polls,
                poll_interval,
                address,
                ..
            } = peer
            {
                let labels = PeerLabels {
                    address: address.clone(),
                };
                self.peer_last_update.get_or_create(&labels).set(
                    (timedata.last_update
                        - clock.now().expect("Unable to get current system time"))
                    .to_seconds(),
                );
                self.peer_poll_interval
                    .get_or_create(&labels)
                    .set(poll_interval.as_duration().to_seconds());
                self.peer_unanswered_polls
                    .get_or_create(&labels)
                    .set(*unanswered_polls as i64);
                self.peer_offset
                    .get_or_create(&labels)
                    .set(timedata.offset.to_seconds());
                self.peer_delay
                    .get_or_create(&labels)
                    .set(timedata.delay.to_seconds());
                self.peer_uncertainty
                    .get_or_create(&labels)
                    .set(timedata.uncertainty.to_seconds());
            }
        }

        for server in &data.servers {
            let labels = ServerLabels {
                listen_address: WrappedSocketAddr(server.address),
            };

            self.server_received_packets
                .get_or_create(&labels)
                .inner()
                .store(server.stats.received_packets.get(), Ordering::Relaxed);
            self.server_accepted_packets
                .get_or_create(&labels)
                .inner()
                .store(server.stats.accepted_packets.get(), Ordering::Relaxed);
            self.server_denied_packets
                .get_or_create(&labels)
                .inner()
                .store(server.stats.denied_packets.get(), Ordering::Relaxed);
            self.server_ignored_packets
                .get_or_create(&labels)
                .inner()
                .store(server.stats.ignored_packets.get(), Ordering::Relaxed);
            self.server_rate_limited_packets
                .get_or_create(&labels)
                .inner()
                .store(server.stats.rate_limited_packets.get(), Ordering::Relaxed);
            self.server_response_send_errors
                .get_or_create(&labels)
                .inner()
                .store(server.stats.response_send_errors.get(), Ordering::Relaxed);
        }
    }

    pub fn registry(&self) -> Registry {
        let mut registry = <Registry>::with_prefix("ntp");

        let system = registry.sub_registry_with_prefix("system");

        system.register_with_unit(
            "poll_interval",
            "Time between polls of the system",
            Unit::Seconds,
            self.system_poll_interval.clone(),
        );
        system.register_with_unit(
            "precision",
            "Precision of the local clock",
            Unit::Seconds,
            self.system_precision.clone(),
        );
        system.register_with_unit(
            "accumulated_steps",
            "Accumulated amount of seconds that the system needed to jump the time",
            Unit::Seconds,
            self.system_accumulated_steps.clone(),
        );
        system.register_with_unit(
            "accumulated_steps_threshold",
            "Threshold for the accumulated step amount at which the NTP daemon will exit (or -1 if no threshold was set)",
            Unit::Seconds,
            self.system_accumulated_steps_threshold.clone(),
        );
        system.register(
            "leap_indicator",
            "Indicates that a leap second will take place",
            self.system_leap_indicator.clone(),
        );

        let peer = registry.sub_registry_with_prefix("peer");

        peer.register_with_unit(
            "uptime",
            "Time since the peer was started",
            Unit::Seconds,
            self.peer_last_update.clone(),
        );

        peer.register_with_unit(
            "poll_interval",
            "Time between polls of the peer",
            Unit::Seconds,
            self.peer_poll_interval.clone(),
        );

        peer.register(
            "reachability_status",
            "Number of polls until the upstream server is unreachable, zero if it is",
            self.peer_unanswered_polls.clone(),
        );

        peer.register_with_unit(
            "offset",
            "Offset between the upstream server and system time",
            Unit::Seconds,
            self.peer_offset.clone(),
        );

        peer.register_with_unit(
            "delay",
            "Current round-trip delay to the upstream server",
            Unit::Seconds,
            self.peer_delay.clone(),
        );

        peer.register_with_unit(
            "uncertainty",
            "Estimated error of the clock",
            Unit::Seconds,
            self.peer_uncertainty.clone(),
        );

        let server = registry.sub_registry_with_prefix("server");

        server.register(
            "received_packets",
            "Number of incoming received packets",
            self.server_received_packets.clone(),
        );

        server.register(
            "accepted_packets",
            "Number of packets accepted",
            self.server_accepted_packets.clone(),
        );

        server.register(
            "denied_packets",
            "Number of denied packets",
            self.server_denied_packets.clone(),
        );

        server.register(
            "ignored_packets",
            "Number of packets ignored",
            self.server_ignored_packets.clone(),
        );

        server.register(
            "rate_limited_packets",
            "Number of rate limited packets",
            self.server_rate_limited_packets.clone(),
        );

        server.register(
            "response_send_errors",
            "Number of packets where there was an error responding",
            self.server_response_send_errors.clone(),
        );

        registry
    }
}
