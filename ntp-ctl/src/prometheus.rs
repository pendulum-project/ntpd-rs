use ntp_daemon::{observer::WrappedSocketAddr, ObservablePeerState, ObservableState};
use prometheus_client::{
    encoding::text::{Encode, SendSyncEncodeMetric},
    metrics::{
        counter::Counter,
        family::Family,
        gauge::{Atomic, Gauge},
    },
    registry::{Registry, Unit},
};

#[derive(Clone, PartialEq, Eq, Hash, Encode)]
struct PeerLabels {
    address: String,
}

#[derive(Clone, PartialEq, Eq, Hash, Encode)]
struct ServerLabels {
    listen_address: WrappedSocketAddr,
}

#[derive(Default)]
pub(crate) struct Metrics {
    system_poll_interval: Gauge<f64>,
    system_poll_interval_exp: Gauge<f64>,
    system_precision: Gauge<f64>,
    system_accumulated_steps: Gauge<f64>,
    system_accumulated_steps_threshold: Gauge<f64>,
    system_leap_indicator: Gauge,
    peer_uptime: Family<PeerLabels, Gauge>,
    peer_poll_interval: Family<PeerLabels, Gauge<f64>>,
    peer_poll_interval_exp: Family<PeerLabels, Gauge<f64>>,
    peer_reachability_status: Family<PeerLabels, Gauge>,
    peer_offset: Family<PeerLabels, Gauge<f64>>,
    peer_delay: Family<PeerLabels, Gauge<f64>>,
    peer_dispersion: Family<PeerLabels, Gauge<f64>>,
    peer_jitter: Family<PeerLabels, Gauge<f64>>,
    server_received_packets: Family<ServerLabels, Counter>,
    server_accepted_packets: Family<ServerLabels, Counter>,
    server_denied_packets: Family<ServerLabels, Counter>,
    server_rate_limited_packets: Family<ServerLabels, Counter>,
    server_response_send_errors: Family<ServerLabels, Counter>,
}

impl Metrics {
    pub(crate) fn fill(&self, data: &ObservableState) {
        self.system_poll_interval.set(
            data.system
                .time_snapshot
                .poll_interval
                .as_duration()
                .to_seconds(),
        );
        self.system_poll_interval_exp
            .set(data.system.time_snapshot.poll_interval.as_log() as f64);
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
            .set(data.system.time_snapshot.leap_indicator as u64);

        for peer in &data.peers {
            if let ObservablePeerState::Observable {
                statistics,
                reachability,
                uptime,
                poll_interval,
                address,
                ..
            } = peer
            {
                let labels = PeerLabels {
                    address: address.clone(),
                };
                self.peer_uptime
                    .get_or_create(&labels)
                    .set(uptime.as_secs());
                self.peer_poll_interval
                    .get_or_create(&labels)
                    .set(poll_interval.as_duration().to_seconds());
                self.peer_poll_interval_exp
                    .get_or_create(&labels)
                    .set(poll_interval.as_log() as f64);
                self.peer_reachability_status
                    .get_or_create(&labels)
                    .set(reachability.reachability_score() as u64);
                self.peer_offset
                    .get_or_create(&labels)
                    .set(statistics.offset.to_seconds());
                self.peer_delay
                    .get_or_create(&labels)
                    .set(statistics.delay.to_seconds());
                self.peer_dispersion
                    .get_or_create(&labels)
                    .set(statistics.dispersion.to_seconds());
                self.peer_jitter
                    .get_or_create(&labels)
                    .set(statistics.jitter);
            }
        }

        for server in &data.servers {
            let labels = ServerLabels {
                listen_address: server.address,
            };

            self.server_received_packets
                .get_or_create(&labels)
                .inner()
                .set(server.stats.received_packets.get());
            self.server_accepted_packets
                .get_or_create(&labels)
                .inner()
                .set(server.stats.accepted_packets.get());
            self.server_denied_packets
                .get_or_create(&labels)
                .inner()
                .set(server.stats.denied_packets.get());
            self.server_rate_limited_packets
                .get_or_create(&labels)
                .inner()
                .set(server.stats.rate_limited_packets.get());
            self.server_response_send_errors
                .get_or_create(&labels)
                .inner()
                .set(server.stats.response_send_errors.get());
        }
    }
}

pub(crate) fn create_registry(metrics: &Metrics) -> Registry<Box<dyn SendSyncEncodeMetric>> {
    let mut registry = <Registry>::with_prefix("ntp");

    let system = registry.sub_registry_with_prefix("system");

    system.register_with_unit(
        "poll_interval",
        "Time between polls of the system",
        Unit::Seconds,
        Box::new(metrics.system_poll_interval.clone()),
    );
    system.register(
        "poll_interval",
        "Exponent of time between poll intervals",
        Box::new(metrics.system_poll_interval_exp.clone()),
    );
    system.register_with_unit(
        "precision",
        "Precision of the local clock",
        Unit::Seconds,
        Box::new(metrics.system_precision.clone()),
    );
    system.register_with_unit(
        "accumulated_steps",
        "Accumulated amount of seconds that the system needed to jump the time",
        Unit::Seconds,
        Box::new(metrics.system_accumulated_steps.clone()),
    );
    system.register_with_unit(
        "accumulated_steps_threshold",
        "Threshold for the accumulated step amount at which the NTP daemon will exit (or -1 if no threshold was set)",
        Unit::Seconds,
        Box::new(metrics.system_accumulated_steps_threshold.clone()),
    );
    system.register(
        "leap_indicator",
        "Indicates that a leap second will take place",
        Box::new(metrics.system_leap_indicator.clone()),
    );

    let peer = registry.sub_registry_with_prefix("peer");

    peer.register_with_unit(
        "uptime",
        "Time since the peer was started",
        Unit::Seconds,
        Box::new(metrics.peer_uptime.clone()),
    );

    peer.register_with_unit(
        "poll_interval",
        "Time between polls of the peer",
        Unit::Seconds,
        Box::new(metrics.peer_poll_interval.clone()),
    );

    peer.register(
        "poll_interval",
        "Exponent of time between polls of the peer",
        Box::new(metrics.peer_poll_interval_exp.clone()),
    );

    peer.register(
        "reachability_status",
        "Number of polls until the upstream server is unreachable, zero if it is",
        Box::new(metrics.peer_reachability_status.clone()),
    );

    peer.register_with_unit(
        "offset",
        "Offset between the upstream server and system time",
        Unit::Seconds,
        Box::new(metrics.peer_offset.clone()),
    );

    peer.register_with_unit(
        "delay",
        "Current round-trip delay to the upstream server",
        Unit::Seconds,
        Box::new(metrics.peer_delay.clone()),
    );

    peer.register_with_unit(
        "dispersion",
        "Maximum error of the clock",
        Unit::Seconds,
        Box::new(metrics.peer_dispersion.clone()),
    );

    peer.register_with_unit(
        "jitter",
        "Variance of network latency",
        Unit::Seconds,
        Box::new(metrics.peer_jitter.clone()),
    );

    let server = registry.sub_registry_with_prefix("server");

    server.register(
        "received_packets",
        "Number of incoming received packets",
        Box::new(metrics.server_received_packets.clone()),
    );

    server.register(
        "accepted_packets",
        "Number of packets accepted",
        Box::new(metrics.server_accepted_packets.clone()),
    );

    server.register(
        "denied_packets",
        "Number of denied packets",
        Box::new(metrics.server_denied_packets.clone()),
    );

    server.register(
        "rate_limited_packets",
        "Number of rate limited packets",
        Box::new(metrics.server_rate_limited_packets.clone()),
    );

    server.register(
        "response_send_errors",
        "Number of packets where there was an error responding",
        Box::new(metrics.server_response_send_errors.clone()),
    );

    registry
}
