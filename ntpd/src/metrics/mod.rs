pub mod exporter;

use crate::daemon::{ObservablePeerState, ObservableState};

struct Measurement<T> {
    labels: Vec<(&'static str, String)>,
    value: T,
}

impl<T> Measurement<T> {
    fn simple(value: T) -> Vec<Measurement<T>> {
        vec![Measurement {
            labels: Default::default(),
            value,
        }]
    }
}

#[derive(PartialEq, Eq, Clone, Copy)]
enum Unit {
    Seconds,
}

impl Unit {
    fn as_str(&self) -> &str {
        "seconds"
    }
}

enum MetricType {
    Gauge,
    Counter,
}

impl MetricType {
    fn as_str(&self) -> &str {
        match self {
            MetricType::Gauge => "gauge",
            MetricType::Counter => "counter",
        }
    }
}

fn format_metric<T: std::fmt::Display>(
    w: &mut impl std::fmt::Write,
    name: &str,
    help: &str,
    metric_type: MetricType,
    unit: Option<Unit>,
    measurements: Vec<Measurement<T>>,
) -> std::fmt::Result {
    let name = if let Some(unit) = unit {
        format!("{}_{}", name, unit.as_str())
    } else {
        name.to_owned()
    };

    // write help text
    writeln!(w, "# HELP {name} {help}.")?;

    // write type
    writeln!(w, "# TYPE {name} {}", metric_type.as_str())?;

    // write unit
    if let Some(unit) = unit {
        writeln!(w, "# UNIT {name} {}", unit.as_str())?;
    }

    // write all the measurements
    for measurement in measurements {
        w.write_str(&name)?;
        if !measurement.labels.is_empty() {
            w.write_str("{")?;

            for (offset, (label, value)) in measurement.labels.iter().enumerate() {
                let value = value
                    .replace('\\', "\\\\")
                    .replace('"', "\\\"")
                    .replace('\n', "\\n");
                write!(w, "{label}=\"{value}\"")?;
                if offset < measurement.labels.len() - 1 {
                    w.write_str(",")?;
                }
            }
            w.write_str("}")?;
        }
        w.write_str(" ")?;
        write!(w, "{}", measurement.value)?;
        w.write_str("\n")?;
    }

    Ok(())
}

macro_rules! collect_peers {
    ($from: expr, |$ident: ident| $value: expr $(,)?) => {{
        let mut data = vec![];
        for tmp in &$from.peers {
            if let crate::metrics::ObservablePeerState::Observable($ident) = tmp {
                let labels = vec![
                    ("address", $ident.address.clone()),
                    ("id", format!("{}", $ident.id)),
                ];
                let value = $value;
                data.push(Measurement { labels, value });
            }
        }
        data
    }};
}

macro_rules! collect_servers {
    ($from: expr, |$ident: ident| $value: expr $(,)?) => {{
        let mut data = vec![];
        for $ident in &$from.servers {
            let labels = vec![("listen_address", format!("{}", $ident.address))];
            let value = $value;
            data.push(Measurement { labels, value })
        }
        data
    }};
}

pub fn format_state(w: &mut impl std::fmt::Write, state: &ObservableState) -> std::fmt::Result {
    format_metric(
        w,
        "ntp_system_poll_interval",
        "Time between polls of the system",
        MetricType::Gauge,
        Some(Unit::Seconds),
        Measurement::simple(
            state
                .system
                .time_snapshot
                .poll_interval
                .as_duration()
                .to_seconds(),
        ),
    )?;

    format_metric(
        w,
        "ntp_system_precision",
        "Precision of the local clock",
        MetricType::Gauge,
        Some(Unit::Seconds),
        Measurement::simple(state.system.time_snapshot.precision.to_seconds()),
    )?;

    format_metric(
        w,
        "ntp_system_accumulated_steps",
        "Accumulated amount of seconds that the system needed to jump the time",
        MetricType::Gauge,
        Some(Unit::Seconds),
        Measurement::simple(state.system.time_snapshot.accumulated_steps.to_seconds()),
    )?;

    format_metric(
        w,
        "ntp_system_accumulated_steps_threshold",
        "Threshold for the accumulated step amount at which the NTP daemon will exit (or -1 if no threshold was set)",
        MetricType::Gauge,
        Some(Unit::Seconds),
        Measurement::simple(state.system
            .accumulated_steps_threshold
            .map(|v| v.to_seconds())
            .unwrap_or(-1.0)),
    )?;

    format_metric(
        w,
        "ntp_system_leap_indicator",
        "Indicates that a leap second will take place",
        MetricType::Gauge,
        Some(Unit::Seconds),
        Measurement::simple(state.system.time_snapshot.leap_indicator as i64),
    )?;

    format_metric(
        w,
        "ntp_peer_uptime",
        "Time since the peer was started",
        MetricType::Gauge,
        Some(Unit::Seconds),
        collect_peers!(state, |p| p.poll_interval.as_duration().to_seconds()),
    )?;

    format_metric(
        w,
        "ntp_peer_poll_interval",
        "Time between polls of the peer",
        MetricType::Gauge,
        Some(Unit::Seconds),
        collect_peers!(state, |p| p.poll_interval.as_duration().to_seconds()),
    )?;

    format_metric(
        w,
        "ntp_peer_reachability_status",
        "Number of polls until the upstream server is unreachable, zero if it is",
        MetricType::Gauge,
        None,
        collect_peers!(state, |p| p.unanswered_polls),
    )?;

    format_metric(
        w,
        "ntp_peer_offset",
        "Offset between the upstream server and system time",
        MetricType::Gauge,
        Some(Unit::Seconds),
        collect_peers!(state, |p| p.timedata.offset.to_seconds()),
    )?;

    format_metric(
        w,
        "ntp_peer_delay",
        "Current round-trip delay to the upstream server",
        MetricType::Gauge,
        Some(Unit::Seconds),
        collect_peers!(state, |p| p.timedata.delay.to_seconds()),
    )?;

    format_metric(
        w,
        "ntp_peer_uncertainty",
        "Estimated error of the clock",
        MetricType::Gauge,
        Some(Unit::Seconds),
        collect_peers!(state, |p| p.timedata.uncertainty.to_seconds()),
    )?;

    format_metric(
        w,
        "ntp_server_received_packets",
        "Number of incoming received packets",
        MetricType::Counter,
        None,
        collect_servers!(state, |s| s.stats.received_packets.get()),
    )?;

    format_metric(
        w,
        "ntp_server_accepted_packets",
        "Number of packets accepted",
        MetricType::Counter,
        None,
        collect_servers!(state, |s| s.stats.accepted_packets.get()),
    )?;

    format_metric(
        w,
        "ntp_server_denied_packets",
        "Number of denied packets",
        MetricType::Counter,
        None,
        collect_servers!(state, |s| s.stats.denied_packets.get()),
    )?;

    format_metric(
        w,
        "ntp_server_ignored_packets",
        "Number of packets ignored",
        MetricType::Counter,
        None,
        collect_servers!(state, |s| s.stats.ignored_packets.get()),
    )?;

    format_metric(
        w,
        "ntp_server_rate_limited_packets",
        "Number of rate limited packets",
        MetricType::Counter,
        None,
        collect_servers!(state, |s| s.stats.rate_limited_packets.get()),
    )?;

    format_metric(
        w,
        "ntp_server_response_send_errors",
        "Number of packets where there was an error responding",
        MetricType::Counter,
        None,
        collect_servers!(state, |s| s.stats.response_send_errors.get()),
    )?;

    w.write_str("# EOF")?;
    Ok(())
}
