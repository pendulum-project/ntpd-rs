pub mod exporter;

use ntp_proto::PollIntervalLimits;

use crate::daemon::ObservableState;

struct Measurement<T> {
    labels: Vec<(&'static str, String)>,
    value: T,
}

impl<T> Measurement<T> {
    fn simple(value: T) -> Vec<Measurement<T>> {
        vec![Measurement {
            labels: Vec::default(),
            value,
        }]
    }
}

#[derive(PartialEq, Eq, Clone, Copy)]
enum Unit {
    Seconds,
}

impl Unit {
    #[allow(clippy::unused_self)]
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
    metric_type: &MetricType,
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

macro_rules! collect_sources {
    ($from: expr, |$ident: ident| $value: expr $(,)?) => {{
        let mut data = vec![];
        for $ident in &$from.sources {
            let labels = vec![
                ("name", $ident.name.clone()),
                ("address", $ident.address.clone()),
                ("id", format!("{}", $ident.id)),
            ];
            let value = $value;
            data.push(Measurement { labels, value });
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

#[allow(clippy::too_many_lines)]
pub fn format_state(w: &mut impl std::fmt::Write, state: &ObservableState) -> std::fmt::Result {
    format_metric(
        w,
        "ntp_uptime",
        "Time that the ntp daemon is running",
        &MetricType::Gauge,
        Some(Unit::Seconds),
        vec![Measurement {
            labels: vec![
                ("version", state.program.version.clone()),
                ("build_commit", state.program.build_commit.clone()),
                ("build_commit_date", state.program.build_commit_date.clone()),
            ],
            value: state.program.uptime_seconds,
        }],
    )?;

    format_metric(
        w,
        "ntp_system_poll_interval",
        "[DEPRECATED] Time between polls of the system",
        &MetricType::Gauge,
        Some(Unit::Seconds),
        Measurement::simple(
            state
                .sources
                .iter()
                .map(|s| s.poll_interval)
                .min()
                .unwrap_or(PollIntervalLimits::default().min)
                .as_duration()
                .to_seconds(),
        ),
    )?;

    format_metric(
        w,
        "ntp_system_accumulated_steps",
        "Accumulated amount of seconds that the system needed to jump the time",
        &MetricType::Gauge,
        Some(Unit::Seconds),
        Measurement::simple(state.system.time_snapshot.accumulated_steps.to_seconds()),
    )?;

    format_metric(
        w,
        "ntp_system_accumulated_steps_threshold",
        "Threshold for the accumulated step amount at which the NTP daemon will exit (or -1 if no threshold was set)",
        &MetricType::Gauge,
        Some(Unit::Seconds),
        Measurement::simple(state.system
            .accumulated_steps_threshold
            .map_or(-1.0, ntp_proto::NtpDuration::to_seconds)),
    )?;

    format_metric(
        w,
        "ntp_system_leap_indicator",
        "Indicates that a leap second will take place",
        &MetricType::Gauge,
        None,
        Measurement::simple(state.system.time_snapshot.leap_indicator as i64),
    )?;

    format_metric(
        w,
        "ntp_system_root_delay",
        "Distance to the closest root time source",
        &MetricType::Gauge,
        Some(Unit::Seconds),
        Measurement::simple(state.system.time_snapshot.root_delay.to_seconds()),
    )?;

    format_metric(
        w,
        "ntp_system_root_dispersion",
        "Estimate of how precise our time is",
        &MetricType::Gauge,
        Some(Unit::Seconds),
        Measurement::simple(state.system.time_snapshot.root_dispersion.to_seconds()),
    )?;

    format_metric(
        w,
        "ntp_system_stratum",
        "Stratum of our clock",
        &MetricType::Gauge,
        None,
        Measurement::simple(state.system.stratum),
    )?;

    format_metric(
        w,
        "ntp_source_poll_interval",
        "Time between polls of the source",
        &MetricType::Gauge,
        Some(Unit::Seconds),
        collect_sources!(state, |p| p.poll_interval.as_duration().to_seconds()),
    )?;

    format_metric(
        w,
        "ntp_source_unanswered_polls",
        "Number of polls since the last successful poll with a maximum of eight",
        &MetricType::Gauge,
        None,
        collect_sources!(state, |p| p.unanswered_polls),
    )?;

    format_metric(
        w,
        "ntp_source_offset",
        "Offset between the upstream source and system time",
        &MetricType::Gauge,
        Some(Unit::Seconds),
        collect_sources!(state, |p| p.timedata.offset.to_seconds()),
    )?;

    format_metric(
        w,
        "ntp_source_delay",
        "Current round-trip delay to the upstream source",
        &MetricType::Gauge,
        Some(Unit::Seconds),
        collect_sources!(state, |p| p.timedata.delay.to_seconds()),
    )?;

    format_metric(
        w,
        "ntp_source_uncertainty",
        "Estimated error of the source clock",
        &MetricType::Gauge,
        Some(Unit::Seconds),
        collect_sources!(state, |p| p.timedata.uncertainty.to_seconds()),
    )?;

    format_metric(
        w,
        "ntp_source_root_delay",
        "Root delay reported by the time source",
        &MetricType::Gauge,
        Some(Unit::Seconds),
        collect_sources!(state, |p| p.timedata.remote_delay.to_seconds()),
    )?;

    format_metric(
        w,
        "ntp_source_root_dispersion",
        "Uncertainty reported by the time source",
        &MetricType::Gauge,
        Some(Unit::Seconds),
        collect_sources!(state, |p| p.timedata.remote_uncertainty.to_seconds()),
    )?;

    format_metric(
        w,
        "ntp_server_received_packets_total",
        "Number of incoming packets",
        &MetricType::Counter,
        None,
        collect_servers!(state, |s| s.stats.received_packets.get()),
    )?;

    format_metric(
        w,
        "ntp_server_accepted_packets_total",
        "Number of packets accepted",
        &MetricType::Counter,
        None,
        collect_servers!(state, |s| s.stats.accepted_packets.get()),
    )?;

    format_metric(
        w,
        "ntp_server_denied_packets_total",
        "Number of denied packets",
        &MetricType::Counter,
        None,
        collect_servers!(state, |s| s.stats.denied_packets.get()),
    )?;

    format_metric(
        w,
        "ntp_server_ignored_packets_total",
        "Number of packets ignored",
        &MetricType::Counter,
        None,
        collect_servers!(state, |s| s.stats.ignored_packets.get()),
    )?;

    format_metric(
        w,
        "ntp_server_rate_limited_packets_total",
        "Number of rate limited packets",
        &MetricType::Counter,
        None,
        collect_servers!(state, |s| s.stats.rate_limited_packets.get()),
    )?;

    format_metric(
        w,
        "ntp_server_response_send_errors_total",
        "Number of packets where there was an error responding",
        &MetricType::Counter,
        None,
        collect_servers!(state, |s| s.stats.response_send_errors.get()),
    )?;

    format_metric(
        w,
        "ntp_server_nts_received_packets_total",
        "Number of incoming NTS packets",
        &MetricType::Counter,
        None,
        collect_servers!(state, |s| s.stats.nts_received_packets.get()),
    )?;

    format_metric(
        w,
        "ntp_server_nts_accepted_packets_total",
        "Number of NTS packets accepted",
        &MetricType::Counter,
        None,
        collect_servers!(state, |s| s.stats.nts_accepted_packets.get()),
    )?;

    format_metric(
        w,
        "ntp_server_nts_denied_packets_total",
        "Number of denied NTS packets",
        &MetricType::Counter,
        None,
        collect_servers!(state, |s| s.stats.nts_denied_packets.get()),
    )?;

    format_metric(
        w,
        "ntp_server_nts_rate_limited_packets_total",
        "Number of rate limited NTS packets",
        &MetricType::Counter,
        None,
        collect_servers!(state, |s| s.stats.nts_rate_limited_packets.get()),
    )?;

    format_metric(
        w,
        "ntp_server_nts_nak_packets_total",
        "Number of NTS nak responses to packets",
        &MetricType::Counter,
        None,
        collect_servers!(state, |s| s.stats.nts_nak_packets.get()),
    )?;

    w.write_str("# EOF\n")?;
    Ok(())
}
