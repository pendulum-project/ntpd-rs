use ntp_daemon::ObservablePeerState;
use ntp_proto::{PeerStatistics, SystemSnapshot};

pub(crate) trait DisplayPrometheus {
    fn write_prometheus(
        &self,
        f: &mut impl std::io::Write,
        labels: &[(&str, &str)],
    ) -> std::io::Result<()>;

    fn format(
        &self,
        f: &mut impl std::io::Write,
        namespace: &str,
        name: &str,
        labels: &[(&str, &str)],
        value: impl std::fmt::Display,
    ) -> std::io::Result<()> {
        write!(f, "{namespace}_{name} ")?;

        if !labels.is_empty() {
            write!(f, "{{")?;

            let mut it = labels.iter().peekable();

            while let Some((key, value)) = it.next() {
                write!(f, "{key} = \"{value}\"")?;

                if it.peek().is_some() {
                    write!(f, ", ")?;
                }
            }

            write!(f, "}} ")?;
        }

        writeln!(f, "{value}")
    }
}

impl DisplayPrometheus for SystemSnapshot {
    fn write_prometheus(
        &self,
        f: &mut impl std::io::Write,
        labels: &[(&str, &str)],
    ) -> std::io::Result<()> {
        writeln!(f, "# TYPE ntp_system_poll_interval gauge")?;

        self.format(
            f,
            "ntp_system",
            "poll_interval",
            labels,
            self.poll_interval.as_duration().to_seconds(),
        )?;

        writeln!(f, "# TYPE ntp_system_precision gauge")?;

        self.format(
            f,
            "ntp_system",
            "precision",
            labels,
            self.precision.to_seconds(),
        )?;

        writeln!(f, "# TYPE ntp_system_accumulated_steps gauge")?;
        self.format(
            f,
            "ntp_system",
            "accumulated_steps",
            labels,
            self.accumulated_steps.to_seconds(),
        )?;

        if let Some(threshold) = self.accumulated_steps_threshold {
            writeln!(f, "# TYPE ntp_system_accumulated_steps_threshold gauge")?;
            self.format(
                f,
                "ntp_system",
                "accumulated_steps_threshold",
                labels,
                threshold.to_seconds(),
            )?;
        }

        writeln!(f, "# TYPE ntp_system_leap_indicator gauge")?;
        let mut labels = labels.to_owned();
        let leap_indicator = format!("{:?}", self.leap_indicator);
        labels.push(("type", &leap_indicator));
        self.format(
            f,
            "ntp_system",
            "leap_indicator",
            &labels,
            self.leap_indicator as u8,
        )?;

        Ok(())
    }
}

impl DisplayPrometheus for ObservablePeerState {
    fn write_prometheus(
        &self,
        f: &mut impl std::io::Write,
        _labels: &[(&str, &str)],
    ) -> std::io::Result<()> {
        match self {
            ObservablePeerState::Nothing => (),
            ObservablePeerState::Observable {
                statistics,
                reachability,
                uptime,
                poll_interval,
                peer_id: _,
                address,
            } => {
                let labels = &[("address", address.as_str())] as &[_];
                statistics.write_prometheus(f, labels)?;

                self.format(
                    f,
                    "ntp_peer",
                    "uptime",
                    labels,
                    uptime.as_secs() as f64 + uptime.subsec_nanos() as f64 * 1e-9,
                )?;

                self.format(
                    f,
                    "ntp_peer",
                    "poll_interval",
                    labels,
                    poll_interval.as_secs() as f64 + poll_interval.subsec_nanos() as f64 * 1e-9,
                )?;

                self.format(
                    f,
                    "ntp_peer",
                    "reachability_status",
                    labels,
                    reachability.is_reachable() as u8,
                )?;

                let result = if reachability.is_reachable() {
                    "success"
                } else {
                    "timeout"
                };
                let labels = &[("address", address.as_str()), ("result", result)] as &[_];
                self.format(
                    f,
                    "ntp_peer",
                    "reachability_unanswered_polls",
                    labels,
                    reachability.unanswered_polls(),
                )?;
            }
        }

        writeln!(f)?;

        Ok(())
    }
}

impl DisplayPrometheus for PeerStatistics {
    fn write_prometheus(
        &self,
        f: &mut impl std::io::Write,
        labels: &[(&str, &str)],
    ) -> std::io::Result<()> {
        let PeerStatistics {
            offset,
            delay,
            dispersion,
            jitter,
        } = self;

        self.format(f, "ntp_peer", "offset", labels, offset.to_seconds())?;
        self.format(f, "ntp_peer", "delay", labels, delay.to_seconds())?;
        self.format(f, "ntp_peer", "dispersion", labels, dispersion.to_seconds())?;
        self.format(f, "ntp_peer", "jitter", labels, *jitter)?;

        Ok(())
    }
}

pub(crate) const PEER_TYPE_HEADERS: &str = r#" 
# TYPE ntp_peer_offset gauge
# TYPE ntp_peer_delay gauge
# TYPE ntp_peer_dispersion gauge
# TYPE ntp_peer_jitter gauge
# TYPE ntp_peer_reachability_status gauge
# TYPE ntp_peer_reachability_unanswered_polls gauge
# TYPE ntp_peer_uptime gauge
# TYPE ntp_peer_poll_interval gauge
"#;
