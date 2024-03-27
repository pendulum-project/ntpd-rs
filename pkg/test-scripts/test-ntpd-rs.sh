#!/usr/bin/env bash

set -eo pipefail
set -x

case $1 in
  post-install|post-upgrade)
      # Ensure users are created
      id ntpd-rs
      id ntpd-rs-observe

      # Ensure deamon and ctl client are present
      # and configuration validates.
      echo -e "\nNTPD-RS HELP OUTPUT:"
      /usr/bin/ntp-daemon --help
      /usr/bin/ntp-metrics-exporter --help
      /usr/bin/ntp-ctl validate

      # # Ensure that the systemd service is running
      # systemctl is-active ntpd-rs.service --quiet

      # # Ensure that the metrics systemd service is not running
      # ! systemctl is-active ntpd-rs-metrics.service --quiet
    ;;
esac
