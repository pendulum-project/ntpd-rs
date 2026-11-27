#!/usr/bin/env bash

set -eo pipefail
set -x

case $1 in
  post-install|post-upgrade)
      # Ensure users are created
      id statime
      id statime-observe

      # Ensure daemon and ctl client are present
      # and configuration validates.
      echo -e "\nSTATIME HELP OUTPUT:"
      /usr/bin/statime-daemon --help
      /usr/bin/statime-metrics --help
      /usr/bin/statime validate

      # # Ensure that the systemd service is running
      # systemctl is-active statime.service --quiet

      # # Ensure that the metrics systemd service is not running
      # ! systemctl is-active statime-metrics.service --quiet
    ;;
esac
