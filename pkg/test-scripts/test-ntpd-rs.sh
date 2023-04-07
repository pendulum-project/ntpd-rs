#!/usr/bin/env bash

set -eo pipefail
set -x

case $1 in
  post-install|post-upgrade)
      echo -e "\nNTPD-RS SERVICE STATUS AFTER START:"
      sleep 1s
      systemctl status ntpd-rs
    ;;
esac
