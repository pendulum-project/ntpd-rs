#!/usr/bin/env bash

set -eo pipefail
set -x

case $1 in
  post-install|post-upgrade)
      echo -e "\nNTPD-RS HELP OUTPUT:"
      /usr/bin/ntp-daemon --help
      /usr/bin/ntp-ctl validate
    ;;
esac
