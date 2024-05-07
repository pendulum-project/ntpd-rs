#!/usr/bin/env bash

export PANDOC_VERSION="3.1.1"

exec docker run --rm -v "$(pwd):/data" -u "$(id -u):$(id -g)" "pandoc/core:$PANDOC_VERSION" "$@"
