#!/usr/bin/env bash

set -eo pipefail

docs_dir="docs/man"
output_dir="${1:-"docs/precompiled/man"}"
files=("ntp-ctl.8" "ntp-daemon.8" "ntp-metrics-exporter.8" "ntp.toml.5")

mkdir -p "$output_dir"

for f in "${files[@]}"; do
    origin_file="$docs_dir/$f.md"
    tmp_file="$output_dir/$f.md"
    target_file="$output_dir/$f"

    echo "Generating man page for $f from '$origin_file' to '$target_file'"
    sed '/<!-- ---/s/<!-- ---/---/' "$origin_file" | sed '/--- -->/s/--- -->/---/' > "$tmp_file"
    utils/pandoc.sh -s -t man "$tmp_file" -o "$target_file"
    rm "$tmp_file"
done
