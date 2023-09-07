#!/usr/bin/env bash

if [ "$#" -lt 1 ]; then
    echo "Missing new version specifier"
    exit 1
fi

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd)
PROJECT_DIR=$(dirname "$SCRIPT_DIR")
NEW_VERSION="$1"
NOTICE_LINE="# NOTE: keep this part at the bottom of the file, do not change this line"

echo "Updating version in Cargo.toml"
sed -i 's/^version\s*=\s*".*"/version = "'"$NEW_VERSION"'"/' "$PROJECT_DIR/Cargo.toml"

echo "Updating workspace crate versions in Cargo.toml"
tmp_file="$PROJECT_DIR/Cargo.toml.tmp"
replace_flag=0
while IFS= read -r line; do
    if [ $replace_flag -eq 1 ]; then
        line=$(echo "$line" | sed 's/version\s*=\s*"[^"]*"/version = "'"$NEW_VERSION"'"/g')
    fi

    if [ "$line" = "$NOTICE_LINE" ]; then
        replace_flag=1
    fi

    echo "$line" >> "$tmp_file"
done < "$PROJECT_DIR/Cargo.toml"
mv "$tmp_file" "$PROJECT_DIR/Cargo.toml"

echo "Updating version in man pages"
sed -i 's/^title: NTP-CTL(8) ntpd-rs .*/title: NTP-CTL(8) ntpd-rs '"$NEW_VERSION"' | ntpd-rs/' "$PROJECT_DIR"/docs/man/ntp-ctl.8.md
sed -i 's/^title: NTP-DAEMON(8) ntpd-rs .*/title: NTP-DAEMON(8) ntpd-rs '"$NEW_VERSION"' | ntpd-rs/' "$PROJECT_DIR"/docs/man/ntp-daemon.8.md
sed -i 's/^title: NTP-METRICS-EXPORTER(8) ntpd-rs .*/title: NTP-METRICS-EXPORTER(8) ntpd-rs '"$NEW_VERSION"' | ntpd-rs/' "$PROJECT_DIR"/docs/man/ntp-metrics-exporter.8.md
sed -i 's/^title: NTP.TOML(5) ntpd-rs .*/title: NTP.TOML(5) ntpd-rs '"$NEW_VERSION"' | ntpd-rs/' "$PROJECT_DIR"/docs/man/ntp.toml.5.md

echo "Rebuilding precompiled man pages"
utils/generate-man.sh

echo "Rebuilding project"
(cd $PROJECT_DIR && cargo build --release)

echo "!!! Version changes complete, make sure that the changelog is synchronized"
