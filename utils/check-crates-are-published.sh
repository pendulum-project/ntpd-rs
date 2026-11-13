#!/usr/bin/env bash

set -eo pipefail

mkdir -p published

CRATES=(
    statime-base
    statime-config
    statime-config-derive
    statime-algo
    statime-csptp
    statime-netptp
    statime-wire
    statime-seccomp
    clock-steering
    timestamped-socket
)

for crate in "${CRATES[@]}"; do
    version="$(sed -n -e "s/^$crate *="'.*{ version = "\(.*\)", path .*/\1/p' Cargo.toml)"
    curl "https://static.crates.io/crates/$crate/$crate-$version.crate" --output "published/$crate-ref.crate"
    cargo package -m "$crate/Cargo.toml" --allow-dirty

    # clean up from previous runs before starting.
    rm -rf "published/$crate"
    mkdir -p published/$crate/{ref,local}
    tar -xf "published/$crate-ref.crate" -C "published/$crate/ref"
    if [ -d "$crate/target" ]; then
        # Deal with crates that are not part of the workspace.
        tar -xf "$crate/target/package/$crate-$version.crate" -C "published/$crate/local"
    else
        tar -xf "target/package/$crate-$version.crate" -C "published/$crate/local"
    fi
    diff -qr --exclude ".cargo_vcs_info.json" "published/$crate/ref" "published/$crate/local"
done
