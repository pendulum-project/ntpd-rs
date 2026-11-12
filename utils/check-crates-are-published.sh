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

    mkdir -p published/$crate/{ref,local}
    tar -xf "published/$crate-ref.crate" -C "published/$crate/ref"
    tar -xf "target/package/$crate-$version.crate" -C "published/$crate/local"
    diff -qr --exclude ".cargo_vcs_info.json" "published/$crate/ref" "published/$crate/local"
done
