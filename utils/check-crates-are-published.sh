#!/usr/bin/env bash
set -eo pipefail

mkdir -p published

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
    cargo package -p "$crate" --allow-dirty
    diff -q "published/$crate-ref.crate" "target/package/$crate-$version.crate"
done