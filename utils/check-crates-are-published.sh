#!/usr/bin/env bash
set -eo pipefail

mkdir -p published

# Check statime-base crate
STATIME_BASE_VERSION=`cat Cargo.toml | sed -n -e 's/^statime-base =.*{ version = "\(.*\)", path .*/\1/p'`
curl "https://static.crates.io/crates/statime-base/statime-base-${STATIME_BASE_VERSION}.crate" --output published/statime-base-ref.crate
cargo package -p statime-base --allow-dirty
diff -q published/statime-base-ref.crate "target/package/statime-base-${STATIME_BASE_VERSION}.crate"

# Check statime-algo crate
STATIME_ALGO_VERSION=`cat Cargo.toml | sed -n -e 's/^statime-algo =.*{ version = "\(.*\)", path .*/\1/p'`
curl "https://static.crates.io/crates/statime-algo/statime-algo-${STATIME_ALGO_VERSION}.crate" --output published/statime-algo-ref.crate
cargo package -p statime-algo --allow-dirty
diff -q published/statime-algo-ref.crate "target/package/statime-algo-${STATIME_ALGO_VERSION}.crate"

# Check statime-csptp crate
STATIME_CSPTP_VERSION=`cat Cargo.toml | sed -n -e 's/^statime-csptp =.*{ version = "\(.*\)", path .*/\1/p'`
curl "https://static.crates.io/crates/statime-csptp/statime-csptp-${STATIME_CSPTP_VERSION}.crate" --output published/statime-csptp-ref.crate
cargo package -p statime-csptp --allow-dirty
diff -q published/statime-csptp-ref.crate "target/package/statime-csptp-${STATIME_CSPTP_VERSION}.crate"

# Check statime-netptp crate
STATIME_NETPTP_VERSION=`cat Cargo.toml | sed -n -e 's/^statime-netptp =.*{ version = "\(.*\)", path .*/\1/p'`
curl "https://static.crates.io/crates/statime-netptp/statime-netptp-${STATIME_NETPTP_VERSION}.crate" --output published/statime-netptp-ref.crate
cargo package -p statime-netptp --allow-dirty
diff -q published/statime-netptp-ref.crate "target/package/statime-netptp-${STATIME_NETPTP_VERSION}.crate"

# Check statime-wire crate
STATIME_WIRE_VERSION=`cat Cargo.toml | sed -n -e 's/^statime-wire =.*{ version = "\(.*\)", path .*/\1/p'`
curl "https://static.crates.io/crates/statime-wire/statime-wire-${STATIME_WIRE_VERSION}.crate" --output published/statime-wire-ref.crate
cargo package -p statime-wire --allow-dirty
diff -q published/statime-wire-ref.crate "target/package/statime-wire-${STATIME_WIRE_VERSION}.crate"

# Check clock-steering crate
CLOCK_STEERING_VERSION=`cat Cargo.toml | sed -n -e 's/^clock-steering =.*{ version = "\(.*\)", path .*/\1/p'`
curl "https://static.crates.io/crates/clock-steering/clock-steering-${CLOCK_STEERING_VERSION}.crate" --output published/clock-steering-ref.crate
cargo package -p clock-steering --allow-dirty
diff -q published/clock-steering-ref.crate "target/package/clock-steering-${CLOCK_STEERING_VERSION}.crate"

# Check timestamped-socket crate
TIMESTAMPED_SOCKET_VERSION=`cat Cargo.toml | sed -n -e 's/^timestamped-socket =.*{ version = "\(.*\)", path .*/\1/p'`
curl "https://static.crates.io/crates/timestamped-socket/timestamped-socket-${TIMESTAMPED_SOCKET_VERSION}.crate" --output published/timestamped-socket-ref.crate
cargo package -p timestamped-socket --allow-dirty
diff -q published/timestamped-socket-ref.crate "target/package/timestamped-socket-${TIMESTAMPED_SOCKET_VERSION}.crate"