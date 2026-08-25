#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."

export STABLE_RUST_VERSION="$(awk -F'"' '/^channel/{print $2}' ./.rust-toolchain/stable/rust-toolchain.toml)"
export BETA_RUST_VERSION="$(awk -F'"' '/^channel/{print $2}' ./.rust-toolchain/beta/rust-toolchain.toml)"
export NIGHTLY_RUST_VERSION="$(awk -F'"' '/^channel/{print $2}' ./.rust-toolchain/nightly/rust-toolchain.toml)"
export MSRV_RUST_VERSION="$(grep rust-version ./Cargo.toml | grep MSRV | cut -d'"' -f2)"

# Determine target Rust version if MATRIX_RUST is set
if [ -n "${MATRIX_RUST:-}" ]; then
    TARGET_RUST_KEY="$(echo "${MATRIX_RUST}" | tr '[:lower:]' '[:upper:]')_RUST_VERSION"
    export TARGET_RUST_VERSION="${!TARGET_RUST_KEY}"
fi

# Export to Github Actions environment
echo "STABLE_RUST_VERSION=$STABLE_RUST_VERSION" >> "$GITHUB_ENV"
echo "BETA_RUST_VERSION=$BETA_RUST_VERSION" >> "$GITHUB_ENV"
echo "NIGHTLY_RUST_VERSION=$NIGHTLY_RUST_VERSION" >> "$GITHUB_ENV"
echo "MSRV_RUST_VERSION=$MSRV_RUST_VERSION" >> "$GITHUB_ENV"
if [ -n "${TARGET_RUST_VERSION:-}" ]; then
    echo "TARGET_RUST_VERSION=$TARGET_RUST_VERSION" >> "$GITHUB_ENV"
fi
