#!/usr/bin/env sh
/home/runner/.cargo/bin/cargo-zigbuild zig cc -- -target arm-linux-gnueabihf -mcpu=generic+v7a+vfp3-d32+thumb2-neon -g $@
