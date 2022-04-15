# NTPD-rs

This project is intended to become a memory-safe implementation of NTP in Rust. It is currently a work in progress, and does not offer any real functionality yet.

## Naming

We are currently looking for a better name for this project. Suggestions for this are welcome.

## Package substructure

Currently, the code is split up into three separate crates:
 - ntp-proto is intended to contain the packet parsing and most of the algorithms around clock selection, filtering and steering.
 - ntp-daemon is intended to become the main deamon, and to deal with most of the networking and configuration
 - ntp-os-clock contains the unsafe code needed to interface with system clocks.

It is a design goal to split of any unsafe code needed to interface with operating system interfaces in separate packages. The intent is to keep these packages as small as possible and ensure that any public functions exposed are themselves safe.
