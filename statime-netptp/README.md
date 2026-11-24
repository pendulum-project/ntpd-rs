# statime-netptp

Network socket management for ptp-based protocols. This crate implements
virtual network sockets for the PTP ports, allowing multiple network sockets
for ptp traffic from various parts of a program whilst keeping only one socket
per interface open in the kernel. This is needed as all ptp and ptp-based
traffic needs to go over ports 319 and 320, which can only be opened once per
interface. This crate is part of the [statime time daemon](https://github.com/trifectatechfoundation/statime).
