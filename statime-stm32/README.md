# Statime STM32

This is an example program for running the statime PTP stack on a microcontroller using hardware timestamping.

It uses RTIC as its executor and runs various tasks for running statime and smoltcp.
Additionally it enables a PPS pin that runs on the clock that is being synchronized.
