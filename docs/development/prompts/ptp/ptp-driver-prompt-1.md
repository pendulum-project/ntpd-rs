Using the analysis in plans/driver-analysis-combined.md, create a PRD for a new source driver for ntpd-rs.  It should use the pps-time crate from crates.io, and should follow mostly the same pattern as the PPS driver.  That is, a blocking thread architecture, one-way (receive-only) communication, and a dual-task threading model.  However, the invocation must be timer-based rather than device-triggered.
Use the GitHub or fetch URL tool to retrieve an example of using the ptp-time crate.  It is available at https://raw.githubusercontent.com/paulgear/ptp-time/refs/heads/main/examples/demo.rs
It should have configurable polling intervals like other network sources.  The default polling interval bounds should be 2^-1 (0.5 seconds) for the minimum and 2^6 (64 seconds) for the maximum.
Please update the PRD with the following responses to open questions:
1. The PTP driver should support multiple PTP devices simultaneously.  A separate, user-supplied configuration for each device is required.
2. Use the pattern from the PPS driver for precision estimation.
3. The PTP capability for precise timestamps is the main target.  If precise timestamps are not available it should fall back to extended timestamps, and only use standard timestamps if both of the above fail.  This should be auto-detected on driver initialisation and not attempted on every poll.
Then proceed to write the PRD to the target file as requested.
