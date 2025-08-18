# Product Requirements Document: PTP Driver for ntpd-rs

## Introduction/Overview
This document specifies the requirements for implementing a new PTP (Precision Time Protocol) source driver for ntpd-rs. The driver will interface with Linux PTP Hardware Clocks (PHC) using the ptp-time crate, providing high-precision time measurements similar to the existing PPS driver but with timer-based polling instead of device-triggered events.

## Goals
1. Enable ntpd-rs to utilize Linux PTP Hardware Clocks for high-precision time synchronization
2. Follow the established driver patterns in ntpd-rs while adapting to PTP-specific requirements
3. Provide configurable polling intervals for optimal performance across different use cases
4. Maintain consistency with existing source driver architecture and error handling patterns

## User Stories
1. **As a system administrator**, I want to configure ntpd-rs to use a PTP hardware clock so that I can achieve sub-microsecond time synchronization accuracy.
2. **As a system administrator**, I want to configure the polling interval for PTP sources so that I can balance precision and system resource usage.
3. **As a system administrator**, I want the PTP driver to handle hardware errors gracefully so that my NTP service remains stable even when PTP devices are temporarily unavailable.

## Functional Requirements
1. **PTP Device Interface**
   - The driver must interface with Linux PTP Hardware Clocks via `/dev/ptp*` device files
   - Must use the ptp-time crate for safe access to PTP ioctls
   - Should support standard PTP device capabilities detection

2. **Timer-Based Polling Architecture**
   - Implement timer-based polling instead of device-triggered events (unlike PPS driver)
   - Use configurable polling intervals with default bounds of 0.5s (2^-1) to 64s (2^6)
   - Follow the dual-task threading model pattern established by the PPS driver

3. **Source Communication Pattern**
   - Implement one-way communication (receive-only) like the PPS driver
   - Use `OneWaySourceUpdate` for measurements instead of `NtpSourceUpdate`
   - Provide high-precision time measurements with appropriate timestamping

4. **Configuration Support**
   - Accept device path configuration (e.g., `/dev/ptp0`)
   - Support configurable polling interval settings
   - Include precision estimation based on PTP capabilities

5. **Error Handling**
   - Graceful handling of PTP device unavailability
   - Proper error reporting to system coordinator
   - Recovery mechanisms for transient hardware issues

6. **Timestamp Capability Detection**
   - Auto-detect available timestamping capabilities on driver initialization
   - Prefer precise timestamps when available
   - Fall back to extended timestamps if precise timestamps are not available
   - Use standard timestamps only as last resort
   - Do not attempt capability detection on every poll

## Non-Goals (Out of Scope)
1. Support for non-Linux PTP implementations or non-Hardware Clock sources
2. Full NTP client/server protocol implementation - only time measurement capabilities
3. Complex PTP network synchronization features beyond simple timestamp acquisition
4. Integration with PTPv2 or PTPv3 protocol layers (focus on hardware clock access)
5. Support for PTP device pin configuration or event generation

## Design Considerations
- Follow the same pattern as the PPS driver for consistency with existing codebase
- Use the dual-task threading model with blocking I/O in separate thread
- Implement timer-based polling using Tokio's interval mechanism
- Maintain compatibility with existing ntpd-rs source management architecture
- Support multiple PTP devices simultaneously through separate user configurations

## Technical Considerations
1. **Dependencies**: Must integrate with ptp-time crate (version specified in Cargo.toml)
2. **Threading Model**: Dual-task model similar to PPS driver - async coordinator with blocking thread for device I/O
3. **Timing Precision**: Should provide sub-microsecond timing precision comparable to PPS driver
4. **System Integration**: Follow established `MsgForSystem::OneWaySourceUpdate` communication pattern
5. **Capability Detection**: Auto-detect timestamp capabilities at initialization time only

## Success Metrics
1. **Performance**: Achieve sub-microsecond timing precision consistent with PPS driver
2. **Reliability**: 99.9% uptime for PTP device operations when devices are available
3. **Configuration**: Support all required configuration parameters through ntpd-rs config system
4. **Error Handling**: Graceful degradation when PTP devices are unavailable or error

## Open Questions
1. Should the PTP driver support multiple PTP devices simultaneously? (Answer: Yes, separate user-supplied configuration for each device)
2. How should precision estimation be handled? (Answer: Use the pattern from the PPS driver)
3. What timestamp capability fallback behavior should be implemented? (Answer: Precise -> Extended -> Standard timestamps with auto-detection at initialization only)
