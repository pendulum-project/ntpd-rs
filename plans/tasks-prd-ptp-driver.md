## Relevant Files

- `ntpd/src/daemon/spawn/ptp.rs` - Main spawner implementation for PTP driver
- `ntpd/src/daemon/ptp_source.rs` - Source task implementation with dual-threading model
- `ntpd/src/daemon/system.rs` - System coordinator integration
- `ntp-proto/src/config.rs` - Configuration type definitions
- `ntpd/src/daemon/pps_source.rs` - Reference implementation for dual-task threading pattern
- `ntpd/src/daemon/sock_source.rs` - Reference for one-way communication pattern
- `ntpd/src/daemon/spawn/pps.rs` - Reference spawner for dual-task pattern
- `ntpd/src/daemon/spawn/sock.rs` - Reference spawner for one-way pattern

## Tasks

- [ ] 1. Create PTP Driver Spawner
  - [ ] 1.1 Implement `PtpSourceSpawner` struct with device path and polling interval configuration
  - [ ] 1.2 Implement `Spawner` trait methods for PTP driver (try_spawn, is_complete, etc.)
  - [ ] 1.3 Add PTP source configuration to `NtpSourceConfig` enum
  - [x] 1.4 Integrate PTP spawner creation in system coordinator
  - [ ] 1.5 Create unit tests for spawner lifecycle management
  - [ ] 1.6 Run unit tests for spawner and fix any problems encountered.
- [ ] 2. Implement PTP Source Task with Dual-Thread Architecture
  - [ ] 2.1 Create `PtpSourceTask` struct with blocking thread channel communication
  - [ ] 2.2 Implement blocking I/O thread for PTP device access using ptp-time crate
  - [ ] 2.3 Implement async coordinator task that manages polling timer
  - [ ] 2.4 Implement timestamp capability detection at initialization only
  - [ ] 2.5 Implement measurement reporting via `OneWaySourceUpdate`
  - [ ] 2.6 Create integration tests for dual-thread communication pattern
  - [ ] 2.7 Run integration tests and fix any problems encountered.
- [ ] 3. Add Configuration Support and Error Handling
  - [ ] 3.1 Implement PTP configuration parsing from ntpd-rs config files
  - [ ] 3.2 Add validation for polling interval bounds (0.5s to 64s)
  - [ ] 3.3 Implement graceful error handling for device unavailability
  - [ ] 3.4 Add recovery mechanisms for transient hardware issues
  - [ ] 3.5 Test configuration loading and error scenarios
  - [ ] 3.6 Run configuration tests and fix any problems encountered.
- [ ] 4. Integrate with System Coordinator and Communication Patterns
  - [ ] 4.1 Implement `MsgForSystem::OneWaySourceUpdate` communication pattern
  - [ ] 4.2 Follow established error handling patterns (NetworkIssue, Unreachable)
  - [ ] 4.3 Ensure compatibility with existing source management architecture
  - [ ] 4.4 Test system integration and message passing
  - [ ] 4.5 Run system integration tests and fix any problems encountered.
- [ ] 5. Create Integration Tests for PTP Driver Implementation
  - [ ] 5.1 Review the changes made in tasks 1-4
  - [ ] 5.2 Review the patterns and techniques used elsewhere in the codebase
  - [ ] 5.3 Create comprehensive integration tests covering all scenarios
  - [ ] 5.4 Run the integration tests and fix any problems encountered.
