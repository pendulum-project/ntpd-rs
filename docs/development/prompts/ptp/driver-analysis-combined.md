# NTP Source Driver Analysis Report

## Executive Summary

The ntpd-rs codebase implements a modular architecture for NTP time sources through a spawner/source pattern. There are two main categories of drivers:

1. **Network-based sources** (Standard, Pool, NTS) - Event-driven with async I/O
2. **Hardware/local sources** (Socket, PPS) - Event-driven with blocking I/O wrapped in async tasks

All sources follow a consistent event-driven architecture using Tokio's async runtime, with no traditional polling mechanisms. However, the system provides guidance for implementing polled drivers when needed.

## Architecture Overview

### Core Components

- **Spawners** (`ntpd/src/daemon/spawn/`): Responsible for creating and managing source instances
- **Sources** (`ntpd/src/daemon/`): Handle actual time measurement and communication
- **System** (`ntpd/src/daemon/system.rs`): Coordinates all sources and manages the time synchronization algorithm

### Communication Pattern

```
Spawner -> SpawnEvent -> System -> SourceCreateParameters -> Source Task
                                                                  |
System <- MsgForSystem <- Source Task (measurements/status)
```

## Source Driver Analysis

### 1. Standard NTP Source (`standard.rs`)

**Type**: Network-based, single server

**Architecture**: Event-driven with timer-based polling

**Location**: `ntpd/src/daemon/spawn/standard.rs` (spawner), `ntpd/src/daemon/ntp_source.rs` (source)

**Key Characteristics**:
- Creates a single NTP source for a given server address
- Handles DNS resolution with retry on failure
- Re-resolves DNS on unreachable errors
- Uses UDP sockets with timestamping support

**Event Mechanism**:
- `tokio::select!` on timer, socket receive, and system updates
- Timer-driven polling intervals determined by NTP algorithm
- Socket events trigger packet processing
- System events update source configuration

**Interface with System**:
- Spawner implements `Spawner` trait
- Source communicates via `MsgForSystem` enum
- Receives system updates via broadcast channel

### 2. Pool NTP Source (`pool.rs`)

**Type**: Network-based, multiple servers from pool

**Architecture**: Event-driven with timer-based polling

**Location**: `ntpd/src/daemon/spawn/pool.rs` (spawner), uses same `ntp_source.rs`

**Key Characteristics**:
- Manages multiple sources from a single pool address
- DNS resolution returns multiple IPs
- Maintains desired count of active sources
- Supports ignore list for problematic servers

**Event Mechanism**:
- Same as Standard source for individual connections
- Spawner manages lifecycle of multiple source instances
- Automatic replacement of failed sources

**Interface with System**:
- Spawner creates multiple `NtpSourceCreateParameters`
- Each spawned source operates independently
- Pool logic handled entirely in spawner

### 3. NTS (Network Time Security) Source (`nts.rs`)

**Type**: Network-based, encrypted NTP

**Architecture**: Event-driven with timer-based polling

**Location**: `ntpd/src/daemon/spawn/nts.rs` (spawner), uses same `ntp_source.rs`

**Key Characteristics**:
- Performs TLS key exchange before NTP communication
- Single source per NTS server
- Timeout handling for key exchange (5 seconds)
- Certificate validation support

**Event Mechanism**:
- Key exchange phase: async TLS connection with timeout
- NTP phase: same as Standard source
- Failure triggers re-key exchange

**Interface with System**:
- Spawner handles key exchange complexity
- Passes NTS data to source via `SourceNtsData`
- Source handles encrypted NTP packets

### 4. Socket Source (`sock.rs`)

**Type**: Local hardware/GPS via Unix socket

**Architecture**: Event-driven (async wrapper around blocking I/O)

**Location**: `ntpd/src/daemon/spawn/sock.rs` (spawner), `ntpd/src/daemon/sock_source.rs` (source)

**Key Characteristics**:
- Receives time data from GPSd via Unix domain socket
- Processes binary time samples (40-byte format)
- One-way time source (no polling)
- Creates and manages Unix socket lifecycle

**Event Mechanism**:
- `tokio::select!` on socket receive and system updates
- Socket events trigger sample processing
- No outbound polling - purely reactive

**Interface with System**:
- Uses `OneWaySourceUpdate` instead of `NtpSourceUpdate`
- Communicates via `MsgForSystem::OneWaySourceUpdate`
- No bidirectional communication

### 5. PPS (Pulse Per Second) Source (`pps.rs`)

**Type**: Hardware timing source

**Architecture**: Event-driven with blocking I/O in separate thread

**Location**: `ntpd/src/daemon/spawn/pps.rs` (spawner), `ntpd/src/daemon/pps_source.rs` (source)

**Key Characteristics**:
- Interfaces with PPS hardware devices
- Blocking I/O handled in separate thread
- High precision timing source
- Requires PPS_CANWAIT capability

**Event Mechanism**:
- Blocking `fetch_blocking()` in dedicated thread
- Thread communicates via mpsc channel
- Main task uses `tokio::select!` on channel and system updates

**Interface with System**:
- Similar to Socket source - one-way updates
- Uses `OneWaySourceUpdate` pattern
- No polling - event-driven by hardware pulses

## Notable Differences Between Drivers

### 1. Communication Patterns

**Network Sources** (Standard, Pool, NTS):
- Bidirectional communication (send/receive)
- Timer-based polling intervals
- Socket-based I/O with timestamping
- Use `NtpSourceUpdate` for measurements

**Local Sources** (Socket, PPS):
- Unidirectional (receive only)
- No polling - purely event-driven
- Use `OneWaySourceUpdate` for measurements
- Different measurement delay types (NtpDuration vs ())

### 2. Error Handling

**Network Sources**:
- Network error detection and recovery
- DNS resolution retry logic
- Connection state management
- Unreachable/demobilize states

**Local Sources**:
- Hardware/file system error handling
- No network-related error recovery
- Simpler state management

### 3. Threading Models

**Network Sources**:
- Single async task per source
- All I/O is async

**Socket Source**:
- Single async task
- Unix socket I/O is async

**PPS Source**:
- Dual-task model: blocking thread + async coordinator
- Required due to blocking PPS API

### 4. Lifecycle Management

**Standard/NTS**:
- Single source per spawner
- Restart on failure

**Pool**:
- Multiple sources per spawner
- Dynamic source replacement

**Socket/PPS**:
- Single source per spawner
- Restart on failure

## System Integration

### Spawner Interface

All spawners implement the `Spawner` trait:

```rust
trait Spawner {
    async fn try_spawn(&mut self, action_tx: &mpsc::Sender<SpawnEvent>) -> Result<(), Self::Error>;
    fn is_complete(&self) -> bool;
    async fn handle_source_removed(&mut self, event: SourceRemovedEvent) -> Result<(), Self::Error>;
    async fn handle_registered(&mut self, event: SourceCreateParameters) -> Result<(), Self::Error>;
    fn get_id(&self) -> SpawnerId;
    fn get_addr_description(&self) -> String;
    fn get_description(&self) -> &str;
}
```

### Source Communication

Sources communicate with the system via:

```rust
enum MsgForSystem<SourceMessage> {
    MustDemobilize(SourceId),
    NetworkIssue(SourceId),
    Unreachable(SourceId),
    SourceUpdate(SourceId, NtpSourceUpdate<SourceMessage>),
    OneWaySourceUpdate(SourceId, OneWaySourceUpdate<SourceMessage>),
}
```

### Event Loop Integration

All sources use `tokio::select!` for event multiplexing:
- Timer events (network sources only)
- I/O events (socket/channel receive)
- System update events (configuration changes)

## Driver Comparison Table

| Driver Type | Architecture | Communication | Polling | Measurement Type | Threading Model |
|-------------|--------------|---------------|---------|------------------|-----------------|
| Standard NTP | Event-driven with polling | Two-way (request/response) | Timer-based | `NtpDuration` | Single async task |
| Pool NTP | Event-driven with polling | Two-way (request/response) | Timer-based | `NtpDuration` | Single async task |
| NTS | Event-driven with polling | Two-way (request/response) | Timer-based | `NtpDuration` | Single async task |
| Socket | Event-driven (async wrapper) | One-way (receive only) | None | `()` | Single async task |
| PPS | Event-driven (blocking thread) | One-way (receive only) | None | `()` | Dual-task model |

## Guidelines for Implementing a New Polled NTP Source Driver

### 1. Architecture Decision

**Event-Driven Approach (Recommended)**:
- Follow existing patterns using `tokio::select!`
- Implement timer-based polling if needed
- Use async I/O where possible

**Key Considerations**:
- All existing sources are event-driven, not traditionally polled
- The system expects async operation
- Blocking I/O requires separate thread (see PPS example)

### 2. Implementation Steps

#### Step 1: Create Spawner

```rust
pub struct MySourceSpawner {
    config: MySourceConfig,
    source_config: SourceConfig,
    id: SpawnerId,
    has_spawned: bool,
}

impl Spawner for MySourceSpawner {
    type Error = MySpawnError;

    async fn try_spawn(&mut self, action_tx: &mpsc::Sender<SpawnEvent>) -> Result<(), Self::Error> {
        // Create source parameters
        // Send SpawnEvent::Create
        // Set has_spawned = true
    }

    fn is_complete(&self) -> bool {
        self.has_spawned
    }

    async fn handle_source_removed(&mut self, event: SourceRemovedEvent) -> Result<(), Self::Error> {
        // Reset has_spawned if not demobilized
        // Handle any cleanup
    }

    // Implement other required methods
}
```

#### Step 2: Create Source Task

**For Network-like Sources**:
```rust
pub struct MySourceTask<C: NtpClock, Controller: SourceController> {
    index: SourceId,
    clock: C,
    channels: SourceChannels<Controller::ControllerMessage, Controller::SourceMessage>,
    source: NtpSource<Controller>, // or OneWaySource<Controller>
    // Your specific fields
}

impl<C, Controller> MySourceTask<C, Controller> {
    async fn run(&mut self) {
        loop {
            tokio::select! {
                // Timer event (if needed)
                () = &mut self.poll_timer => {
                    // Handle polling
                }
                // I/O event
                result = self.receive_data() => {
                    // Process received data
                }
                // System updates
                result = self.channels.system_update_receiver.recv() => {
                    // Handle system updates
                }
            }
        }
    }
}
```

**For Hardware/Local Sources**:
```rust
// Similar to Socket/PPS pattern
// Use OneWaySource instead of NtpSource
// Send OneWaySourceUpdate instead of SourceUpdate
```

#### Step 3: Integrate with System

1. Add config type to `NtpSourceConfig` enum
2. Add spawner creation in `system.rs`
3. Add source creation parameters if needed
4. Update configuration parsing

### 3. Key Design Patterns

#### Timer Management
```rust
// For polled sources, use tokio timer
let mut poll_timer = tokio::time::interval(poll_interval);

tokio::select! {
    _ = poll_timer.tick() => {
        // Perform poll operation
    }
    // Other events...
}
```

#### Error Handling
```rust
// Network errors should trigger restart
self.channels.msg_for_system_sender
    .send(MsgForSystem::NetworkIssue(self.index))
    .await.ok();

// Unreachable should trigger address re-resolution
self.channels.msg_for_system_sender
    .send(MsgForSystem::Unreachable(self.index))
    .await.ok();
```

#### Measurement Reporting
```rust
// For two-way sources
let update = NtpSourceUpdate { /* ... */ };
self.channels.msg_for_system_sender
    .send(MsgForSystem::SourceUpdate(self.index, update))
    .await.ok();

// For one-way sources
let update = OneWaySourceUpdate { /* ... */ };
self.channels.msg_for_system_sender
    .send(MsgForSystem::OneWaySourceUpdate(self.index, update))
    .await.ok();
```

### 4. Testing Considerations

- Follow existing test patterns in each source module
- Test spawner lifecycle (create, remove, restart)
- Test source communication with system
- Mock external dependencies
- Test error conditions and recovery

### 5. Configuration Integration

Add to configuration types:
```rust
// In config module
#[derive(Debug, Clone)]
pub struct MySourceConfig {
    // Your configuration fields
}

// In NtpSourceConfig enum
pub enum NtpSourceConfig {
    // Existing variants...
    MySource(MySourceConfig),
}
```

### 6. Common Pitfalls to Avoid

1. **Don't use traditional polling loops** - use event-driven patterns
2. **Handle all error cases** - network, I/O, parsing errors
3. **Implement proper cleanup** - remove from snapshots on exit
4. **Use appropriate update types** - NtpSourceUpdate vs OneWaySourceUpdate
5. **Follow async patterns** - don't block the runtime
6. **Test spawner state management** - handle restart scenarios

### 7. Performance Considerations

- Use efficient I/O patterns (async where possible)
- Minimize allocations in hot paths
- Consider batching if processing many measurements
- Use appropriate buffer sizes
- Profile memory usage and async task overhead

## Conclusion

The ntpd-rs source driver architecture is consistently event-driven across all source types. New drivers should follow this pattern rather than implementing traditional polling loops. The modular spawner/source design provides good separation of concerns and makes it straightforward to add new source types while maintaining consistency with the existing codebase.

The key to successful implementation is understanding the async event-driven patterns used throughout the codebase and following the established communication protocols between spawners, sources, and the system coordinator.
