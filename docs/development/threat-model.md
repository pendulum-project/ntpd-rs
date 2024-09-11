# Threat model

This document a threat model, based on the methodology presented by Eleanor
Saitta, that we as developers use as a guide in our development process. It may
not contain all the context needed to fully understand it, if clarifications are
needed please ask us.

The used methodology is entirely manual, but is derived from
[Trike](https://www.octotrike.org/).

## Actors, Assets & Actions

### Actors

We model the following actors:

- System Admin: Administrator of the system running ntpd-rs
- System User: Non-administrator user of the system running ntpd-rs
- Reference Source: A remote time server we use as a source for our time.
- External Client: A remote user that is allowed to use this instance of
  ntpd-rs to receive time.
- Anonymous: Any other party

### Assets

We model the following assets:

- Clock: The system clock
- Source configuration: The configuration on which sources to use, including
  some metadata on the current status of those sources
- Server configuration: The configuration on which interfaces to provide an
  NTP server on, and who can use those, including some metadata on the current
  server status.
- Request nonce: The random nonce a client uses for a specific request to the
  server to match the response to the request.
- Client NTS keys: The keys a client uses to communicate with a server.
- Client NTS cookies: The cookies a client uses to communicate with the server.
- Server NTS keys: The keys a server uses to communicate with a client
  (ephemeral).
- Server NTS cookies: The cookies a server is about to send to a client
  (ephemeral).
- NTS Cookie keys: The keys a server uses to encrypt cookies.

### Actions

<table>
    <tr>
        <th></th>
        <th colspan=2>Clock</th>
        <th colspan=2>Source Configuration</th>
        <th colspan=2>Server Configuration</th>
        <th colspan=2>Request Nonce</th>
        <th colspan=2>Client NTS Keys</th>
        <th colspan=2>Client NTS Cookies</th>
        <th colspan=2>Server NTS Keys</th>
        <th colspan=2>Server NTS Cookies</th>
        <th colspan=2>NTS Cookie keys</th>
    </tr>
    <tr>
        <th rowspan=2>System admin</th>
        <td>Create - N/A</td>
        <td bgcolor="green">Read - Always</td>
        <td bgcolor="green">Create - Always</td>
        <td bgcolor="green">Read - Always</td>
        <td bgcolor="green">Create - Always</td>
        <td bgcolor="green">Read - Always</td>
        <td>Create - N/A</td>
        <td bgcolor="green">Read - Always</td>
        <td>Create - N/A</td>
        <td bgcolor="green">Read - Always</td>
        <td>Create - N/A</td>
        <td bgcolor="green">Read - Always</td>
        <td>Create - N/A</td>
        <td bgcolor="green">Read - Always</td>
        <td bgcolor="green">Create - Always</td>
        <td bgcolor="green">Read - Always</td>
        <td bgcolor="green">Create - Always</td>
        <td bgcolor="green">Read - Always</td>
    </tr>
    <tr>
        <td bgcolor="green">Update - Always</td>
        <td>Delete - N/A</td>
        <td bgcolor="green">Update - Always</td>
        <td>Delete - N/A</td>
        <td bgcolor="green">Update - Always</td>
        <td>Delete - N/A</td>
        <td>Update - N/A</td>
        <td>Delete - N/A</td>
        <td>Update - N/A</td>
        <td>Delete - N/A</td>
        <td>Update - N/A</td>
        <td>Delete - N/A</td>
        <td>Update - N/A</td>
        <td>Delete - N/A</td>
        <td>Update - N/A</td>
        <td>Delete - N/A</td>
        <td bgcolor="green">Update - Always</td>
        <td bgcolor="green">Delete - Always</td>
    </tr>
    <tr>
        <th rowspan=2>System user</th>
        <td>Create - N/A</td>
        <td bgcolor="green">Read - Always</td>
        <td bgcolor="red">Create - Never</td>
        <td bgcolor="orange">Read - Sometimes</td>
        <td bgcolor="red">Create - Never</td>
        <td bgcolor="orange">Read - Sometimes</td>
        <td>Create - N/A</td>
        <td bgcolor="orange">Read - Sometimes</td>
        <td>Create - N/A</td>
        <td bgcolor="orange">Read - Sometimes</td>
        <td>Create - N/A</td>
        <td bgcolor="orange">Read - Sometimes</td>
        <td>Create - N/A</td>
        <td bgcolor="orange">Read - Sometimes</td>
        <td bgcolor="orange">Create - Sometimes</td>
        <td bgcolor="orange">Read - Sometimes</td>
        <td bgcolor="orange">Create - Sometimes</td>
        <td bgcolor="orange">Read - Sometimes</td>
    </tr>
    <tr>
        <td bgcolor="red">Update - Never</td>
        <td>Delete - N/A</td>
        <td bgcolor="red">Update - Never</td>
        <td>Delete - N/A</td>
        <td bgcolor="red">Update - Never</td>
        <td>Delete - N/A</td>
        <td>Update - N/A</td>
        <td>Delete - N/A</td>
        <td>Update - N/A</td>
        <td>Delete - N/A</td>
        <td>Update - N/A</td>
        <td>Delete - N/A</td>
        <td>Update - N/A</td>
        <td>Delete - N/A</td>
        <td>Update - N/A</td>
        <td>Delete - N/A</td>
        <td bgcolor="orange">Update - Sometimes</td>
        <td bgcolor="orange">Delete - Sometimes</td>
    </tr>
    <tr>
        <th rowspan=2>Reference source</th>
        <td>Create - N/A</td>
        <td bgcolor="red">Read - Never</td>
        <td bgcolor="red">Create - Never</td>
        <td bgcolor="red">Read - Never</td>
        <td bgcolor="red">Create - Never</td>
        <td bgcolor="red">Read - Never</td>
        <td>Create - N/A</td>
        <td bgcolor="orange">Read - Sometimes</td>
        <td>Create - N/A</td>
        <td bgcolor="orange">Read - Sometimes</td>
        <td>Create - N/A</td>
        <td bgcolor="orange">Read - Sometimes</td>
        <td>Create - N/A</td>
        <td bgcolor="red">Read - Never</td>
        <td bgcolor="red">Create - Never</td>
        <td bgcolor="red">Read - Never</td>
        <td bgcolor="red">Create - Never</td>
        <td bgcolor="red">Read - Never</td>
    </tr>
    <tr>
        <td bgcolor="orange">Update - Sometimes</td>
        <td>Delete - N/A</td>
        <td bgcolor="red">Update - Never</td>
        <td>Delete - N/A</td>
        <td bgcolor="red">Update - Never</td>
        <td>Delete - N/A</td>
        <td>Update - N/A</td>
        <td>Delete - N/A</td>
        <td>Update - N/A</td>
        <td>Delete - N/A</td>
        <td>Update - N/A</td>
        <td>Delete - N/A</td>
        <td>Update - N/A</td>
        <td>Delete - N/A</td>
        <td>Update - N/A</td>
        <td>Delete - N/A</td>
        <td bgcolor="red">Update - Never</td>
        <td bgcolor="red">Delete - Never</td>
    </tr>
    <tr>
        <th rowspan=2>External client</th>
        <td>Create - N/A</td>
        <td bgcolor="green">Read - Always</td>
        <td bgcolor="red">Create - Never</td>
        <td bgcolor="green">Read - Always</td>
        <td bgcolor="red">Create - Never</td>
        <td bgcolor="red">Read - Never</td>
        <td>Create - N/A</td>
        <td bgcolor="red">Read - Never</td>
        <td>Create - N/A</td>
        <td bgcolor="red">Read - Never</td>
        <td>Create - N/A</td>
        <td bgcolor="red">Read - Never</td>
        <td>Create - N/A</td>
        <td bgcolor="orange">Read - Sometimes</td>
        <td bgcolor="orange">Create - Sometimes</td>
        <td bgcolor="orange">Read - Sometimes</td>
        <td bgcolor="red">Create - Never</td>
        <td bgcolor="red">Read - Never</td>
    </tr>
    <tr>
        <td bgcolor="red">Update - Never</td>
        <td>Delete - N/A</td>
        <td bgcolor="red">Update - Never</td>
        <td>Delete - N/A</td>
        <td bgcolor="red">Update - Never</td>
        <td>Delete - N/A</td>
        <td>Update - N/A</td>
        <td>Delete - N/A</td>
        <td>Update - N/A</td>
        <td>Delete - N/A</td>
        <td>Update - N/A</td>
        <td>Delete - N/A</td>
        <td>Update - N/A</td>
        <td>Delete - N/A</td>
        <td>Update - N/A</td>
        <td>Delete - N/A</td>
        <td bgcolor="red">Update - Never</td>
        <td bgcolor="red">Delete - Never</td>
    </tr>
    <tr>
        <th rowspan=2>Anonymous</th>
        <td>Create - N/A</td>
        <td bgcolor="red">Read - Never</td>
        <td bgcolor="red">Create - Never</td>
        <td bgcolor="red">Read - Never</td>
        <td bgcolor="red">Create - Never</td>
        <td bgcolor="red">Read - Never</td>
        <td>Create - N/A</td>
        <td bgcolor="red">Read - Never</td>
        <td>Create - N/A</td>
        <td bgcolor="red">Read - Never</td>
        <td>Create - N/A</td>
        <td bgcolor="red">Read - Never</td>
        <td>Create - N/A</td>
        <td bgcolor="red">Read - Never</td>
        <td bgcolor="red">Create - Never</td>
        <td bgcolor="red">Read - Never</td>
        <td bgcolor="red">Create - Never</td>
        <td bgcolor="red">Read - Never</td>
    </tr>
    <tr>
        <td bgcolor="red">Update - Never</td>
        <td>Delete - N/A</td>
        <td bgcolor="red">Update - Never</td>
        <td>Delete - N/A</td>
        <td bgcolor="red">Update - Never</td>
        <td>Delete - N/A</td>
        <td>Update - N/A</td>
        <td>Delete - N/A</td>
        <td>Update - N/A</td>
        <td>Delete - N/A</td>
        <td>Update - N/A</td>
        <td>Delete - N/A</td>
        <td>Update - N/A</td>
        <td>Delete - N/A</td>
        <td>Update - N/A</td>
        <td>Delete - N/A</td>
        <td bgcolor="red">Update - Never</td>
        <td bgcolor="red">Delete - Never</td>
    </tr>
</table>

- Reference sources may update the Clock only when sufficiently many agree and
  don't exceed configured adjustment limits.
- Reference sources may only know request information related to requests to
  them.
- System users may read configuration (both types) only when allowed by system
  admin.
- External clients may know key material and cookies related to their session.

## Failure cases

<table>
    <tr>
        <th></th>
        <th colspan=2>Escalation of Privilege</th>
        <th colspan=2>Denial of Service</th>
    </tr>
    <tr>
        <th rowspan=2>Clock</th>
        <td>Create - NA</td>
        <td bgcolor="green">Read - Low</td>
        <td>Create - NA</td>
        <td bgcolor="yellow">Read - Medium</td>
    </tr>
    <tr>
        <td bgcolor="red">Update - Critical</td>
        <td>Delete - N/A</td>
        <td bgcolor="yellow">Update - Medium</td>
        <td>Delete - N/A</td>
    </tr>
    <tr>
        <th rowspan=2>Source configuration</th>
        <td bgcolor="red">Create - Critical</td>
        <td bgcolor="yellow">Read - Medium</td>
        <td>Create - N/A</td>
        <td bgcolor="green">Read - Low</td>
    </tr>
    <tr>
        <td bgcolor="red">Update - Critical</td>
        <td>Delete - N/A</td>
        <td bgcolor="green">Update - Low</td>
        <td>Delete - N/A</td>
    </tr>
    <tr>
        <th rowspan=2>Server configuration</th>
        <td bgcolor="yellow">Create - Medium</td>
        <td bgcolor="green">Read - Low</td>
        <td>Create - N/A</td>
        <td bgcolor="green">Read - Low</td>
    </tr>
    <tr>
        <td bgcolor="yellow">Update - Medium</td>
        <td>Delete - N/A</td>
        <td bgcolor="green">Update - Low</td>
        <td>Delete - N/A</td>
    </tr>
    <tr>
        <th rowspan=2>Request nonce</th>
        <td>Create - N/A</td>
        <td bgcolor="green">Read - Low</td>
        <td>Create - N/A</td>
        <td>Read - N/A</td>
    </tr>
    <tr>
        <td>Update - N/A</td>
        <td>Delete - N/A</td>
        <td>Update - N/A</td>
        <td>Delete - N/A</td>
    </tr>
    <tr>
        <th rowspan=2>Client NTS keys</th>
        <td>Create - N/A</td>
        <td bgcolor="red">Read - Critical</td>
        <td>Create - N/A</td>
        <td>Read - N/A</td>
    </tr>
    <tr>
        <td>Update - N/A</td>
        <td>Delete - N/A</td>
        <td>Update - N/A</td>
        <td>Delete - N/A</td>
    </tr>
    <tr>
        <th rowspan=2>Client NTS cookies</th>
        <td>Create - N/A</td>
        <td bgcolor="green">Read - Low</td>
        <td>Create - N/A</td>
        <td>Read - N/A</td>
    </tr>
    <tr>
        <td>Update - N/A</td>
        <td>Delete - N/A</td>
        <td>Update - N/A</td>
        <td>Delete - N/A</td>
    </tr>
    <tr>
        <th rowspan=2>Server NTS keys</th>
        <td>Create - N/A</td>
        <td bgcolor="red">Read - Critical</td>
        <td>Create - N/A</td>
        <td>Read - N/A</td>
    </tr>
    <tr>
        <td>Update - N/A</td>
        <td>Delete - N/A</td>
        <td>Update - N/A</td>
        <td>Delete - N/A</td>
    </tr>
    <tr>
        <th rowspan=2>Server NTS cookies</th>
        <td>Create - N/A</td>
        <td bgcolor="green">Read - Low</td>
        <td>Create - N/A</td>
        <td>Read - N/A</td>
    </tr>
    <tr>
        <td>Update - N/A</td>
        <td>Delete - N/A</td>
        <td>Update - N/A</td>
        <td>Delete - N/A</td>
    </tr>
    <tr>
        <th rowspan=2>NTS Cookie keys</th>
        <td bgcolor="red">Create - Critical</td>
        <td bgcolor="red">Read - Critical</td>
        <td>Create - N/A</td>
        <td>Read - N/A</td>
    </tr>
    <tr>
        <td bgcolor="red">Update - Critical</td>
        <td bgcolor="yellow">Delete - Medium</td>
        <td>Update - N/A</td>
        <td>Delete - N/A</td>
    </tr>
</table>

 - Request nonce: The random nonce a client uses for a specific request to the
   server to match the response to the request.
 - Client NTS keys: The keys a client uses to communicate with a server.
 - Client NTS cookies: The cookies a client uses to communicate with the server.
 - Server NTS keys: The keys a server uses to communicate with a client
   (ephemeral).
 - Server NTS cookies: The cookies a server is about to send to a client
   (ephemeral).
 - NTS Cookie keys: The keys a server uses to encrypt cookies.

## Security strategy

- If any actor tries to read the clock, the system will not respond with a
  valid time if the IP address is not on the configured allowlist
- If any actor tries to update the clock, the system tries to verify consensus
  among multiple reference sources
- If any actor tries to update the clock, the system refuses updates beyond a
  configured limit
- If the configuration file (used to create the configuration) is
  world-writable, the system will emit a warning
- If the configuration socket (used to update the configuration) is
  world-writable, the system will emit a warning
- The observability socket (used to read the configuration/status) is a unix
  socket, which is unreachable over the network by default
- If any actor tries to read the clock too often, the system will stop
  responding a valid time to them
- If the nts cookie key storage file is world-readable, the system will emit a
  warning. The system will never create this file with permissions other than
  `0600`.

## Data flow diagram

![](flowdiagram.svg)

- The security boundaries between the admin and system users and ntpd-rs run
  through the unix sockets used for communication.
- The security boundaries for reference sources and external clients run
  through the network sockets used for communication.
