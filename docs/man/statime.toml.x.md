<!-- ---
title: STATIME.TOML(x) statime-linux 1.0.0 | statime-linux
--- -->

# NAME

`statime.toml` - configuration file for the statime-linux ptp-daemon

# DESCRIPTION

Configuration of ntpd-rs happens in the `statime.toml` configuration format. The
toml format is in lots of ways similar to a simple ini with several extensions
allowing a json-like syntax.

The statime configuration file consists of several sections, each of which
configures a separate part of the ptp-daemon process. Each of the secions is
described in the rest of this document. Many settings will have defaults, which
will be indicated by each configuration setting shown.

# CONFIGURATION

## `[[port]]` 

`interface` = *interface name*
:   The network interface of this PTP port. For instance `"lo"` or `"enp0s31f6"`

`announce_interval` = *interval* (**1**)
:   How often an announce message is sent by a master.
    Defined as an exponent of 2, so a value of 1 means every 2^1 = 2 seconds

`sync_interval` = *interval* (**0**)
:   How often a sync message is sent. 
    Defined as an exponent of 2, so a value of 0 means every 2^0 = 1 seconds

`announce_receipt_timeout` = *number of announce intervals* (**3**)
:   Number of announce intervals to wait before the port becomes master 

`delay_asymmetry` = *nanoseconds* (**0**)
:   The value is positive when the slave-to-master propagation time is longer than the master-to-slave propagation time.

`delay_mechanism` = *interval* (**0**)
:   Currently the only supported delay mechanism is E2E.
    Defined as an exponent of 2, so a value of 0 means every 2^0 = 1 seconds

`master_only` = *bool* (**false**)
:   The port is always a master instance

`hardware_clock` = *path* (**unset**)
:   Path to a hardware clock device, for instance ` "/dev/ptp0"` 

`acceptable_master_list` = [ *clock identity*, .. ] (**unset**)
:   List of clock identities that this port will accept as its master.
    A clock identity is encoded as a 16-character hexadecimal string, for example 
    `acceptable_master_list = ["00FFFFFFFFFFFFFB"]`

