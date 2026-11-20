use std::{
    fmt::{self, Debug},
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    sync::Arc,
};

// This can be extended when necessary via
// $ varlinkctl introspect /run/systemd/resolve/io.systemd.Resolve io.systemd.Resolve
// See also org.freedesktop.resolve1(5)
varlink_derive::varlink_async!(
    io_systemd_resolve,
    r#"
interface io.systemd.Resolve

# Encapsulates a resolved address.
type ResolvedAddress(
        ifindex: ?int,
        family: int,
        address: []int
)

# Resolves a hostname to one or more IP addresses.
method ResolveHostname(
        # The Linux interface index for the network interface to search on. Typically left unspecified, in order to search on all interfaces.
        ifindex: ?int,
        # The host name to resolve.
        name: string,
        # The address family to search for, one of AF_INET or AF_INET6.
        family: ?int,
        # Various search flags.
        flags: ?int
) -> (
        # Array of resolved IP addresses
        addresses: []ResolvedAddress,
        # Canonical name of the host.
        name: string,
        # Various flags indicating details on discovered data.
        flags: int
)
"#
);

use io_systemd_resolve::{
    Call_ResolveHostname, ErrorKind, VarlinkCallError, VarlinkClient, VarlinkClientInterface,
    VarlinkInterface,
};

/// Input: Don't DNSSEC validate request
const SD_RESOLVED_NO_VALIDATE: i64 = 1 << 10;

const SD_RESOLVED_ADDR: &str = "unix:/run/systemd/resolve/io.systemd.Resolve";

/// A client for systemd-resolved's varlink API.
pub struct ResolvedClient(VarlinkClient);

impl ResolvedClient {
    /// Attempts to connect to systemd-resolved over varlink at its default
    /// socket location.
    ///
    /// # Errors
    ///
    /// Returns a [`varlink::Error`] when connecting fails.
    pub async fn try_connect() -> varlink::Result<Self> {
        let connection = varlink::AsyncConnection::with_address(SD_RESOLVED_ADDR).await?;

        Ok(Self(VarlinkClient::new(connection)))
    }

    /// Try to resolve a hostname through systemd-resolved.
    ///
    /// # Errors
    ///
    /// Returns an [`io::Error`] when the lookup fails.
    pub async fn resolve_hostname(
        &self,
        host: String,
        port: u16,
        disable_dnssec: bool,
    ) -> io::Result<impl Iterator<Item = SocketAddr>> {
        let reply = self
            .0
            .resolve_hostname(
                None,
                host,
                None,
                disable_dnssec.then_some(SD_RESOLVED_NO_VALIDATE),
            )
            .call()
            .await
            .map_err(|e| io::Error::other(e))?;

        Ok(reply
            .addresses
            .into_iter()
            .map(move |addr| match addr.family as i32 {
                libc::AF_INET => SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::new(
                        addr.address[0] as u8,
                        addr.address[1] as u8,
                        addr.address[2] as u8,
                        addr.address[3] as u8,
                    ),
                    port,
                )),
                libc::AF_INET6 => SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::new(
                        addr.address[0] as u16,
                        addr.address[1] as u16,
                        addr.address[2] as u16,
                        addr.address[3] as u16,
                        addr.address[4] as u16,
                        addr.address[5] as u16,
                        addr.address[6] as u16,
                        addr.address[7] as u16,
                    ),
                    port,
                    0,
                    0,
                )),
                _ => unreachable!(),
            }))
    }
}
