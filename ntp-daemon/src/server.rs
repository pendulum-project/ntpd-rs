use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use ntp_proto::{
    NtpAssociationMode, NtpClock, NtpHeader, NtpTimestamp, ReferenceId, SystemSnapshot,
};
use ntp_udp::UdpSocket;
use tokio::{sync::RwLock, task::JoinHandle};
use tracing::{error, instrument, trace, warn};

use crate::config::ServerConfig;

pub struct ServerTask<C: 'static + NtpClock + Send> {
    socket: UdpSocket,
    system: Arc<RwLock<SystemSnapshot>>,
    client_cache: TimestampedCache<SocketAddr>,
    clock: C,
}

impl<C: 'static + NtpClock + Send> ServerTask<C> {
    pub fn spawn(
        config: ServerConfig,
        system: Arc<RwLock<SystemSnapshot>>,
        clock: C,
        network_wait_period: Duration,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            let socket = loop {
                match UdpSocket::server(config.addr).await {
                    Ok(socket) => break socket,
                    Err(error) => {
                        warn!(?error, "Could not open server socket");
                        tokio::time::sleep(network_wait_period).await;
                    }
                }
            };

            // Unwrap should be safe because we know the socket was bound to a local addres just before
            let _our_id = ReferenceId::from_ip(socket.as_ref().local_addr().unwrap().ip());

            let mut process = ServerTask {
                socket,
                system,
                clock,
                client_cache: TimestampedCache::new(config.rate_limiting_cache_size),
            };

            process.serve(config.rate_limiting_cutoff).await
        })
    }

    #[instrument(level = "debug", skip(self), fields(
        addr = debug(self.socket.as_ref().local_addr().unwrap()),
    ))]
    async fn serve(&mut self, rate_limiting_cutoff: Duration) {
        loop {
            let mut buf = [0_u8; 48];
            let recv_res = self.socket.recv(&mut buf).await;
            match accept_packet(recv_res, &buf) {
                AcceptResult::Accept(packet, peer_addr, recv_timestamp) => {
                    let system = *self.system.read().await;

                    let timestamp = Instant::now();
                    let cutoff = rate_limiting_cutoff;

                    let response = if self.client_cache.is_allowed(peer_addr, timestamp, cutoff) {
                        NtpHeader::timestamp_response(
                            &system,
                            packet,
                            recv_timestamp,
                            &mut self.clock,
                        )
                    } else {
                        NtpHeader::rate_limit_response()
                    };

                    if let Err(send_err) =
                        self.socket.send_to(&response.serialize(), peer_addr).await
                    {
                        warn!(error=?send_err, "Could not send response packet");
                    }
                }
                AcceptResult::NetworkGone => {
                    // TODO: handle network failures
                    error!("Server connection gone");
                    break;
                }
                AcceptResult::Ignore => {}
            }
        }
    }
}

enum AcceptResult {
    Accept(NtpHeader, SocketAddr, NtpTimestamp),
    Ignore,
    NetworkGone,
}

fn accept_packet(
    result: Result<(usize, SocketAddr, Option<NtpTimestamp>), std::io::Error>,
    buf: &[u8; 48],
) -> AcceptResult {
    match result {
        Ok((size, peer_addr, Some(recv_timestamp))) => {
            // Note: packets are allowed to be bigger when including extensions.
            // we don't expect them, but the server may still send them. The
            // extra bytes are guaranteed safe to ignore. `recv` truncates the messages.
            // Messages of fewer than 48 bytes are skipped entirely
            if size < 48 {
                warn!(expected = 48, actual = size, "received packet is too small");

                AcceptResult::Ignore
            } else {
                match NtpHeader::deserialize(buf) {
                    Ok(packet) => match packet.mode {
                        NtpAssociationMode::Client => {
                            trace!("NTP client request accepted from {}", peer_addr);
                            AcceptResult::Accept(packet, peer_addr, recv_timestamp)
                        }
                        _ => {
                            trace!(
                                "NTP packet with unkown mode {:?} ignored from {}",
                                packet.mode,
                                peer_addr
                            );
                            AcceptResult::Ignore
                        }
                    },
                    Err(e) => {
                        warn!("received invalid packet: {}", e);
                        AcceptResult::Ignore
                    }
                }
            }
        }
        Ok((size, _, None)) => {
            warn!(?size, "received a packet without a timestamp");

            AcceptResult::Ignore
        }
        Err(receive_error) => {
            warn!(?receive_error, "could not receive packet");

            match receive_error.raw_os_error() {
                // For a server, we only trigger NetworkGone restarts
                // on ENETDOWN. ENETUNREACH, EHOSTDOWN and EHOSTUNREACH
                // do not signal restart-worthy conditions for the a
                // server (they essentially indicate problems with the
                // remote network/host, which is not relevant for a server).
                // Furthermore, they can conceivably be triggered by a
                // malicious third party, and triggering restart on them
                // would then result in a denial-of-service.
                Some(libc::ENETDOWN) => AcceptResult::NetworkGone,
                _ => AcceptResult::Ignore,
            }
        }
    }
}

/// A size-bounded cache where each entry is timestamped.
///
/// The planned use is in rate limiting: we keep track of when a peer last checked in. If it checks
/// in too often, we issue a rate limiting KISS code.
///
/// The implementation is fixed-size (and in practice small) hash map. Collisions are not a big
/// problem (the cache size can be configured if we observe too many collisions)
#[derive(Debug)]
struct TimestampedCache<T> {
    elements: Vec<Option<(T, Instant)>>,
}

impl<T: std::hash::Hash + Eq> TimestampedCache<T> {
    fn new(length: usize) -> Self {
        Self {
            // looks a bit odd, but prevents a `Clone` constraint
            elements: std::iter::repeat_with(|| None).take(length).collect(),
        }
    }

    fn index(&self, item: &T) -> usize {
        use std::hash::Hasher;

        let mut hasher = std::collections::hash_map::DefaultHasher::default();

        item.hash(&mut hasher);

        hasher.finish() as usize % self.elements.len()
    }

    fn is_allowed(&mut self, item: T, timestamp: Instant, cutoff: Duration) -> bool {
        let index = self.index(&item);

        // check if the current occupant of this slot is actually the same item
        let timestamp_if_same = self.elements[index]
            .as_ref()
            .and_then(|(v, t)| (&item == v).then_some(t))
            .copied();

        self.elements[index] = Some((item, timestamp));

        if let Some(old_timestamp) = timestamp_if_same {
            // old and new are the same; check the time
            timestamp.duration_since(old_timestamp) <= cutoff
        } else {
            // old and new are different; this is always OK
            true
        }
    }
}

#[cfg(test)]
mod timestamped_cache {
    use std::time::{Duration, Instant};

    use super::*;

    #[test]
    fn timestamped_cache() {
        let length = 8u8;
        let mut cache: TimestampedCache<u8> = TimestampedCache::new(length as usize);

        let second = Duration::from_secs(1);
        let instant = Instant::now();

        cache.is_allowed(0, instant, second);

        assert!(cache.is_allowed(0, instant, second));

        let later = instant + 2 * second;
        assert!(!cache.is_allowed(0, later, second));

        // simulate a hash collision
        let even_later = later + 2 * second;
        assert!(cache.is_allowed(length, even_later, second));
    }
}
