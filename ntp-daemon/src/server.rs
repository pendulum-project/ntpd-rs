use std::{net::SocketAddr, sync::Arc};

use ntp_proto::{
    NtpAssociationMode, NtpClock, NtpHeader, NtpTimestamp, ReferenceId, SystemSnapshot,
};
use ntp_udp::UdpSocket;
use tokio::{sync::RwLock, task::JoinHandle};
use tracing::{error, instrument, trace, warn};

pub struct ServerTask<C: 'static + NtpClock + Send> {
    socket: UdpSocket,
    system: Arc<RwLock<SystemSnapshot>>,
    client_cache: TimestampedCache<SocketAddr>,
    clock: C,
}

impl<C: 'static + NtpClock + Send> ServerTask<C> {
    pub fn spawn(
        addr: SocketAddr,
        system: Arc<RwLock<SystemSnapshot>>,
        clock: C,
        network_wait_period: std::time::Duration,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            let socket = loop {
                match UdpSocket::server(addr).await {
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
                client_cache: TimestampedCache::new(32),
            };

            process.serve().await
        })
    }

    #[instrument(level = "debug", skip(self), fields(
        addr = debug(self.socket.as_ref().local_addr().unwrap()),
    ))]
    async fn serve(&mut self) {
        loop {
            let mut buf = [0_u8; 48];
            let recv_res = self.socket.recv(&mut buf).await;
            match accept_packet(recv_res, &buf) {
                AcceptResult::Accept(packet, peer_addr, recv_timestamp) => {
                    let system = *self.system.read().await;

                    let timestamp = std::time::Instant::now();
                    let cutoff = std::time::Duration::from_secs(32);

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

#[derive(Debug)]
struct TimestampedCache<T> {
    elements: Vec<Option<(T, std::time::Instant)>>,
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

    fn insert(&mut self, item: T, timestamp: std::time::Instant) {
        let index = self.index(&item);
        self.elements[index] = Some((item, timestamp));
    }

    fn get(&self, item: &T) -> Option<std::time::Instant> {
        match &self.elements[self.index(item)] {
            None => None,
            Some((existing, timestamp)) => {
                if existing == item {
                    Some(*timestamp)
                } else {
                    None
                }
            }
        }
    }

    fn is_allowed(
        &mut self,
        item: T,
        timestamp: std::time::Instant,
        cutoff: std::time::Duration,
    ) -> bool {
        match self.get(&item) {
            None => {
                self.insert(item, timestamp);
                true
            }
            Some(existing_timestamp) => {
                self.insert(item, timestamp);

                timestamp.duration_since(existing_timestamp) >= cutoff
            }
        }
    }
}
