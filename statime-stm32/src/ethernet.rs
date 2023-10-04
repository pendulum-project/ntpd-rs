use core::task::Poll;

use defmt::unwrap;
use futures::future::poll_fn;
use ieee802_3_miim::{
    phy::{PhySpeed, LAN8742A},
    Phy,
};
use rtic::Mutex;
use rtic_monotonics::{systick::Systick, Monotonic};
use smoltcp::{
    iface::{Config, Interface, SocketHandle, SocketSet, SocketStorage},
    socket::{dhcpv4, udp},
    wire::{EthernetAddress, IpAddress, IpCidr, Ipv4Address},
};
use stm32_eth::{
    dma::{EthernetDMA, PacketId, PacketIdNotFound, RxRingEntry, TxRingEntry},
    mac,
    mac::{EthernetMACWithMii, MdcPin, MdioPin},
    ptp::Timestamp,
};
use stm32f7xx_hal::signature::Uid;

pub struct DmaResources {
    pub rx_ring: [RxRingEntry; 2],
    pub tx_ring: [TxRingEntry; 2],
}

impl DmaResources {
    pub const fn new() -> Self {
        Self {
            rx_ring: [RxRingEntry::new(), RxRingEntry::new()],
            tx_ring: [TxRingEntry::new(), TxRingEntry::new()],
        }
    }
}

#[derive(Copy, Clone)]
pub struct UdpSocketResources {
    pub rx_meta_storage: [udp::PacketMetadata; 8],
    pub rx_payload_storage: [u8; 8192],
    pub tx_meta_storage: [udp::PacketMetadata; 8],
    pub tx_payload_storage: [u8; 8192],
}

impl UdpSocketResources {
    pub const fn new() -> Self {
        Self {
            rx_meta_storage: [udp::PacketMetadata::EMPTY; 8],
            rx_payload_storage: [0; 8192],
            tx_meta_storage: [udp::PacketMetadata::EMPTY; 8],
            tx_payload_storage: [0; 8192],
        }
    }
}

pub struct NetworkStack {
    pub dma: EthernetDMA<'static, 'static>,
    pub iface: Interface,
    pub sockets: SocketSet<'static>,
}

impl NetworkStack {
    pub fn poll(&mut self) {
        self.iface
            .poll(now(), &mut &mut self.dma, &mut self.sockets);
    }

    pub fn poll_delay(&mut self) -> Option<smoltcp::time::Duration> {
        self.iface.poll_delay(now(), &self.sockets)
    }
}

fn now() -> smoltcp::time::Instant {
    let now_millis = Systick::now().ticks();
    // TODO handle case where systick is not 1kHz
    smoltcp::time::Instant::from_millis(i64::try_from(now_millis).unwrap())
}

/// Initialize the PHY, wait for link and set the speed
///
/// This function will *block* until the ethernet link is up!
pub fn setup_phy<MDIO: MdioPin, MDC: MdcPin>(mac: EthernetMACWithMii<MDIO, MDC>) {
    // Setup PHY
    let mut phy = LAN8742A::new(mac, 0);

    phy.phy_init();

    defmt::info!("Waiting for link up.");

    while !phy.phy_link_up() {}

    defmt::info!("Link up.");

    if let Some(speed) = phy.link_speed().map(|s| match s {
        PhySpeed::HalfDuplexBase10T => mac::Speed::HalfDuplexBase10T,
        PhySpeed::FullDuplexBase10T => mac::Speed::FullDuplexBase10T,
        PhySpeed::HalfDuplexBase100Tx => mac::Speed::HalfDuplexBase100Tx,
        PhySpeed::FullDuplexBase100Tx => mac::Speed::FullDuplexBase100Tx,
    }) {
        phy.get_miim().set_speed(speed);
        defmt::info!("Detected link speed: {}", speed);
    } else {
        defmt::warn!("Failed to detect link speed.");
    }
}

pub fn setup_smoltcp(
    sockets: &'static mut [SocketStorage],
    mut dma: &mut EthernetDMA,
    mac_address: [u8; 6],
) -> (Interface, SocketSet<'static>) {
    // Setup smoltcp
    let cfg = Config::new(EthernetAddress(mac_address).into());

    let mut interface = Interface::new(cfg, &mut dma, smoltcp::time::Instant::ZERO);

    interface.update_ip_addrs(|a| {
        unwrap!(a.push(IpCidr::new(IpAddress::v4(10, 0, 0, 2), 24)));
    });

    unwrap!(interface.join_multicast_group(
        &mut dma,
        Ipv4Address::new(224, 0, 1, 129),
        smoltcp::time::Instant::ZERO
    ));
    unwrap!(interface.join_multicast_group(
        &mut dma,
        Ipv4Address::new(224, 0, 0, 107),
        smoltcp::time::Instant::ZERO
    ));

    defmt::info!("Set IPs to: {}", interface.ip_addrs());

    // Register socket
    let sockets = SocketSet::new(sockets);

    (interface, sockets)
}

pub fn setup_udp_socket(
    socket_set: &mut SocketSet,
    resources: &'static mut UdpSocketResources,
    port: u16,
) -> SocketHandle {
    let UdpSocketResources {
        rx_meta_storage,
        rx_payload_storage,
        tx_meta_storage,
        tx_payload_storage,
    } = resources;

    let rx_buffer = udp::PacketBuffer::new(&mut rx_meta_storage[..], &mut rx_payload_storage[..]);
    let tx_buffer = udp::PacketBuffer::new(&mut tx_meta_storage[..], &mut tx_payload_storage[..]);
    let mut socket = udp::Socket::new(rx_buffer, tx_buffer);
    unwrap!(socket.bind(port));

    socket_set.add(socket)
}

pub fn setup_dhcp_socket(socket_set: &mut SocketSet) -> SocketHandle {
    let dhcp_socket = dhcpv4::Socket::new();
    socket_set.add(dhcp_socket)
}

pub async fn recv_slice(
    net: &mut impl Mutex<T = NetworkStack>,
    socket: SocketHandle,
    buffer: &mut [u8],
) -> Result<(usize, Timestamp), RecvError> {
    poll_fn(|cx| {
        let result = net.lock(|net| {
            // Get next packet (if any)
            let socket: &mut udp::Socket = net.sockets.get_mut(socket);
            socket.register_recv_waker(cx.waker());
            let (len, meta) = socket.recv_slice(buffer)?;

            // Get the timestamp
            let packet_id = PacketId::from(meta.meta);
            let timestamp = match net.dma.rx_timestamp(&packet_id) {
                Ok(Some(ts)) => ts,
                Ok(None) => return Err(RecvError::NoTimestampRecorded),
                Err(e) => return Err(e.into()),
            };

            // Return the buffer length and timestamp
            Ok((len, timestamp))
        });

        match result {
            Ok(r) => Poll::Ready(Ok(r)),
            Err(RecvError::Exhausted) => Poll::Pending,
            e @ Err(_) => Poll::Ready(e),
        }
    })
    .await
}

#[derive(Debug, Clone, Copy, defmt::Format)]
pub enum RecvError {
    Exhausted,
    PacketIdNotFound(PacketIdNotFound),
    NoTimestampRecorded,
}

impl From<PacketIdNotFound> for RecvError {
    fn from(value: PacketIdNotFound) -> Self {
        Self::PacketIdNotFound(value)
    }
}

impl From<udp::RecvError> for RecvError {
    fn from(value: udp::RecvError) -> Self {
        match value {
            udp::RecvError::Exhausted => Self::Exhausted,
        }
    }
}

/// Generate a mac based on the UID of the chip.
///
/// *Note: This is not the proper way to do it.
/// You're supposed to buy a mac address or buy a phy that includes a mac and
/// use that one*
pub fn generate_mac_address() -> [u8; 6] {
    let mut hasher = adler::Adler32::new();

    // Form the basis of our OUI octets
    let bin_name = env!("CARGO_BIN_NAME").as_bytes();
    hasher.write_slice(bin_name);
    let oui = hasher.checksum().to_ne_bytes();

    // Form the basis of our NIC octets
    let uid: [u8; 12] =
        unsafe { core::mem::transmute_copy::<_, [u8; core::mem::size_of::<Uid>()]>(Uid::get()) };
    hasher.write_slice(&uid);
    let nic = hasher.checksum().to_ne_bytes();

    // To make it adhere to EUI-48, we set it to be a unicast locally administered
    // address
    [
        oui[0] & 0b1111_1100 | 0b0000_0010,
        oui[1],
        oui[2],
        nic[0],
        nic[1],
        nic[2],
    ]
}

/// Convert a mac address (or formally EUI-48) to a EUI-64
///
/// TODO check reference
/// Conversion follows the [Guidelines for Use of Extended Unique Identifier (EUI), Organizationally Unique Identifier (OUI), and Company ID (CID)](https://standards.ieee.org/wp-content/uploads/import/documents/tutorials/eui.pdf)
pub fn eui48_to_eui64(address: [u8; 6]) -> [u8; 8] {
    [
        address[0] ^ 0b00000010,
        address[1],
        address[2],
        0xff,
        0xfe,
        address[3],
        address[4],
        address[5],
    ]
}
