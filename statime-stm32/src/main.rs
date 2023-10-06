#![no_main]
#![no_std]
#![feature(type_alias_impl_trait)]
// This lint produces false positives in this project with the nightly-2023-09-19 compiler
#![allow(clippy::needless_pass_by_ref_mut)]

use core::{pin::pin, task::Poll};

use defmt::unwrap;
use defmt_rtt as _;
use embassy_sync::waitqueue::WakerRegistration;
use ethernet::{DmaResources, NetworkStack};
use futures::future::FutureExt;
use panic_probe as _;
use rtic::{app, Mutex};
use rtic_monotonics::systick::{ExtU64, Systick};
use rtic_sync::{channel::Receiver, make_channel};
use smoltcp::{
    iface::{SocketHandle, SocketStorage},
    socket::dhcpv4,
    wire::{IpCidr, Ipv4Address, Ipv4Cidr},
};
use statime::{BasicFilter, PtpInstance};
use stm32_eth::{dma::PacketId, EthPins, Parts, PartsIn};
use stm32f7xx_hal::{
    gpio::{Output, Pin, Speed},
    prelude::*,
    rng::RngExt,
};

use crate::{
    ethernet::{generate_mac_address, recv_slice, UdpSocketResources},
    port::setup_statime,
    ptp_clock::stm_time_to_statime,
};

mod ethernet;
mod port;
mod ptp_clock;

defmt::timestamp!("{=u64:iso8601ms}", {
    let time = stm32_eth::ptp::EthernetPTP::get_time();
    time.seconds() as u64 * 1_000 + (time.subseconds().nanos() / 1000000) as u64
});

#[app(device = stm32f7xx_hal::pac, dispatchers = [CAN1_RX0])]
mod app {
    use super::*;
    use crate::port::TimerName;

    #[shared]
    struct Shared {
        net: NetworkStack,
        ptp_port: port::Port,
        tx_waker: WakerRegistration,
    }

    #[local]
    struct Local {}

    #[init(local = [
        dma_resources: DmaResources = DmaResources::new(),
        sockets: [SocketStorage<'static>; 8] = [SocketStorage::EMPTY; 8],
        udp_resources: [UdpSocketResources; 2] = [UdpSocketResources::new(); 2]
    ])]
    fn init(cx: init::Context) -> (Shared, Local) {
        let p = cx.device;

        // Setup clocks
        let clocks = {
            let rcc = p.RCC.constrain();
            let clocks = rcc.cfgr.sysclk(216.MHz()).hclk(216.MHz());
            clocks.freeze()
        };

        // Setup systick to be used for delays
        let systick_token = rtic_monotonics::create_systick_token!();
        Systick::start(cx.core.SYST, clocks.sysclk().to_Hz(), systick_token);

        // Uncomment to see the statime logs at the cost of quite a bit of extra flash
        // usage
        //
        // log_to_defmt::setup();

        // Setup GPIO
        let (led_pin, pps, eth_pins, mdio, mdc) = {
            let gpioa = p.GPIOA.split();
            let gpiob = p.GPIOB.split();
            let gpioc = p.GPIOC.split();
            let gpiog = p.GPIOG.split();

            let led_pin = gpiob.pb7.into_push_pull_output();
            let pps = gpiob.pb5.into_push_pull_output();

            let ref_clk = gpioa.pa1.into_floating_input();
            let crs = gpioa.pa7.into_floating_input();
            let tx_d1 = gpiob.pb13.into_floating_input();
            let rx_d0 = gpioc.pc4.into_floating_input();
            let rx_d1 = gpioc.pc5.into_floating_input();

            let (tx_en, tx_d0) = {
                (
                    gpiog.pg11.into_floating_input(),
                    gpiog.pg13.into_floating_input(),
                )
            };

            let (mdio, mdc) = (
                gpioa.pa2.into_alternate().set_speed(Speed::VeryHigh),
                gpioc.pc1.into_alternate().set_speed(Speed::VeryHigh),
            );

            let eth_pins = EthPins {
                ref_clk,
                crs,
                tx_en,
                tx_d0,
                tx_d1,
                rx_d0,
                rx_d1,
            };

            (led_pin, pps, eth_pins, mdio, mdc)
        };

        // Setup Ethernet
        let Parts {
            mut dma,
            mac,
            mut ptp,
        } = {
            let ethernet = PartsIn {
                dma: p.ETHERNET_DMA,
                mac: p.ETHERNET_MAC,
                mmc: p.ETHERNET_MMC,
                ptp: p.ETHERNET_PTP,
            };

            let DmaResources { rx_ring, tx_ring } = cx.local.dma_resources;

            unwrap!(stm32_eth::new_with_mii(
                ethernet, rx_ring, tx_ring, clocks, eth_pins, mdio, mdc
            )
            .ok())
        };

        defmt::trace!("Enabling DMA interrupts");
        dma.enable_interrupt();

        // Setup PPS
        ptp.enable_pps(pps);
        ptp.set_pps_freq(4);

        // Setup PHY
        crate::ethernet::setup_phy(mac);

        // Setup smoltcp as our network stack
        let mac_address = generate_mac_address();
        let (interface, mut sockets) =
            crate::ethernet::setup_smoltcp(cx.local.sockets, &mut dma, mac_address);

        // Create sockets
        let [tc_res, g_res] = cx.local.udp_resources;

        let event_socket = crate::ethernet::setup_udp_socket(&mut sockets, tc_res, 319);
        let general_socket = crate::ethernet::setup_udp_socket(&mut sockets, g_res, 320);

        // Setup DHCP
        let dhcp_socket = crate::ethernet::setup_dhcp_socket(&mut sockets);

        let net = NetworkStack {
            dma,
            iface: interface,
            sockets,
        };

        // Setup statime
        let rng = p.RNG.init();
        let (ptp_instance, ptp_port) = setup_statime(ptp, mac_address, rng);

        // Setup message channels
        type TimerMsg = (TimerName, core::time::Duration);
        let (timer_sender, timer_receiver) = make_channel!(TimerMsg, 4);

        type PacketIdMsg = (statime::TimestampContext, PacketId);
        let (packet_id_sender, packet_id_receiver) = make_channel!(PacketIdMsg, 16);

        // Setup context for event handling around the `ptp_port`
        let ptp_port = port::Port::new(
            timer_sender,
            packet_id_sender,
            event_socket,
            general_socket,
            ptp_port,
        );

        // Start tasks
        {
            // Blink LED
            blinky::spawn(led_pin).unwrap_or_else(|_| defmt::panic!("Failed to start blinky"));

            // Listen on sockets
            event_listen::spawn().unwrap_or_else(|_| defmt::panic!("Failed to start event_listen"));
            general_listen::spawn()
                .unwrap_or_else(|_| defmt::panic!("Failed to start general_listen"));

            // Listen for transmit timestamps
            tx_timestamp_listener::spawn(packet_id_receiver)
                .unwrap_or_else(|_| defmt::panic!("Failed to start send_timestamp_grabber"));

            // Listen for timer events
            statime_timers::spawn(timer_receiver)
                .unwrap_or_else(|_| defmt::panic!("Failed to start timers"));

            // Handle BMCA phase for statime
            instance_bmca::spawn(ptp_instance)
                .unwrap_or_else(|_| defmt::panic!("Failed to start instance bmca"));

            // Poll network interfaces and run DHCP
            poll_smoltcp::spawn().unwrap_or_else(|_| defmt::panic!("Failed to start poll_smoltcp"));
            dhcp::spawn(dhcp_socket).unwrap_or_else(|_| defmt::panic!("Failed to start dhcp"));
        }

        (
            Shared {
                net,
                ptp_port,
                tx_waker: WakerRegistration::new(),
            },
            Local {},
        )
    }

    /// Task that runs the BMCA every required interval
    #[task(shared = [net, ptp_port], priority = 1)]
    async fn instance_bmca(
        mut cx: instance_bmca::Context,
        ptp_instance: &'static PtpInstance<BasicFilter>,
    ) {
        let net = &mut cx.shared.net;
        let ptp_port = &mut cx.shared.ptp_port;

        loop {
            // Run the BMCA with our single port
            ptp_port.lock(|ptp_port| {
                ptp_port.perform_bmca(
                    |bmca_port| {
                        ptp_instance.bmca(&mut [bmca_port]);
                    },
                    net,
                );
            });

            // Wait for the given time before running again
            let wait_duration = ptp_instance.bmca_interval();
            Systick::delay((wait_duration.as_millis() as u64).millis()).await;
        }
    }

    /// Task that runs the timers and lets the port handle the expired timers.
    /// The channel is used for resetting the timers (which comes from the port
    /// actions and get sent here).
    #[task(shared = [net, ptp_port], priority = 0)]
    async fn statime_timers(
        mut cx: statime_timers::Context,
        mut timer_resets: Receiver<'static, (TimerName, core::time::Duration), 4>,
    ) {
        let net = &mut cx.shared.net;
        let ptp_port = &mut cx.shared.ptp_port;

        let mut announce_timer_delay = pin!(Systick::delay(24u64.hours()).fuse());
        let mut sync_timer_delay = pin!(Systick::delay(24u64.hours()).fuse());
        let mut delay_request_timer_delay = pin!(Systick::delay(24u64.hours()).fuse());
        let mut announce_receipt_timer_delay = pin!(Systick::delay(24u64.hours()).fuse());
        let mut filter_update_timer_delay = pin!(Systick::delay(24u64.hours()).fuse());

        loop {
            futures::select_biased! {
                _ = announce_timer_delay => {
                    ptp_port.lock(|port| port.handle_timer(TimerName::Announce, net));
                }
                _ = sync_timer_delay => {
                    ptp_port.lock(|port| port.handle_timer(TimerName::Sync, net));
                }
                _ = delay_request_timer_delay => {
                    ptp_port.lock(|port| port.handle_timer(TimerName::DelayRequest, net));
                }
                _ = announce_receipt_timer_delay => {
                    ptp_port.lock(|port| port.handle_timer(TimerName::AnnounceReceipt, net));
                }
                _ = filter_update_timer_delay => {
                    ptp_port.lock(|port| port.handle_timer(TimerName::FilterUpdate, net));
                }
                reset = timer_resets.recv().fuse() => {
                    let (timer, delay_time) = unwrap!(reset.ok());

                    let delay = match timer {
                        TimerName::Announce => &mut announce_timer_delay,
                        TimerName::Sync => &mut sync_timer_delay,
                        TimerName::DelayRequest => &mut delay_request_timer_delay,
                        TimerName::AnnounceReceipt => &mut announce_receipt_timer_delay,
                        TimerName::FilterUpdate => &mut filter_update_timer_delay,
                    };

                    delay.set(Systick::delay((delay_time.as_millis() as u64).millis()).fuse());
                }
            }
        }
    }

    /// Listen for new transmission timestamps
    ///
    /// This waits for new packet IDs of send packets for which a timestamp
    /// should be collected and fetches them from the ethernet peripheral. In
    /// case the packet ID is not known yet it will retry a few times to handle
    /// the case where a packet is not send directly (e.g. because ARP is
    /// fetching the receivers mac address).
    #[task(shared = [net, ptp_port, tx_waker], priority = 0)]
    async fn tx_timestamp_listener(
        mut cx: tx_timestamp_listener::Context,
        mut packet_id_receiver: Receiver<'static, (statime::TimestampContext, PacketId), 16>,
    ) {
        // Extract state to keep code more readable
        let tx_waker = &mut cx.shared.tx_waker;
        let net = &mut cx.shared.net;
        let ptp_port = &mut cx.shared.ptp_port;

        loop {
            // Wait for the next (smoltcp) packet id and its (statime) timestamp context
            let (timestamp_context, packet_id) = unwrap!(packet_id_receiver.recv().await.ok());

            // We try a limited amount of times since the queued packet might not be sent
            // first (e.g. in case ARP needs to run first)
            let mut tries = 10;

            let timestamp = core::future::poll_fn(|ctx| {
                // Register to wake up after every tx packet has been sent
                tx_waker.lock(|tx_waker| tx_waker.register(ctx.waker()));

                // Keep polling as long as we have tries left
                match net.lock(|net| net.dma.poll_tx_timestamp(&packet_id)) {
                    Poll::Ready(Ok(ts)) => Poll::Ready(ts),
                    Poll::Ready(Err(_)) | Poll::Pending => {
                        if tries > 0 {
                            tries -= 1;
                            Poll::Pending
                        } else {
                            Poll::Ready(None)
                        }
                    }
                }
            })
            .await;

            match timestamp {
                Some(timestamp) => ptp_port.lock(|port| {
                    // Inform statime about the timestamp we collected
                    port.handle_send_timestamp(
                        timestamp_context,
                        stm_time_to_statime(timestamp),
                        net,
                    );
                }),
                None => defmt::error!("Failed to get timestamp for packet id {}", packet_id),
            }
        }
    }

    /// Hello world blinky
    ///
    /// Blinks the blue LED on the Nucleo board to indicate that the program is
    /// running
    #[task(priority = 0)]
    async fn blinky(_cx: blinky::Context, mut led: Pin<'B', 7, Output>) {
        loop {
            Systick::delay(500u64.millis()).await;
            led.set_high();
            Systick::delay(500u64.millis()).await;
            led.set_low();
        }
    }

    /// Listen for packets on the event udp socket
    #[task(shared = [net, ptp_port], priority = 1)]
    async fn event_listen(mut cx: event_listen::Context) {
        let socket = cx.shared.ptp_port.lock(|ptp_port| ptp_port.event_socket());

        listen_and_handle::<true>(&mut cx.shared.net, socket, &mut cx.shared.ptp_port).await
    }

    /// Listen for packets on the general udp socket
    #[task(shared = [net, ptp_port], priority = 0)]
    async fn general_listen(mut cx: general_listen::Context) {
        let socket = cx
            .shared
            .ptp_port
            .lock(|ptp_port| ptp_port.general_socket());

        listen_and_handle::<false>(&mut cx.shared.net, socket, &mut cx.shared.ptp_port).await
    }

    /// Listen for packets on the given socket
    ///
    /// The handling for both event and general sockets is basically the
    /// same and only differs in which `handle_*` function needs to be
    /// called.
    async fn listen_and_handle<const IS_EVENT: bool>(
        net: &mut impl Mutex<T = NetworkStack>,
        socket: SocketHandle,
        port: &mut impl Mutex<T = port::Port>,
    ) {
        // Get a local buffer to store the received packet
        // This is needed because we want to send and receive on the same socket at the
        // same time which both requires a `&mut` to the socket.
        let mut buffer = [0u8; 1500];
        loop {
            // Receive the next packet into the buffer
            let (len, timestamp) = match recv_slice(net, socket, &mut buffer).await {
                Ok(ok) => ok,
                Err(e) => {
                    defmt::error!("Failed to receive a packet because: {}", e);
                    continue;
                }
            };
            let data = &buffer[..len];

            // Inform statime about the new packet
            port.lock(|port| {
                if IS_EVENT {
                    port.handle_event_receive(data, stm_time_to_statime(timestamp), net);
                } else {
                    port.handle_general_receive(data, net);
                };
            });
        }
    }

    /// Poll smoltcp
    ///
    /// Smoltcp needs to be regularly polled to handle its state machines
    /// So we poll it after the delay it indicates.
    #[task(shared = [net], priority = 0)]
    async fn poll_smoltcp(mut cx: poll_smoltcp::Context) {
        loop {
            // Let smoltcp handle its things
            let delay_millis = cx
                .shared
                .net
                .lock(|net| {
                    net.poll();
                    net.poll_delay().map(|d| d.total_millis())
                })
                .unwrap_or(50);

            // TODO this could wait longer if we were notified about any other calls to
            // poll, would be an optimization for later to go to sleep longer
            Systick::delay(delay_millis.millis()).await;
        }
    }

    /// Handle the interrupt of the ethernet peripheral
    #[task(binds = ETH, shared = [net, tx_waker], priority = 2)]
    fn eth_interrupt(mut cx: eth_interrupt::Context) {
        let reason = stm32_eth::eth_interrupt_handler();

        // Receiving a tx event wakes the task waiting for tx timestamps
        if reason.tx {
            cx.shared.tx_waker.lock(|tx_waker| tx_waker.wake());
        }

        // Let smoltcp handle any new packets
        cx.shared.net.lock(|net| {
            net.poll();
        });
    }

    /// Run a DHCP client to dynamically acquire an IP address
    #[task(shared = [net], priority = 0)]
    async fn dhcp(mut cx: dhcp::Context, dhcp_handle: SocketHandle) {
        loop {
            core::future::poll_fn(|ctx| {
                cx.shared.net.lock(|net| {
                    let dhcp_socket = net.sockets.get_mut::<dhcpv4::Socket>(dhcp_handle);
                    dhcp_socket.register_waker(ctx.waker());

                    match dhcp_socket.poll() {
                        Some(dhcpv4::Event::Deconfigured) => {
                            defmt::warn!("DHCP got deconfigured");
                            net.iface.update_ip_addrs(|addrs| {
                                let dest = unwrap!(addrs.iter_mut().next());
                                *dest = IpCidr::Ipv4(Ipv4Cidr::new(Ipv4Address::UNSPECIFIED, 0));
                            });
                            net.iface.routes_mut().remove_default_ipv4_route();
                            Poll::Pending
                        }
                        Some(dhcpv4::Event::Configured(config)) => {
                            defmt::debug!("DHCP config acquired!");

                            defmt::debug!("IP address:      {}", config.address);
                            net.iface.update_ip_addrs(|addrs| {
                                let dest = unwrap!(addrs.iter_mut().next());
                                *dest = IpCidr::Ipv4(config.address);
                            });
                            if let Some(router) = config.router {
                                defmt::debug!("Default gateway: {}", router);
                                unwrap!(net.iface.routes_mut().add_default_ipv4_route(router));
                            } else {
                                defmt::debug!("Default gateway: None");
                                net.iface.routes_mut().remove_default_ipv4_route();
                            }

                            for (i, s) in config.dns_servers.iter().enumerate() {
                                defmt::debug!("DNS server {}:    {}", i, s);
                            }
                            Poll::Ready(())
                        }
                        None => Poll::Pending,
                    }
                })
            })
            .await;
        }
    }
}
