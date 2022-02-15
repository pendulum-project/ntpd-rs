use std::sync::mpsc;

use nix::sys::socket::{InetAddr, SockAddr};
use statime::{
    datastructures::common::ClockIdentity,
    network::linux::{get_clock_id, LinuxRuntime},
    port::Port,
};

fn main() {
    let (tx, rx) = mpsc::channel();
    let network_runtime = LinuxRuntime::new(tx);
    let identity = ClockIdentity(get_clock_id().expect("Could not get clock identity"));

    let mut port = Port::new(
        identity,
        0,
        0,
        0,
        network_runtime.clone(),
        SockAddr::Inet(InetAddr::new(
            nix::sys::socket::IpAddr::new_v4(0, 0, 0, 0),
            0,
        )),
    );

    loop {
        let packet = rx.recv().expect("Could not get further network packets");
        port.handle_network(packet);
        if let Some(data) = port.extract_measurement() {
            println!("Offset to master: {}", data);
        }
    }
}
