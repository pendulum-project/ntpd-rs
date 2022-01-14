use std::{
    net::{SocketAddr, UdpSocket},
    sync::mpsc::channel,
    time::SystemTime,
};

fn main() {
    let (tx, rx) = channel::<(SocketAddr, Option<SystemTime>, Vec<u8>)>();
    let tx_319 = tx.clone();
    std::thread::spawn(move || {
        let socket = UdpSocket::bind("0.0.0.0:319").unwrap();
        socket
            .join_multicast_v4(&"224.0.1.129".parse().unwrap(), &"0.0.0.0".parse().unwrap())
            .unwrap();
        let mut buf = [0; 511];
        loop {
            let (amt, src) = socket.recv_from(&mut buf).unwrap();
            let ts = SystemTime::now();
            tx_319.send((src, Some(ts), buf[..amt].to_vec())).unwrap();
        }
    });
    let tx_320 = tx.clone();
    std::thread::spawn(move || {
        let socket = UdpSocket::bind("0.0.0.0:320").unwrap();
        socket
            .join_multicast_v4(&"224.0.1.129".parse().unwrap(), &"0.0.0.0".parse().unwrap())
            .unwrap();
        let mut buf = [0; 511];
        loop {
            let (amt, src) = socket.recv_from(&mut buf).unwrap();
            tx_320.send((src, None, buf[..amt].to_vec())).unwrap();
        }
    });

    loop {
        let (src, ts, data) = rx.recv().unwrap();
        if let Some(ts) = ts {
            println!("Received {:?} from {:?} at {:?}", data, src, ts);
        } else {
            println!("Received {:?} from {:?}", data, src);
        }
    }
}
