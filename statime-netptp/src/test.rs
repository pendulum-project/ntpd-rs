use std::net::{Ipv4Addr, Ipv6Addr};

use crate::NetworkManager;

#[tokio::test]
async fn test_ipv4() {
    let manager = NetworkManager::<Ipv4Addr>::new().unwrap();
    let general = manager.open_general();
    let mut socket = general.listen_socket();

    socket
        .send_general(&[1, 2, 3, 4], None, Ipv4Addr::LOCALHOST)
        .await
        .unwrap();
    let result = socket.recv().await.unwrap();
    assert_eq!(&*result.bytes_read, [1, 2, 3, 4].as_slice());

    let ts = socket
        .send_event(&[5, 6, 7, 8], None, Ipv4Addr::LOCALHOST)
        .await
        .unwrap();
    assert!(ts.is_some());
    let result = socket.recv().await.unwrap();
    assert_eq!(&*result.bytes_read, [5, 6, 7, 8].as_slice());
    assert!(result.timestamp.is_some());
}

#[tokio::test]
async fn test_ipv6() {
    let manager = NetworkManager::<Ipv6Addr>::new().unwrap();
    let general = manager.open_general();
    let mut socket = general.listen_socket();

    socket
        .send_general(&[1, 2, 3, 4], None, Ipv6Addr::LOCALHOST)
        .await
        .unwrap();
    let result = socket.recv().await.unwrap();
    assert_eq!(&*result.bytes_read, [1, 2, 3, 4].as_slice());

    let ts = socket
        .send_event(&[5, 6, 7, 8], None, Ipv6Addr::LOCALHOST)
        .await
        .unwrap();
    assert!(ts.is_some());
    let result = socket.recv().await.unwrap();
    assert_eq!(&*result.bytes_read, [5, 6, 7, 8].as_slice());
    assert!(result.timestamp.is_some());
}
