use timestamped_socket::interface::ChangeDetector;

#[tokio::main]
async fn main() {
    let mut detector = ChangeDetector::new().unwrap();

    loop {
        detector.wait_for_change().await;
        println!("Change detected");
    }
}
