#[tokio::main]
async fn main() -> ! {
    let result = nts_pool_ke::nts_pool_ke_main().await;
    std::process::exit(if result.is_ok() { 0 } else { 1 });
}
