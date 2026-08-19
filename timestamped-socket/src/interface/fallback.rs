use super::InterfaceName;

struct Private;

pub struct ChangeDetector {
    _private: Private,
}

impl ChangeDetector {
    pub fn new() -> std::io::Result<Self> {
        Ok(Self { _private: Private })
    }

    pub async fn wait_for_change(&mut self) {
        // No platform independent way, but checking every so often is fine for a fallback
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
    }
}

pub fn lookup_phc(_interface: InterfaceName) -> Option<u32> {
    None
}
