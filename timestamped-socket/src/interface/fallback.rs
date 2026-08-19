use super::InterfaceName;

struct Private;

/// A detector for changes to which network interfaces are available on the system.
pub struct ChangeDetector {
    _private: Private,
}

impl ChangeDetector {
    /// Create a new detector for changes to which network interfaces are available on the system.
    ///
    /// # Errors
    /// May fail if the system does not allow a new change detector to be created.
    pub fn new() -> std::io::Result<Self> {
        Ok(Self { _private: Private })
    }

    /// Wait for a change to which network interfaces are present.
    pub async fn wait_for_change(&mut self) {
        // No platform independent way, but checking every so often is fine for a fallback
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
    }
}

/// Get the hardware clock index associated with the given interface.
#[must_use]
pub fn lookup_phc(_interface: InterfaceName) -> Option<u32> {
    None
}
