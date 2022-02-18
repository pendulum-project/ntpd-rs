pub mod bmca;
pub mod dataset_comparison;
pub mod foreign_master;

// TODO: Replace with the real port state implementation
pub enum PortState {
    Listening,
    Slave,
    Uncalibrated,
    Passive,
}
