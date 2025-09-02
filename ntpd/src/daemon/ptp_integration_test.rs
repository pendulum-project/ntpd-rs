#[cfg(test)]
mod tests {
    use std::{collections::HashMap, path::PathBuf, sync::{Arc, RwLock}, time::Duration};

    use ntp_proto::{
        AlgorithmConfig, KalmanClockController, NtpClock, NtpDuration, NtpLeapIndicator,
        NtpTimestamp, SourceConfig, SynchronizationConfig,
    };
    use tokio::sync::mpsc;

    use crate::daemon::{
        config::PtpSourceConfig,
        ntp_source::{MsgForSystem, SourceChannels},
        ptp_source::PtpSourceTask,
        spawn::{SourceId, ptp::PtpSpawner, Spawner},
        util::EPOCH_OFFSET,
    };

    #[derive(Debug, Clone, Default)]
    struct TestClock {}

    impl NtpClock for TestClock {
        type Error = std::time::SystemTimeError;

        fn now(&self) -> std::result::Result<NtpTimestamp, Self::Error> {
            let cur = std::time::SystemTime::now()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)?;

            Ok(NtpTimestamp::from_seconds_nanos_since_ntp_era(
                EPOCH_OFFSET.wrapping_add(cur.as_secs() as u32),
                cur.subsec_nanos(),
            ))
        }

        fn set_frequency(&self, _freq: f64) -> Result<NtpTimestamp, Self::Error> {
            self.now()
        }

        fn get_frequency(&self) -> Result<f64, Self::Error> {
            Ok(0.0)
        }

        fn step_clock(&self, _offset: NtpDuration) -> Result<NtpTimestamp, Self::Error> {
            panic!("Shouldn't be called by source");
        }

        fn disable_ntp_algorithm(&self) -> Result<(), Self::Error> {
            Ok(())
        }

        fn error_estimate_update(
            &self,
            _est_error: NtpDuration,
            _max_error: NtpDuration,
        ) -> Result<(), Self::Error> {
            panic!("Shouldn't be called by source");
        }

        fn status_update(&self, _leap_status: NtpLeapIndicator) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_ptp_spawner_integration() {
        // Test that PTP spawner properly creates spawn events
        let device_path = PathBuf::from("/dev/ptp0");
        let mut spawner = PtpSpawner::new(
            PtpSourceConfig {
                delay: 0.0,
                interval: ntp_proto::PollInterval::from_byte(0),
                path: device_path.clone(),
                precision: 1e-9,
                stratum: 0,
            },
            SourceConfig::default(),
        );

        let (action_tx, mut action_rx) = mpsc::channel(1);

        // Initially not complete
        assert!(!spawner.is_complete());

        // Try to spawn should succeed
        spawner.try_spawn(&action_tx).await.unwrap();

        // Should now be complete
        assert!(spawner.is_complete());

        // Should receive spawn event
        let event = action_rx.recv().await.unwrap();
        assert_eq!(event.id, spawner.get_id());

        // Verify spawn action contains correct parameters
        match event.action {
            crate::daemon::spawn::SpawnAction::Create(
                crate::daemon::spawn::SourceCreateParameters::Ptp(params)
            ) => {
                assert_eq!(params.path, device_path);
                assert_eq!(params.interval, ntp_proto::PollInterval::from_byte(0));
            }
            _ => panic!("Expected PTP source create parameters"),
        }
    }

    #[tokio::test]
    async fn test_ptp_source_message_passing() {
        // Test that PTP source properly handles system messages
        // Note: This test will fail if no PTP device is available, which is expected
        let (_system_update_sender, system_update_receiver) = tokio::sync::broadcast::channel(1);
        let (msg_for_system_sender, mut msg_for_system_receiver) = mpsc::channel(1);

        let index = SourceId::new();
        let clock = TestClock {};
        let mut system: ntp_proto::System<_, KalmanClockController<_, _>> =
            ntp_proto::System::new(
                clock.clone(),
                SynchronizationConfig::default(),
                AlgorithmConfig::default(),
                Arc::new([]),
            ).unwrap();

        let device_path = PathBuf::from("/dev/ptp0");

        // Create PTP source - this will likely fail due to no device, but that's expected
        let source = system.create_ptp_source(index, SourceConfig::default(), 1.0).unwrap();

        let handle = PtpSourceTask::spawn(
            index,
            device_path,
            ntp_proto::PollInterval::from_byte(0),
            clock,
            SourceChannels {
                msg_for_system_sender,
                system_update_receiver,
                source_snapshots: Arc::new(RwLock::new(HashMap::new())),
            },
            source,
            0,
            0.0,
        );

        // Should receive NetworkIssue message due to device unavailability
        let msg = tokio::time::timeout(Duration::from_millis(100), msg_for_system_receiver.recv())
            .await
            .unwrap()
            .unwrap();

        match msg {
            MsgForSystem::NetworkIssue(source_id) => {
                assert_eq!(source_id, index);
            }
            _ => panic!("Expected NetworkIssue message due to device unavailability"),
        }

        handle.abort();
    }
}
