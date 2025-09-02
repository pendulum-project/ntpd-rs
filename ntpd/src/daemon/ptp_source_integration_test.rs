#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::Duration;
    use tokio::sync::mpsc;
    use tokio::time::timeout;

    use ntp_proto::SourceConfig;
    use crate::daemon::{
        config::PtpSourceConfig,
        ntp_source::MsgForSystem,
        spawn::{
            SourceCreateParameters, SpawnAction, Spawner,
            ptp::PtpSpawner, SourceId, SourceRemovedEvent, SourceRemovalReason,
        },
        system::MESSAGE_BUFFER_SIZE,
    };

    #[tokio::test]
    async fn test_ptp_spawner_system_integration() {
        // Create a temporary path for testing
        let test_path = std::env::temp_dir().join("test_ptp_device");

        // Create PTP spawner
        let mut spawner = PtpSpawner::new(
            PtpSourceConfig {
                delay: 0.0,
                path: test_path.clone(),
                period: 1.0,
                precision: 1e-6,
                stratum: 0,
            },
            SourceConfig::default(),
        );

        let spawner_id = spawner.get_id();
        let (action_tx, mut action_rx) = mpsc::channel(MESSAGE_BUFFER_SIZE);

        // Test spawner creation
        assert!(!spawner.is_complete());
        assert_eq!(spawner.get_description(), "PTP");
        assert_eq!(spawner.get_addr_description(), test_path.display().to_string());

        // Test spawn action
        spawner.try_spawn(&action_tx).await.unwrap();
        assert!(spawner.is_complete());

        // Verify spawn event
        let spawn_event = action_rx.try_recv().unwrap();
        assert_eq!(spawn_event.id, spawner_id);

        let SpawnAction::Create(create_params) = spawn_event.action;
        let SourceCreateParameters::Ptp(ptp_params) = create_params else {
            panic!("Expected PTP source create parameters");
        };

        assert_eq!(ptp_params.path, test_path);
        assert_eq!(ptp_params.period, 1.0);
    }

    #[tokio::test]
    async fn test_ptp_spawner_source_removal_handling() {
        let test_path = std::env::temp_dir().join("test_ptp_device_removal");

        let mut spawner = PtpSpawner::new(
            PtpSourceConfig {
                delay: 0.0,
                path: test_path,
                period: 2.0,
                precision: 1e-6,
                stratum: 0,
            },
            SourceConfig::default(),
        );

        let (action_tx, mut action_rx) = mpsc::channel(MESSAGE_BUFFER_SIZE);

        // Spawn a source
        spawner.try_spawn(&action_tx).await.unwrap();
        assert!(spawner.is_complete());

        // Consume the spawn event
        let _spawn_event = action_rx.try_recv().unwrap();

        // Test network issue removal (should allow respawn)
        let source_id = SourceId::new();
        let removal_event = SourceRemovedEvent {
            id: source_id,
            reason: SourceRemovalReason::NetworkIssue,
        };

        spawner.handle_source_removed(removal_event).await.unwrap();
        assert!(!spawner.is_complete()); // Should be ready to respawn

        // Test demobilized removal (should not allow respawn)
        spawner.try_spawn(&action_tx).await.unwrap();
        assert!(spawner.is_complete());

        // Consume the second spawn event
        let _spawn_event2 = action_rx.try_recv().unwrap();

        let demobilized_event = SourceRemovedEvent {
            id: source_id,
            reason: SourceRemovalReason::Demobilized,
        };

        spawner.handle_source_removed(demobilized_event).await.unwrap();
        assert!(spawner.is_complete()); // Should remain complete
    }

    #[tokio::test]
    async fn test_ptp_message_passing_patterns() {
        // Test that PTP sources use the correct message types
        let (msg_tx, mut msg_rx) = mpsc::channel::<MsgForSystem<()>>(MESSAGE_BUFFER_SIZE);
        let source_id = SourceId::new();

        // Simulate OneWaySourceUpdate message (what PTP should send)
        let update = ntp_proto::OneWaySourceUpdate {
            snapshot: ntp_proto::OneWaySourceSnapshot {
                source_id: ntp_proto::ReferenceId::PTP,
                stratum: 0,
            },
            message: Some(()),
        };

        msg_tx.send(MsgForSystem::OneWaySourceUpdate(source_id, update)).await.unwrap();

        // Verify message was received correctly
        let received_msg = msg_rx.try_recv().unwrap();
        match received_msg {
            MsgForSystem::OneWaySourceUpdate(id, update) => {
                assert_eq!(id, source_id);
                assert_eq!(update.snapshot.source_id, ntp_proto::ReferenceId::PTP);
                assert_eq!(update.snapshot.stratum, 0);
            }
            _ => panic!("Expected OneWaySourceUpdate message"),
        }
    }

    #[tokio::test]
    async fn test_ptp_error_handling_patterns() {
        let (msg_tx, mut msg_rx) = mpsc::channel::<MsgForSystem<()>>(MESSAGE_BUFFER_SIZE);
        let source_id = SourceId::new();

        // Test NetworkIssue error pattern
        msg_tx.send(MsgForSystem::NetworkIssue(source_id)).await.unwrap();

        let received_msg = msg_rx.try_recv().unwrap();
        match received_msg {
            MsgForSystem::NetworkIssue(id) => {
                assert_eq!(id, source_id);
            }
            _ => panic!("Expected NetworkIssue message"),
        }

        // Test Unreachable error pattern
        msg_tx.send(MsgForSystem::Unreachable(source_id)).await.unwrap();

        let received_msg = msg_rx.try_recv().unwrap();
        match received_msg {
            MsgForSystem::Unreachable(id) => {
                assert_eq!(id, source_id);
            }
            _ => panic!("Expected Unreachable message"),
        }
    }

    #[tokio::test]
    async fn test_ptp_source_create_parameters() {
        let test_path = PathBuf::from("/dev/ptp0");
        let source_id = SourceId::new();
        let config = SourceConfig::default();
        let period = 0.5;

        let params = SourceCreateParameters::Ptp(crate::daemon::spawn::PtpSourceCreateParameters {
            id: source_id,
            path: test_path.clone(),
            config,
            period,
            stratum: 0,
            delay: 0.0,
        });

        // Test parameter accessors
        assert_eq!(params.get_id(), source_id);
        assert_eq!(params.get_addr(), test_path.display().to_string());

        // Test parameter extraction
        let SourceCreateParameters::Ptp(ptp_params) = params else {
            panic!("Expected PTP parameters");
        };

        assert_eq!(ptp_params.id, source_id);
        assert_eq!(ptp_params.path, test_path);
        assert_eq!(ptp_params.period, period);
    }

    #[tokio::test]
    async fn test_ptp_spawner_lifecycle() {
        let test_path = std::env::temp_dir().join("test_ptp_lifecycle");

        let mut spawner = PtpSpawner::new(
            PtpSourceConfig {
                delay: 0.0,
                path: test_path.clone(),
                period: 4.0,
                precision: 1e-9,
                stratum: 0,
            },
            SourceConfig::default(),
        );

        let (action_tx, mut action_rx) = mpsc::channel(MESSAGE_BUFFER_SIZE);

        // Initial state
        assert!(!spawner.is_complete());

        // Spawn source
        spawner.try_spawn(&action_tx).await.unwrap();
        assert!(spawner.is_complete());

        // Verify spawn event details
        let spawn_event = action_rx.try_recv().unwrap();
        let SpawnAction::Create(SourceCreateParameters::Ptp(params)) = spawn_event.action else {
            panic!("Expected PTP create parameters");
        };

        assert_eq!(params.path, test_path);
        assert_eq!(params.period, 4.0);

        // Test that spawner doesn't spawn again when complete
        let result = timeout(Duration::from_millis(100), action_rx.recv()).await;
        assert!(result.is_err()); // Should timeout since no new spawn events

        // Test source removal and respawn capability
        let removal_event = SourceRemovedEvent {
            id: params.id,
            reason: SourceRemovalReason::NetworkIssue,
        };

        spawner.handle_source_removed(removal_event).await.unwrap();
        assert!(!spawner.is_complete());

        // Should be able to spawn again
        spawner.try_spawn(&action_tx).await.unwrap();
        assert!(spawner.is_complete());

        // Verify second spawn event
        let second_spawn_event = action_rx.try_recv().unwrap();
        assert!(matches!(second_spawn_event.action, SpawnAction::Create(SourceCreateParameters::Ptp(_))));
    }
}
