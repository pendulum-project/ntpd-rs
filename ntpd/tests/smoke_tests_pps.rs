use tokio::runtime::Runtime;
use ntp_proto::{NtpClock, NtpTimestamp};
use ntpd_rs::daemon::{ntp_source::{PpsSourceTask, MsgForSystem, SourceChannels}, config::TimestampMode, spawn::SourceId};
use tokio::time::{sleep, Duration};
use tracing::info;
use std::os::unix::io::RawFd;
use tokio::sync::mpsc;
use std::pin::Pin;


// Mock Clock implementation
struct MockClock;

impl NtpClock for MockClock {
    fn now(&self) -> Result<NtpTimestamp, Box<dyn std::error::Error>> {
        Ok(NtpTimestamp::from_fixed_int(0))
    }
}

// Mock Wait implementation 
struct MockWait {
    duration: Duration,
}

impl Future for MockWait {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Self::Output> {
        if self.duration.as_secs() == 0 {
            std::task::Poll::Ready(())
        } else {
            cx.waker().wake_by_ref();
            std::task::Poll::Pending
        }
    }
}

impl Wait for MockWait {
    fn reset(self: Pin<&mut Self>, deadline: Instant) {
        let mut_self = self.get_mut();
        mut_self.duration = deadline.duration_since(Instant::now());
    }
}

async fn mock_source_channels() -> SourceChannels {
    let (msg_for_system_sender, msg_for_system_receiver) = mpsc::channel(10);
    SourceChannels {
        msg_for_system_sender,
        msg_for_system_receiver,
    }
}

#[tokio::test]
async fn test_pps_source_task() {
    let clock = MockClock;
    let channels = mock_source_channels().await;
    //Create a temporary file to get a valid file descriptor
    let temp_file = tempfile().unwrap();
    let pps_fd = temp_file.as_raw_fd();    
    
    let index = SourceId::default();

    let handle = PpsSourceTask::spawn(index, clock, TimestampMode::default(), channels);

    // Simulate waiting for some time to allow the task to run
    sleep(Duration::from_secs(1)).await;

    // Retrieve the messages sent to the system
    let mut receiver = channels.msg_for_system_receiver;

    // Simulate a PPS signal
    let _ = receiver.recv().await;

    // Ensure that the task has processed the PPS signal
    assert!(receiver.try_recv().is_ok());

    // Check that an appropriate message has been sent to the system
    if let Some(msg) = receiver.recv().await {
        match msg {
            MsgForSystem::PpsSourceUpdate(source_id, _update) => {
                assert_eq!(source_id, index);
            }
            _ => panic!("Expected PpsSourceUpdate message"),
        }
    } else {
        panic!("Expected a message from PpsSourceTask");
    }

    // Ensure the task is stopped after the test
    handle.abort();
    handle.await.unwrap_err();
}

#[tokio::test]
async fn test_pps_source_task_with_timer() {
    let clock = MockClock;
    let channels = mock_source_channels().await;
    // Create a temporary file to get a valid file descriptor
    let temp_file = tempfile().unwrap();
    let pps_fd = temp_file.as_raw_fd();
    let index = SourceId::default();

    let handle = PpsSourceTask::spawn(index, clock, TimestampMode::default(), channels);

    // Simulate waiting for some time to allow the task to run
    sleep(Duration::from_secs(2)).await;

    // Add your assertions here
    // Check that certain messages are sent to the system
    // Verify that the PPS signals are being processed correctly

    // Retrieve the messages sent to the system
    let mut receiver = channels.msg_for_system_receiver;

    // Simulate a timer event
    let _ = receiver.recv().await;

    // Ensure that the task has processed the timer event
    assert!(receiver.try_recv().is_ok());

    // Check that an appropriate message has been sent to the system
    if let Some(msg) = receiver.recv().await {
        match msg {
            MsgForSystem::PpsSourceUpdate(source_id, _update) => {
                assert_eq!(source_id, index);
            }
            _ => panic!("Expected PpsSourceUpdate message"),
        }
    } else {
        panic!("Expected a message from PpsSourceTask");
    }

    // Ensure the task is stopped after the test
    handle.abort();
    handle.await.unwrap_err();
}
