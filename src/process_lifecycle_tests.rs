#![cfg(test)]

use super::*;
use crate::{ExecutionFailure, OutputObserver, OutputSummary};
use async_trait::async_trait;
use std::future::Future;
use std::task::Poll;
use std::time::Duration;

fn spawn_shell(workspace: &std::path::Path, script: &str) -> Child {
    let mut command = Command::new("/bin/sh");
    command
        .arg("-c")
        .arg(script)
        .current_dir(workspace)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    configure_process_group(&mut command);
    command.spawn().unwrap()
}

struct HangingCompletion;

#[async_trait]
impl OutputObserver for HangingCompletion {
    async fn on_output_delta(&self, _delta: &str) {}

    async fn on_output_complete(&self, _summary: &OutputSummary) {
        std::future::pending::<()>().await;
    }
}

#[tokio::test]
async fn completion_observer_cannot_hold_a_finished_command_forever() {
    let workspace = tempfile::tempdir().unwrap();
    let mut child = spawn_shell(workspace.path(), "printf done");
    let result = tokio::time::timeout(
        Duration::from_secs(2),
        read_process_output(&mut child, 100, MAX_OUTPUT_SIZE, Some(&HangingCompletion)),
    )
    .await
    .expect("a completion observer must not keep a finished command pending");
    let error = result.expect_err("an unfinished observer must be reported");
    assert_eq!(
        error.downcast_ref::<ExecutionFailure>(),
        Some(&ExecutionFailure::ObserverTimeout)
    );
}

#[tokio::test]
async fn root_exit_stops_background_work_before_waiting_for_pipe_eof() {
    let workspace = tempfile::tempdir().unwrap();
    let mut child = spawn_shell(
        workspace.path(),
        "(touch ready; sleep 2; touch late) & \
         while [ ! -f ready ]; do sleep 0.01; done; exit 0",
    );
    let output = tokio::time::timeout(
        Duration::from_secs(1),
        read_process_output(&mut child, 3_000, MAX_OUTPUT_SIZE, None),
    )
    .await
    .expect("a background process holding stdout must not delay root completion")
    .unwrap();
    assert!(workspace.path().join("ready").exists());
    assert_eq!(output.status.unwrap().code(), Some(0));
    assert!(!output.timed_out);
    assert!(!workspace.path().join("late").exists());
}

#[tokio::test(flavor = "current_thread")]
async fn cancellation_before_the_owner_is_polled_stops_the_process_group() {
    let workspace = tempfile::tempdir().unwrap();
    let script = "(touch ready; sleep 0.5; touch late) & while :; do sleep 0.01; done";
    let mut command = Command::new("/bin/sh");
    command.arg("-c").arg(script).current_dir(workspace.path());
    let request = CommandRequest {
        command: script.into(),
        timeout_ms: 2_000,
        output_observer: None,
        env: None,
    };
    let budget = crate::policy::ResolvedResourceBudget::resolve(
        &crate::policy::ResourceLimits::default(),
        request.timeout_ms,
    )
    .unwrap();
    let mut execution = Box::pin(run_tokio_command(
        command,
        request,
        &budget,
        "cancellation fixture",
    ));
    std::future::poll_fn(|context| {
        assert!(execution.as_mut().poll(context).is_pending());
        Poll::Ready(())
    })
    .await;

    // Keep the single-threaded owner unpolled while the real child starts.
    let ready_deadline = std::time::Instant::now() + Duration::from_secs(2);
    while !workspace.path().join("ready").exists() {
        assert!(
            std::time::Instant::now() < ready_deadline,
            "fixture did not start"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    drop(execution);
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(
        !workspace.path().join("late").exists(),
        "an unpolled owner left its descendant running"
    );
}
