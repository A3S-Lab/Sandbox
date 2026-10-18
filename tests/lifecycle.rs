#![cfg(test)]

use a3s_sandbox::{CommandRequest, ExecutionFailure, NativeSandbox, OutputObserver, OutputSummary};
use async_trait::async_trait;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;

struct HangingCompletion;

#[async_trait]
impl OutputObserver for HangingCompletion {
    async fn on_output_delta(&self, _delta: &str) {}

    async fn on_output_complete(&self, _summary: &OutputSummary) {
        std::future::pending::<()>().await;
    }
}

#[tokio::test]
async fn completed_command_preserves_observer_failure_as_a_typed_non_replayable_error() {
    let workspace = tempfile::tempdir().unwrap();
    let sandbox = NativeSandbox::new(workspace.path()).unwrap();
    let result = tokio::time::timeout(
        Duration::from_secs(45),
        sandbox.execute(CommandRequest {
            command: if cfg!(windows) {
                "[IO.File]::WriteAllText('executed', 'done')"
            } else {
                "printf done > executed"
            }
            .into(),
            timeout_ms: 30_000,
            output_observer: Some(Arc::new(HangingCompletion)),
            env: None,
        }),
    )
    .await
    .expect("observer must not keep an executed command pending");
    assert_eq!(
        std::fs::read(workspace.path().join("executed")).unwrap(),
        b"done"
    );
    let error = result.unwrap_err();
    assert!(error
        .chain()
        .any(|cause| cause.downcast_ref::<ExecutionFailure>()
            == Some(&ExecutionFailure::ObserverTimeout)));
}

struct HangingDelta {
    started: Notify,
}

#[async_trait]
impl OutputObserver for HangingDelta {
    async fn on_output_delta(&self, _delta: &str) {
        self.started.notify_one();
        std::future::pending::<()>().await;
    }
}

#[tokio::test]
async fn dropping_the_caller_still_stops_a_command_blocked_in_its_observer() {
    let workspace = tempfile::tempdir().unwrap();
    let sandbox = NativeSandbox::new(workspace.path()).unwrap();
    let observer = Arc::new(HangingDelta {
        started: Notify::new(),
    });
    let output_observer = observer.clone();
    let caller = tokio::spawn(async move {
        sandbox
            .execute(CommandRequest {
                command: if cfg!(windows) {
                    "Write-Output ready; Start-Sleep -Seconds 4; [IO.File]::WriteAllText('late', 'leaked')"
                } else {
                    "printf ready; sleep 0.5; printf leaked > late"
                }.into(),
                timeout_ms: 30_000,
                output_observer: Some(output_observer),
                env: None,
            })
            .await
    });
    tokio::time::timeout(Duration::from_secs(45), observer.started.notified())
        .await
        .expect("command readiness was not observed");
    caller.abort();
    assert!(caller.await.unwrap_err().is_cancelled());
    tokio::time::sleep(Duration::from_secs(if cfg!(windows) { 5 } else { 1 })).await;
    assert!(
        !workspace.path().join("late").exists(),
        "cancelled command wrote after return"
    );
}

#[test]
fn execution_failure_codes_are_closed_and_stable() {
    for (code, reason) in [
        ("command_cancelled", ExecutionFailure::Cancelled),
        (
            "command_settlement_unknown",
            ExecutionFailure::SettlementUnknown,
        ),
        (
            "command_observer_timeout",
            ExecutionFailure::ObserverTimeout,
        ),
    ] {
        assert_eq!(ExecutionFailure::parse(code).unwrap(), reason);
        assert_eq!(reason.as_str(), code);
    }
    assert!(ExecutionFailure::parse("success").is_err());
}

#[tokio::test]
async fn command_deadline_bounds_a_delta_observer_that_never_returns() {
    let workspace = tempfile::tempdir().unwrap();
    let sandbox = NativeSandbox::new(workspace.path()).unwrap();
    let result = tokio::time::timeout(
        Duration::from_secs(45),
        sandbox.execute(CommandRequest {
            command: if cfg!(windows) {
                "Write-Output ready; Start-Sleep -Seconds 60"
            } else {
                "printf ready; sleep 60"
            }
            .into(),
            timeout_ms: if cfg!(windows) { 15_000 } else { 500 },
            output_observer: Some(Arc::new(HangingDelta {
                started: Notify::new(),
            })),
            env: None,
        }),
    )
    .await
    .expect("output callbacks must not bypass the command deadline")
    .unwrap();
    assert!(result.timed_out);
    assert_ne!(result.exit_code, 0);
}
