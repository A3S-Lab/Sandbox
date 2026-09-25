//! Gate 2 integration: policy resource budgets on live execute.

use crate::observability::ReasonCode;
use crate::{CommandRequest, NativeSandbox, OutputObserver, OutputSummary, SandboxPolicy};
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Default)]
struct RecordingObserver {
    summary: Mutex<Option<OutputSummary>>,
}

#[async_trait]
impl OutputObserver for RecordingObserver {
    async fn on_output_delta(&self, _delta: &str) {}

    async fn on_output_complete(&self, summary: &OutputSummary) {
        *self.summary.lock().await = Some(*summary);
    }
}

#[tokio::test]
async fn gate2_policy_output_ceiling_truncates_capture() {
    let workspace = tempfile::tempdir().unwrap();
    let mut policy = SandboxPolicy::a3s_bash_baseline();
    policy.resources.max_output_bytes = 4_096;
    let sandbox = NativeSandbox::with_policy(workspace.path(), policy).unwrap();
    let observer = Arc::new(RecordingObserver::default());

    #[cfg(not(windows))]
    let command = "dd if=/dev/zero bs=20000 count=1 2>/dev/null | tr '\\0' x";
    #[cfg(windows)]
    let command = "[Console]::Out.Write([string]::new('x', 20000))";

    let output = sandbox
        .execute(CommandRequest {
            command: command.into(),
            timeout_ms: 30_000,
            output_observer: Some(observer.clone()),
            env: None,
        })
        .await
        .unwrap();

    let summary = observer
        .summary
        .lock()
        .await
        .expect("observer completion callback was not invoked");
    assert!(summary.total_bytes >= 20_000, "{summary:?}");
    assert_eq!(summary.captured_bytes, 4_096);
    assert!(summary.truncated);
    assert!(output.stdout.contains("truncated") || output.stderr.contains("truncated"));
}

#[tokio::test]
async fn gate2_policy_timeout_ceiling_caps_request() {
    let workspace = tempfile::tempdir().unwrap();
    let mut policy = SandboxPolicy::a3s_bash_baseline();
    policy.resources.timeout_ms = 200;
    let sandbox = NativeSandbox::with_policy(workspace.path(), policy).unwrap();

    #[cfg(not(windows))]
    let command = "sleep 5";
    #[cfg(windows)]
    let command = "Start-Sleep -Seconds 5";

    let output = sandbox
        .execute(CommandRequest {
            command: command.into(),
            timeout_ms: 30_000,
            output_observer: None,
            env: None,
        })
        .await
        .unwrap();
    assert!(output.timed_out, "expected timeout under policy ceiling");

    let events = sandbox.audit_log().snapshot();
    assert!(events
        .iter()
        .any(|event| event.reason_code == ReasonCode::Timeout));
}

#[cfg(any(target_os = "linux", windows))]
#[tokio::test]
async fn gate2_memory_ceiling_stops_overallocation() {
    let workspace = tempfile::tempdir().unwrap();
    let mut policy = SandboxPolicy::a3s_bash_baseline();
    // Keep enough headroom for launcher + shell, but far below the allocation.
    policy.resources.max_memory_bytes = Some(64 * 1024 * 1024);
    let sandbox = NativeSandbox::with_policy(workspace.path(), policy).unwrap();

    #[cfg(target_os = "linux")]
    let command = "perl -e 'my $x = \"x\" x (256 * 1024 * 1024); print length($x)'";
    #[cfg(windows)]
    let command = "$buf = New-Object byte[] (256MB); Write-Output $buf.Length";

    let output = sandbox
        .execute(CommandRequest {
            command: command.into(),
            timeout_ms: 30_000,
            output_observer: None,
            env: None,
        })
        .await
        .unwrap();

    // Over-allocation must not succeed as a clean large print.
    let combined = format!("{}{}", output.stdout, output.stderr);
    assert!(
        output.exit_code != 0 || output.timed_out || !combined.contains("268435456"),
        "memory ceiling should prevent successful 256MiB allocation; stdout={} stderr={} exit={}",
        output.stdout,
        output.stderr,
        output.exit_code
    );
}

#[cfg(target_os = "macos")]
#[test]
fn gate2_macos_memory_limit_fails_closed_at_policy() {
    let workspace = tempfile::tempdir().unwrap();
    let mut policy = SandboxPolicy::a3s_bash_baseline();
    policy.resources.max_memory_bytes = Some(64 * 1024 * 1024);
    let error = format!(
        "{:#}",
        NativeSandbox::with_policy(workspace.path(), policy).unwrap_err()
    );
    assert!(
        error.contains("memory limit"),
        "macOS must fail closed instead of claiming unenforceable RLIMIT_AS: {error}"
    );
}

#[cfg(windows)]
#[tokio::test]
async fn gate2_windows_process_limit_blocks_extra_children() {
    let workspace = tempfile::tempdir().unwrap();
    let mut policy = SandboxPolicy::a3s_bash_baseline();
    // Job ACTIVE_PROCESS counts the whole tree; keep it tight.
    policy.resources.max_processes = Some(2);
    let sandbox = NativeSandbox::with_policy(workspace.path(), policy).unwrap();

    let output = sandbox
        .execute(CommandRequest {
            command: "1..8 | ForEach-Object { Start-Process -NoNewWindow pwsh -ArgumentList '-NoProfile','-Command','Start-Sleep -Seconds 2' }; Start-Sleep -Seconds 1; Write-Output spawned"
                .into(),
            timeout_ms: 15_000,
            output_observer: None,
            env: None,
        })
        .await
        .unwrap();

    let stderr = output.stderr.to_ascii_lowercase();
    // The Job Object blocks the extra process. English reports "quota"; other
    // locales do not. A Start-Process error record is the same kernel effect.
    assert!(
        output.exit_code != 0
            || !output.stdout.contains("spawned")
            || stderr.contains("quota")
            || output.stderr.contains("Start-Process"),
        "Job process limit should prevent spawning many children; stdout={} stderr={}",
        output.stdout,
        output.stderr
    );
}

#[cfg(not(windows))]
#[tokio::test]
async fn gate2_unix_process_limit_fails_closed_at_policy() {
    // Gate 11: on Linux the refusal is probe-scoped — hosts with a
    // delegated cgroup subtree accept and enforce pids.max; every other
    // unix host refuses at construction. Windows enforces via Job Objects.
    let workspace = tempfile::tempdir().unwrap();
    let mut policy = SandboxPolicy::a3s_bash_baseline();
    policy.resources.max_processes = Some(8);
    match NativeSandbox::with_policy(workspace.path(), policy) {
        Ok(sandbox) => {
            assert!(
                sandbox.capabilities().resource_process_limit,
                "accepting a pids quota requires the capability"
            );
        }
        Err(error) => {
            let error = format!("{error:#}");
            assert!(
                error.contains("process limit"),
                "hosts without a cgroup fence must fail closed: {error}"
            );
        }
    }
}
