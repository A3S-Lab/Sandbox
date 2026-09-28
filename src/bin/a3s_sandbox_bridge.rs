//! `a3s-sandbox-bridge` — machine protocol bridge for non-Rust hosts.
//!
//! Speaks newline-delimited JSON over stdin/stdout so a Go (or other) SDK can
//! drive the native sandbox without cgo. The bridge process owns the sandbox:
//! when it exits — graceful EOF, `shutdown`, or crash — every sandboxed
//! process tree dies with it via the crate's process-group guards.
//!
//! Protocol v1 (one JSON object per line):
//!
//!   request  {"id": 1, "method": "initialize", "params": {"workspace": "/abs"}}
//!   response {"id": 1, "ok": true, "result": {...}}
//!   response {"id": 1, "ok": false, "error": {"code": "...", "message": "..."}}
//!   event    {"event": "output", "id": 2, "delta": "..."}
//!   event    {"event": "output_complete", "id": 2, "summary": {...}}
//!
//! Methods: `initialize`, `probe`, `capabilities`, `exec`, `ping`, `shutdown`.
//! A malformed line is a protocol violation: the bridge emits an error and
//! exits non-zero (fail closed — a desynchronized stream must not be guessed
//! at).

use a3s_sandbox::{CommandOutput, CommandRequest, NativeSandbox, OutputObserver, OutputSummary};
use anyhow::{anyhow, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;

const DEFAULT_TIMEOUT_MS: u64 = 120_000;

/// Streams output deltas from the sandbox into the protocol writer channel.
/// The backend trait does not distinguish stdout from stderr; deltas arrive
/// interleaved in the order the backend observed them.
struct BridgeObserver {
    tx: mpsc::UnboundedSender<String>,
    request_id: u64,
}

impl BridgeObserver {
    fn emit(&self, line: Value) {
        let _ = self.tx.send(line.to_string());
    }
}

#[async_trait::async_trait]
impl OutputObserver for BridgeObserver {
    async fn on_output_delta(&self, delta: &str) {
        self.emit(json!({"event": "output", "id": self.request_id, "delta": delta}));
    }

    async fn on_output_complete(&self, summary: &OutputSummary) {
        self.emit(json!({"event": "output_complete", "id": self.request_id, "summary": {
            "total_bytes": summary.total_bytes,
            "captured_bytes": summary.captured_bytes,
            "truncated": summary.truncated,
            "timed_out": summary.timed_out,
        }}));
    }
}

fn send(tx: &mpsc::UnboundedSender<String>, value: Value) {
    let _ = tx.send(value.to_string());
}

fn send_ok(tx: &mpsc::UnboundedSender<String>, id: u64, result: Value) {
    send(tx, json!({"id": id, "ok": true, "result": result}));
}

fn send_error(tx: &mpsc::UnboundedSender<String>, id: u64, code: &str, message: String) {
    send(tx, json!({"id": id, "ok": false, "error": {"code": code, "message": message}}));
}

fn sandbox_summary(sandbox: &NativeSandbox) -> Value {
    let report = sandbox.capability_report();
    let caps = report.capabilities;
    json!({
        "backend": report.backend,
        "session_id": sandbox.session_id(),
        "policy_digest": sandbox.policy_digest(),
        "unavailable": report.unavailable,
        "capabilities": {
            "filesystem_path_policy": caps.filesystem_path_policy,
            "filesystem_readonly_mounts": caps.filesystem_readonly_mounts,
            "filesystem_ephemeral_writes": caps.filesystem_ephemeral_writes,
            "network_deny_all": caps.network_deny_all,
            "mediated_http": caps.mediated_http,
            "mediated_socks": caps.mediated_socks,
            "unix_socket_allowlist": caps.unix_socket_allowlist,
            "resource_timeout": caps.resource_timeout,
            "resource_output_limit": caps.resource_output_limit,
            "resource_memory_limit": caps.resource_memory_limit,
            "resource_process_limit": caps.resource_process_limit,
            "resource_cpu_limit": caps.resource_cpu_limit,
        },
    })
}

fn handle_exec(
    sandbox: Arc<NativeSandbox>,
    tx: mpsc::UnboundedSender<String>,
    id: u64,
    params: &Value,
) -> Option<tokio::task::JoinHandle<()>> {
    let command = match params.get("command").and_then(Value::as_str) {
        Some(command) if !command.is_empty() => command.to_string(),
        _ => {
            send_error(&tx, id, "bad_request", "params.command must be a non-empty string".into());
            return None;
        }
    };
    let timeout_ms = params
        .get("timeout_ms")
        .and_then(Value::as_u64)
        .unwrap_or(DEFAULT_TIMEOUT_MS);
    let env: Option<Arc<HashMap<String, String>>> = params
        .get("env")
        .and_then(Value::as_object)
        .map(|map| {
            Arc::new(
                map.iter()
                    .filter_map(|(key, value)| value.as_str().map(|v| (key.clone(), v.to_string())))
                    .collect::<HashMap<String, String>>(),
            )
        });

    let observer: Arc<dyn OutputObserver> = Arc::new(BridgeObserver {
        tx: tx.clone(),
        request_id: id,
    });

    Some(tokio::spawn(async move {
        let request = CommandRequest {
            command,
            timeout_ms,
            output_observer: Some(observer),
            env,
        };
        match sandbox.execute(request).await {
            Ok(CommandOutput { stdout, stderr, exit_code, timed_out }) => {
                send(&tx, json!({"id": id, "ok": true, "result": {
                    "stdout": stdout,
                    "stderr": stderr,
                    "exit_code": exit_code,
                    "timed_out": timed_out,
                }}));
            }
            Err(error) => {
                send(&tx, json!({"id": id, "ok": false, "error": {
                    "code": "exec_failed",
                    "message": format!("{error:#}"),
                }}));
            }
        }
    }))
}

async fn run() -> Result<std::process::ExitCode> {
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    let writer = tokio::spawn(async move {
        let mut stdout = tokio::io::stdout();
        while let Some(line) = rx.recv().await {
            if stdout.write_all(line.as_bytes()).await.is_err() {
                break;
            }
            if stdout.write_all(b"\n").await.is_err() {
                break;
            }
            if stdout.flush().await.is_err() {
                break;
            }
        }
    });

    let mut state: Option<Arc<NativeSandbox>> = None;
    let mut running: HashMap<u64, tokio::task::JoinHandle<()>> = HashMap::new();
    let mut lines = BufReader::new(tokio::io::stdin()).lines();

    while let Ok(Some(line)) = lines.next_line().await {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let request: Value = match serde_json::from_str(trimmed) {
            Ok(value) => value,
            Err(error) => {
                send_error(&tx, 0, "bad_request", format!("malformed JSON line: {error}"));
                // A desynchronized stream cannot be trusted: fail closed.
                return Ok(std::process::ExitCode::from(1));
            }
        };

        let id = request.get("id").and_then(Value::as_u64).unwrap_or(0);
        let method = request.get("method").and_then(Value::as_str).unwrap_or("");
        let params = request.get("params").cloned().unwrap_or(Value::Null);

        match method {
            "initialize" => {
                let workspace = params
                    .get("workspace")
                    .and_then(Value::as_str)
                    .filter(|path| std::path::Path::new(path).is_absolute())
                    .ok_or_else(|| anyhow!("params.workspace must be an absolute path string"))?;
                match NativeSandbox::new(workspace) {
                    Ok(sandbox) => {
                        send_ok(&tx, id, sandbox_summary(&sandbox));
                        state = Some(Arc::new(sandbox));
                    }
                    Err(error) => {
                        send_error(&tx, id, "initialize_failed", format!("{error:#}"));
                    }
                }
            }
            "probe" => match state.as_ref() {
                Some(sandbox) => match sandbox.probe().await {
                    Ok(()) => send_ok(&tx, id, json!({"backend": sandbox.backend()})),
                    Err(error) => send_error(&tx, id, "probe_failed", format!("{error:#}")),
                },
                None => send_error(&tx, id, "not_initialized", "call initialize first".into()),
            },
            "capabilities" => match state.as_ref() {
                Some(sandbox) => send_ok(&tx, id, sandbox_summary(sandbox)),
                None => send_error(&tx, id, "not_initialized", "call initialize first".into()),
            },
            "exec" => match state.clone() {
                Some(sandbox) => {
                    if let Some(handle) = handle_exec(sandbox, tx.clone(), id, &params) {
                        running.insert(id, handle);
                    }
                }
                None => send_error(&tx, id, "not_initialized", "call initialize first".into()),
            },
            "ping" => send_ok(&tx, id, json!({"alive": true})),
            "shutdown" => {
                send_ok(&tx, id, json!({"bye": true}));
                break;
            }
            other => send_error(&tx, id, "unknown_method", format!("unknown method {other:?}")),
        }
    }

    // Fail every in-flight exec: aborting the task drops its future, which
    // drops the crate's ProcessGroupGuard and terminates the sandboxed tree.
    // Dropping `state` alone would not be enough — running tasks hold clones.
    for (_, handle) in running.drain() {
        handle.abort();
    }
    // Yield once so aborted tasks run their destructors before we exit.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    drop(state);
    drop(tx);
    let _ = writer.await;
    Ok(std::process::ExitCode::SUCCESS)
}

fn main() -> std::process::ExitCode {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let result = runtime.block_on(run());
    // Drop the runtime before returning: in-flight exec tasks are aborted and
    // their ProcessGroupGuard destructors terminate every sandboxed process
    // group. Never call process::exit here — it would skip those destructors.
    drop(runtime);
    match result {
        Ok(code) => code,
        Err(error) => {
            eprintln!("a3s-sandbox-bridge: {error:#}");
            std::process::ExitCode::from(1)
        }
    }
}
