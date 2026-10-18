#![cfg(all(test, windows))]

use a3s_sandbox::{windows_host_powershell, CommandRequest, NativeSandbox};
use base64::Engine;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::Path;
use std::time::Duration;
use windows_sys::Win32::Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows_sys::Win32::System::Threading::{
    OpenProcess, TerminateProcess, WaitForSingleObject, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE,
};

fn literal(path: &Path) -> String {
    format!("'{}'", path.to_string_lossy().replace('\'', "''"))
}

struct ProcessTree {
    workspace: tempfile::TempDir,
    processes: Vec<OwnedHandle>,
}

impl ProcessTree {
    fn new() -> Self {
        Self {
            workspace: tempfile::tempdir().unwrap(),
            processes: Vec::new(),
        }
    }

    fn command(&self) -> String {
        let child = format!(
            "[IO.File]::WriteAllText({}, [string]$PID); Start-Sleep -Seconds 120",
            literal(&self.workspace.path().join("child.pid"))
        );
        let encoded = base64::engine::general_purpose::STANDARD.encode(
            child
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>(),
        );
        format!(
            "[IO.File]::WriteAllText({}, [string]$PID); $child = Start-Process -FilePath {} -ArgumentList '-NoLogo','-NoProfile','-NonInteractive','-EncodedCommand','{}' -PassThru -NoNewWindow; while (-not (Test-Path -LiteralPath {})) {{ Start-Sleep -Milliseconds 20 }}",
            literal(&self.workspace.path().join("root.pid")),
            literal(&windows_host_powershell(self.workspace.path()).unwrap()),
            encoded,
            literal(&self.workspace.path().join("release")),
        )
    }

    async fn observe_ready_processes(&mut self) {
        tokio::time::timeout(Duration::from_secs(60), async {
            while self.processes.len() < 2 {
                let name = if self.processes.is_empty() {
                    "root.pid"
                } else {
                    "child.pid"
                };
                if let Some(pid) = std::fs::read_to_string(self.workspace.path().join(name))
                    .ok()
                    .and_then(|value| value.parse::<u32>().ok())
                {
                    let raw =
                        unsafe { OpenProcess(PROCESS_SYNCHRONIZE | PROCESS_TERMINATE, 0, pid) };
                    assert!(!raw.is_null(), "failed to observe live process {pid}");
                    let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
                    assert_eq!(
                        unsafe { WaitForSingleObject(handle.as_raw_handle(), 0) },
                        WAIT_TIMEOUT
                    );
                    self.processes.push(handle);
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("both root and descendant must execute before termination");
    }

    async fn assert_stopped(&self) {
        for process in &self.processes {
            tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    match unsafe { WaitForSingleObject(process.as_raw_handle(), 0) } {
                        WAIT_OBJECT_0 => break,
                        WAIT_TIMEOUT => tokio::time::sleep(Duration::from_millis(5)).await,
                        result => panic!("process wait failed: {result}"),
                    }
                }
            })
            .await
            .expect("a sandbox process survived termination");
        }
    }
}

impl Drop for ProcessTree {
    fn drop(&mut self) {
        for process in &self.processes {
            unsafe {
                TerminateProcess(process.as_raw_handle(), 1);
                WaitForSingleObject(process.as_raw_handle(), 500);
            }
        }
    }
}

#[tokio::test]
async fn job_descendants_stop_on_return_timeout_and_cancellation() {
    for mode in ["return", "timeout", "cancel"] {
        let mut tree = ProcessTree::new();
        let sandbox = NativeSandbox::new(tree.workspace.path()).unwrap();
        let command = tree.command();
        let caller = tokio::spawn(async move {
            sandbox
                .execute(CommandRequest {
                    command,
                    timeout_ms: if mode == "timeout" { 30_000 } else { 90_000 },
                    output_observer: None,
                    env: None,
                })
                .await
        });
        tree.observe_ready_processes().await;
        match mode {
            "return" => {
                std::fs::write(tree.workspace.path().join("release"), b"release").unwrap();
                let output = caller.await.unwrap().unwrap();
                assert_eq!(output.exit_code, 0, "{output:?}");
                assert!(!output.timed_out);
            }
            "timeout" => {
                let output = caller.await.unwrap().unwrap();
                assert!(output.timed_out);
                assert_ne!(output.exit_code, 0);
            }
            "cancel" => {
                caller.abort();
                assert!(caller.await.unwrap_err().is_cancelled());
            }
            _ => unreachable!(),
        }
        tree.assert_stopped().await;
    }
}

#[tokio::test]
async fn killing_the_host_stops_the_root_and_descendant_without_rust_cleanup() {
    let mut tree = ProcessTree::new();
    let mut owner = tokio::process::Command::new(env!("CARGO_BIN_EXE_a3s-sandbox"))
        .arg("exec")
        .arg("--workspace")
        .arg(tree.workspace.path())
        .arg("--")
        .arg(tree.command())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    tree.observe_ready_processes().await;
    assert!(owner.try_wait().unwrap().is_none());
    owner.start_kill().unwrap();
    let status = tokio::time::timeout(Duration::from_secs(2), owner.wait())
        .await
        .unwrap()
        .unwrap();
    assert!(!status.success());
    tree.assert_stopped().await;
}
