#![cfg(all(test, target_os = "linux"))]

use a3s_sandbox::{posix_shell_single_quote, CommandRequest, NativeSandbox};
use std::path::PathBuf;
use std::time::Duration;

struct DetachedTree {
    workspace: tempfile::TempDir,
    marker: String,
    namespace: Option<PathBuf>,
}

impl DetachedTree {
    fn new() -> Self {
        let workspace = tempfile::tempdir().unwrap();
        let marker = format!(
            "a3s-lifetime-{}-{}",
            std::process::id(),
            workspace.path().file_name().unwrap().to_string_lossy()
        );
        Self {
            workspace,
            marker,
            namespace: None,
        }
    }

    fn command(&self) -> String {
        format!(
            "setsid /bin/sh -c '(sleep 20; printf leaked > late) & printf ready > ready; wait' {} & while [ ! -f release ]; do sleep 0.01; done",
            posix_shell_single_quote(&self.marker)
        )
    }

    async fn observe_detached_namespace(&mut self) {
        let namespace = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if self.workspace.path().join("ready").exists() {
                    for entry in std::fs::read_dir("/proc").unwrap().flatten() {
                        let command =
                            std::fs::read(entry.path().join("cmdline")).unwrap_or_default();
                        if command
                            .split(|byte| *byte == 0)
                            .any(|arg| arg == self.marker.as_bytes())
                        {
                            if let Ok(namespace) = std::fs::read_link(entry.path().join("ns/pid")) {
                                return namespace;
                            }
                        }
                    }
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("detached process must become observable before termination");
        assert_ne!(namespace, std::fs::read_link("/proc/self/ns/pid").unwrap());
        self.namespace = Some(namespace);
    }

    fn members(&self) -> Vec<u32> {
        let Some(namespace) = &self.namespace else {
            return Vec::new();
        };
        std::fs::read_dir("/proc")
            .unwrap()
            .flatten()
            .filter_map(|entry| {
                let pid = entry.file_name().to_string_lossy().parse::<u32>().ok()?;
                (std::fs::read_link(entry.path().join("ns/pid"))
                    .ok()
                    .as_ref()
                    == Some(namespace))
                .then_some(pid)
            })
            .collect()
    }

    async fn assert_settled(&self) {
        tokio::time::timeout(Duration::from_secs(1), async {
            while !self.members().is_empty() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("namespace still contains processes: {:?}", self.members()));
        assert!(!self.workspace.path().join("late").exists());
    }
}

impl Drop for DetachedTree {
    fn drop(&mut self) {
        for pid in self.members() {
            unsafe {
                libc::kill(pid as i32, libc::SIGKILL);
            }
        }
    }
}

#[tokio::test]
async fn detached_namespace_descendants_stop_on_return_timeout_and_cancellation() {
    for mode in ["return", "timeout", "cancel"] {
        let mut tree = DetachedTree::new();
        let sandbox = NativeSandbox::new(tree.workspace.path()).unwrap();
        let command = tree.command();
        let caller = tokio::spawn(async move {
            sandbox
                .execute(CommandRequest {
                    command,
                    timeout_ms: if mode == "timeout" { 2_500 } else { 10_000 },
                    output_observer: None,
                    env: None,
                })
                .await
        });
        tree.observe_detached_namespace().await;
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
        tree.assert_settled().await;
    }
}

#[tokio::test]
async fn killing_the_host_stops_the_detached_pid_namespace_without_rust_cleanup() {
    let mut tree = DetachedTree::new();
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
    tree.observe_detached_namespace().await;
    assert!(owner.try_wait().unwrap().is_none());
    owner.start_kill().unwrap();
    let status = tokio::time::timeout(Duration::from_secs(1), owner.wait())
        .await
        .unwrap()
        .unwrap();
    assert!(!status.success());
    tree.assert_settled().await;
}
