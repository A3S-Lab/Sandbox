//! Gate 6 CLI integration: probe / digest / capabilities reproduction.

use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_a3s-sandbox")
}

#[test]
fn cli_digest_prints_stable_hex() {
    let workspace = tempfile::tempdir().unwrap();
    let output = Command::new(bin())
        .args(["digest", "--workspace", workspace.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let digest = String::from_utf8_lossy(&output.stdout).trim().to_string();
    assert_eq!(digest.len(), 64);
    assert!(digest.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn cli_capabilities_emits_backend_and_unavailable() {
    let workspace = tempfile::tempdir().unwrap();
    let output = Command::new(bin())
        .args([
            "capabilities",
            "--workspace",
            workspace.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(json["backend"].as_str().is_some());
    assert!(json["capabilities"]["network_deny_all"].as_bool().unwrap());
    assert!(json["unavailable"].is_array());
}

#[test]
fn cli_exec_runs_command_in_sandbox() {
    let workspace = tempfile::tempdir().unwrap();
    #[cfg(windows)]
    let command_args = [
        "exec",
        "--workspace",
        workspace.path().to_str().unwrap(),
        "--",
        "Write-Output",
        "gate6-cli-ok",
    ];
    #[cfg(not(windows))]
    let command_args = [
        "exec",
        "--workspace",
        workspace.path().to_str().unwrap(),
        "--",
        "printf",
        "%s",
        "gate6-cli-ok",
    ];
    let output = Command::new(bin()).args(command_args).output().unwrap();
    assert!(
        output.status.success(),
        "stderr={} stdout={}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("gate6-cli-ok"));
}
