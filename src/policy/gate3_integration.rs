//! Gate 3: typed mounts and session write modes — unit + compile integration.

use crate::policy::{
    decide_read, decide_write, normalize_policy_path, AccessDecision, BackendCapabilities,
    EnforcedPolicy, FilesystemMount, MountMode, PathRule, SandboxPolicy, SessionWriteMode,
};
use crate::NativeSandbox;
use std::fs;

#[test]
fn gate3_ephemeral_session_fails_closed_without_overlay_capability() {
    let mut policy = SandboxPolicy::a3s_bash_baseline();
    policy.filesystem.session_write = SessionWriteMode::Ephemeral;
    let caps = BackendCapabilities {
        filesystem_ephemeral_writes: false,
        ..BackendCapabilities::native_gate2()
    };
    let error = policy.validate_for_backend(caps).unwrap_err().to_string();
    assert!(
        error.contains("ephemeral") || error.contains("overlay"),
        "{error}"
    );
}

#[test]
fn gate3_readonly_mount_outside_workspace_compiles_for_read_not_write() {
    let workspace = tempfile::tempdir().unwrap();
    let scratch = tempfile::tempdir().unwrap();
    let knowledge = tempfile::tempdir().unwrap();
    fs::write(knowledge.path().join("doc.txt"), "knowledge").unwrap();

    let mut policy = SandboxPolicy::a3s_bash_baseline();
    policy.filesystem.mounts.push(FilesystemMount {
        root: PathRule::Exact(knowledge.path().to_string_lossy().into_owned()),
        mode: MountMode::ReadOnly,
    });

    let enforced = EnforcedPolicy::compile(
        &policy,
        workspace.path(),
        scratch.path(),
        BackendCapabilities::native_gate2(),
    )
    .expect("compile RO mount");
    let knowledge_canon = knowledge.path().canonicalize().unwrap();
    assert!(
        enforced
            .allow_read
            .iter()
            .any(|path| path == &knowledge_canon),
        "RO mount must enter allow_read: {:?}",
        enforced.allow_read
    );
    assert!(
        !enforced
            .allow_write
            .iter()
            .any(|path| path == &knowledge_canon || knowledge_canon.starts_with(path)),
        "RO mount must not be writable via allow_write: {:?}",
        enforced.allow_write
    );
}

#[test]
fn gate3_readwrite_mount_outside_workspace_fails_closed() {
    let workspace = tempfile::tempdir().unwrap();
    let scratch = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();

    let mut policy = SandboxPolicy::a3s_bash_baseline();
    policy.filesystem.mounts.push(FilesystemMount {
        root: PathRule::Exact(outside.path().to_string_lossy().into_owned()),
        mode: MountMode::ReadWrite,
    });

    let error = format!(
        "{:#}",
        EnforcedPolicy::compile(
            &policy,
            workspace.path(),
            scratch.path(),
            BackendCapabilities::native_gate2(),
        )
        .unwrap_err()
    );
    assert!(
        error.contains("outside") || error.contains("ReadWrite") || error.contains("broaden"),
        "{error}"
    );
}

#[test]
fn gate3_readonly_mount_under_workspace_denies_writes() {
    let workspace = tempfile::tempdir().unwrap();
    let scratch = tempfile::tempdir().unwrap();
    let ro_dir = workspace.path().join("vendor-docs");
    fs::create_dir_all(&ro_dir).unwrap();
    fs::write(ro_dir.join("readme.md"), "ro").unwrap();

    let mut policy = SandboxPolicy::a3s_bash_baseline();
    policy.filesystem.mounts.push(FilesystemMount {
        root: PathRule::Exact("vendor-docs".into()),
        mode: MountMode::ReadOnly,
    });

    let enforced = EnforcedPolicy::compile(
        &policy,
        workspace.path(),
        scratch.path(),
        BackendCapabilities::native_gate2(),
    )
    .unwrap();
    let ro_canon = ro_dir.canonicalize().unwrap();
    assert!(enforced.deny_write.iter().any(|path| path == &ro_canon));
}

#[test]
fn gate3_document_decisions_treat_readonly_mount_as_readable() {
    let mut policy = SandboxPolicy::a3s_bash_baseline();
    policy.filesystem.mounts.push(FilesystemMount {
        root: PathRule::Exact("knowledge".into()),
        mode: MountMode::ReadOnly,
    });
    let path = normalize_policy_path("knowledge/doc.txt").unwrap();
    assert_eq!(decide_read(&policy, &path), AccessDecision::Allow);
    assert_eq!(decide_write(&policy, &path), AccessDecision::Deny);
}

#[tokio::test]
async fn gate3_native_sandbox_reads_readonly_mount_and_blocks_writes() {
    let workspace = tempfile::tempdir().unwrap();
    let knowledge = tempfile::tempdir().unwrap();
    fs::write(knowledge.path().join("doc.txt"), "gate3-knowledge").unwrap();

    let mut policy = SandboxPolicy::a3s_bash_baseline();
    policy.filesystem.mounts.push(FilesystemMount {
        root: PathRule::Exact(knowledge.path().to_string_lossy().into_owned()),
        mode: MountMode::ReadOnly,
    });
    let sandbox = NativeSandbox::with_policy(workspace.path(), policy).unwrap();

    #[cfg(not(windows))]
    let read_cmd = format!("cat '{}'", knowledge.path().join("doc.txt").display());
    #[cfg(windows)]
    let read_cmd = format!(
        "Get-Content -Raw '{}'",
        knowledge.path().join("doc.txt").display()
    );

    let output = sandbox
        .execute(crate::CommandRequest {
            command: read_cmd,
            timeout_ms: 30_000,
            output_observer: None,
            env: None,
        })
        .await
        .unwrap();
    assert!(
        output.stdout.contains("gate3-knowledge"),
        "stdout={} stderr={}",
        output.stdout,
        output.stderr
    );

    #[cfg(not(windows))]
    let write_cmd = format!(
        "echo mutated > '{}'",
        knowledge.path().join("doc.txt").display()
    );
    #[cfg(windows)]
    let write_cmd = format!(
        "Set-Content -Path '{}' -Value mutated",
        knowledge.path().join("doc.txt").display()
    );

    let write_output = sandbox
        .execute(crate::CommandRequest {
            command: write_cmd,
            timeout_ms: 30_000,
            output_observer: None,
            env: None,
        })
        .await
        .unwrap();
    assert_ne!(
        write_output.exit_code, 0,
        "RO mount writes must fail; stdout={} stderr={}",
        write_output.stdout, write_output.stderr
    );
    let contents = fs::read_to_string(knowledge.path().join("doc.txt")).unwrap();
    assert_eq!(contents, "gate3-knowledge");
}

#[cfg(target_os = "linux")]
#[test]
fn gate3_linux_ephemeral_is_accepted_by_policy() {
    let mut policy = SandboxPolicy::a3s_bash_baseline();
    policy.filesystem.session_write = SessionWriteMode::Ephemeral;
    policy
        .validate_for_backend(BackendCapabilities::native_gate2())
        .expect("Linux claims ephemeral via bwrap tmpfs");
    let workspace = tempfile::tempdir().unwrap();
    NativeSandbox::with_policy(workspace.path(), policy).unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn gate3_linux_ephemeral_compiles_session_write_mode() {
    let workspace = tempfile::tempdir().unwrap();
    let scratch = tempfile::tempdir().unwrap();
    let mut policy = SandboxPolicy::a3s_bash_baseline();
    policy.filesystem.session_write = SessionWriteMode::Ephemeral;
    let enforced = EnforcedPolicy::compile(
        &policy,
        workspace.path(),
        scratch.path(),
        BackendCapabilities::native_gate2(),
    )
    .unwrap();
    assert_eq!(enforced.session_write, SessionWriteMode::Ephemeral);
}

#[cfg(not(target_os = "linux"))]
#[test]
fn gate3_ephemeral_rejected_by_native_sandbox_constructor() {
    let workspace = tempfile::tempdir().unwrap();
    let mut policy = SandboxPolicy::a3s_bash_baseline();
    policy.filesystem.session_write = SessionWriteMode::Ephemeral;
    let error = format!(
        "{:#}",
        NativeSandbox::with_policy(workspace.path(), policy).unwrap_err()
    );
    assert!(
        error.contains("ephemeral") || error.contains("overlay"),
        "{error}"
    );
}
