//! Gate 1 integration: portable fixtures + compile path + live boundary.

use super::{
    decide_network, decide_read, decide_write, normalize_policy_path, policy_digest,
    AccessDecision, BackendCapabilities, EnforcedPolicy, FilesystemRules, PathRule, SandboxPolicy,
};
use crate::{CommandRequest, NativeSandbox};

/// Portable A3S Bash-shaped fixture used on every OS. Absolute host roots are
/// intentionally absent so decisions compare identically across platforms.
fn portable_bash_fixture() -> SandboxPolicy {
    SandboxPolicy {
        filesystem: FilesystemRules {
            allow_read: vec![
                PathRule::Exact("workspace".into()),
                PathRule::Exact("scratch".into()),
            ],
            deny_read: vec![
                PathRule::Exact("workspace/.env".into()),
                PathRule::Glob("workspace/.env*".into()),
            ],
            allow_write: vec![
                PathRule::Exact("workspace".into()),
                PathRule::Exact("scratch".into()),
            ],
            deny_write: vec![
                PathRule::Exact("workspace/.git".into()),
                PathRule::Exact("workspace/.a3s".into()),
            ],
            write_exceptions: vec![PathRule::Exact("workspace/.a3s/loops".into())],
            ..Default::default()
        },
        ..SandboxPolicy::a3s_bash_baseline()
    }
}

#[test]
fn gate1_fixture_decisions_match_expected_table() {
    let policy = portable_bash_fixture();
    policy.validate().unwrap();

    let cases = [
        (
            "workspace/src/main.rs",
            AccessDecision::Allow,
            AccessDecision::Allow,
        ),
        (
            "workspace/.env",
            AccessDecision::Deny,
            AccessDecision::Allow,
        ),
        (
            "workspace/.env.local",
            AccessDecision::Deny,
            AccessDecision::Allow,
        ),
        (
            "workspace/.git/config",
            AccessDecision::Allow,
            AccessDecision::Deny,
        ),
        (
            "workspace/.a3s/policy.acl",
            AccessDecision::Allow,
            AccessDecision::Deny,
        ),
        (
            "workspace/.a3s/loops/g1/STATE.md",
            AccessDecision::Allow,
            AccessDecision::Allow,
        ),
        ("outside/file", AccessDecision::Deny, AccessDecision::Deny),
    ];

    for (path, read, write) in cases {
        let normalized = normalize_policy_path(path).unwrap();
        assert_eq!(decide_read(&policy, &normalized), read, "read {path}");
        assert_eq!(decide_write(&policy, &normalized), write, "write {path}");
    }
    assert_eq!(decide_network(&policy), AccessDecision::Deny);
}

#[test]
fn gate1_fixture_digest_is_replay_stable() {
    let first = policy_digest(&portable_bash_fixture());
    let second = policy_digest(&portable_bash_fixture());
    assert_eq!(first, second);
    assert_eq!(first.len(), 64);
}

#[test]
fn gate1_compile_requires_sandbox_policy_and_rejects_broadening() {
    let workspace = tempfile::tempdir().unwrap();
    let scratch = tempfile::tempdir().unwrap();
    let baseline = SandboxPolicy::a3s_bash_baseline();
    let enforced = EnforcedPolicy::compile(
        &baseline,
        workspace.path(),
        scratch.path(),
        BackendCapabilities::native_gate1(),
    )
    .unwrap();
    assert!(enforced
        .allow_write
        .contains(&workspace.path().canonicalize().unwrap()));
    assert!(enforced
        .allow_write
        .contains(&scratch.path().canonicalize().unwrap()));

    let mut mediated = baseline.clone();
    mediated.features.mediated_network = true;
    mediated
        .network
        .allow
        .push(crate::policy::NetworkAllowRule {
            host: "example.com".into(),
            port: Some(443),
            path_prefix: None,
        });
    let compiled = EnforcedPolicy::compile(
        &mediated,
        workspace.path(),
        scratch.path(),
        BackendCapabilities::native_gate1(),
    );
    if cfg!(any(target_os = "macos", target_os = "linux")) {
        compiled.expect("claiming platforms can enforce mediated HTTP");
    } else {
        let error = format!("{:#}", compiled.unwrap_err());
        assert!(
            error.contains("mediated_network") || error.contains("fail closed"),
            "{error}"
        );
    }
}

#[test]
fn gate1_compile_applies_exact_deny_overlays_without_globs() {
    let workspace = tempfile::tempdir().unwrap();
    let scratch = tempfile::tempdir().unwrap();
    std::fs::write(workspace.path().join("extra.secret"), "x").unwrap();

    let mut policy = SandboxPolicy::a3s_bash_baseline();
    policy
        .filesystem
        .deny_read
        .push(PathRule::Exact("extra.secret".into()));
    let enforced = EnforcedPolicy::compile(
        &policy,
        workspace.path(),
        scratch.path(),
        BackendCapabilities::native_gate1(),
    )
    .unwrap();
    let denied = workspace
        .path()
        .join("extra.secret")
        .canonicalize()
        .unwrap();
    assert!(enforced.deny_read.contains(&denied));

    policy
        .filesystem
        .deny_read
        .push(PathRule::Glob("*.secret".into()));
    let error = EnforcedPolicy::compile(
        &policy,
        workspace.path(),
        scratch.path(),
        BackendCapabilities::native_gate1(),
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("glob"), "{error}");
}

#[test]
fn gate1_compile_refuses_allow_overlays_outside_workspace_or_scratch() {
    let workspace = tempfile::tempdir().unwrap();
    let scratch = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let mut policy = SandboxPolicy::a3s_bash_baseline();
    policy.filesystem.allow_write.push(PathRule::Exact(
        outside.path().canonicalize().unwrap().display().to_string(),
    ));
    let error = EnforcedPolicy::compile(
        &policy,
        workspace.path(),
        scratch.path(),
        BackendCapabilities::native_gate1(),
    )
    .unwrap_err()
    .to_string();
    assert!(
        error.contains("outside") || error.contains("broaden") || error.contains("fail closed"),
        "{error}"
    );
}

#[tokio::test]
async fn gate1_native_sandbox_integration_still_executes() {
    let workspace = tempfile::tempdir().unwrap();
    let sandbox = NativeSandbox::new(workspace.path()).unwrap();
    assert_eq!(
        policy_digest(sandbox.policy()),
        policy_digest(&SandboxPolicy::a3s_bash_baseline())
    );
    sandbox
        .probe()
        .await
        .expect("Gate 0 probe must remain green");
    let output = sandbox
        .execute(CommandRequest {
            command: if cfg!(windows) {
                "Write-Output gate1-ok".into()
            } else {
                "printf gate1-ok".into()
            },
            timeout_ms: 30_000,
            output_observer: None,
            env: None,
        })
        .await
        .expect("Gate 0 execute must remain green");
    assert!(
        output.stdout.contains("gate1-ok"),
        "stdout={}",
        output.stdout
    );
    assert_eq!(output.exit_code, 0);
}

#[test]
fn gate1_native_sandbox_rejects_unenforcible_policy() {
    let workspace = tempfile::tempdir().unwrap();
    let sandbox = NativeSandbox::new(workspace.path()).unwrap();
    let mut policy = SandboxPolicy::a3s_bash_baseline();
    // Prefer a limit that remains unenforceable on every Gate 2 backend.
    policy.resources.max_call_depth = Some(32);
    let error = sandbox
        .ensure_policy_enforceable(&policy)
        .unwrap_err()
        .to_string();
    assert!(error.contains("max_call_depth"), "{error}");
    sandbox
        .ensure_policy_enforceable(&SandboxPolicy::a3s_bash_baseline())
        .unwrap();

    let error = format!(
        "{:#}",
        NativeSandbox::with_policy(workspace.path(), policy).unwrap_err()
    );
    assert!(error.contains("max_call_depth"), "{error}");

    // Unix cannot claim process-tree quotas without cgroup; Windows Job can.
    let mut process_policy = SandboxPolicy::a3s_bash_baseline();
    process_policy.resources.max_processes = Some(32);
    if cfg!(windows) {
        sandbox
            .ensure_policy_enforceable(&process_policy)
            .expect("Windows Job Object can enforce max_processes");
    } else {
        let error = sandbox
            .ensure_policy_enforceable(&process_policy)
            .unwrap_err()
            .to_string();
        assert!(error.contains("process limit"), "{error}");
    }
}
