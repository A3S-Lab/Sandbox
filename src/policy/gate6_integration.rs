//! Gate 6: monotonic policy updates and explicit capability reporting.

use crate::policy::{BackendCapabilities, NetworkAllowRule, PolicyUpdateOptions, SandboxPolicy};
use crate::NativeSandbox;

#[test]
fn gate6_capability_report_lists_unavailable_surfaces() {
    let workspace = tempfile::tempdir().unwrap();
    let sandbox = NativeSandbox::new(workspace.path()).unwrap();
    let report = sandbox.capability_report();
    assert_eq!(report.backend, sandbox.backend());
    assert_eq!(report.capabilities, BackendCapabilities::native_gate2());
    assert!(!report.policy_digest.is_empty());
    assert_eq!(
        report.unavailable.contains(&"mediated_http"),
        !report.capabilities.mediated_http
    );
    assert_eq!(
        report.unavailable.contains(&"mediated_socks"),
        !report.capabilities.mediated_socks
    );
    assert_eq!(
        report.unavailable.contains(&"unix_socket_allowlist"),
        !report.capabilities.unix_socket_allowlist
    );
}

#[test]
fn gate6_replace_policy_refuses_silent_broadening() {
    let workspace = tempfile::tempdir().unwrap();
    let mut sandbox = NativeSandbox::new(workspace.path()).unwrap();
    let mut next = SandboxPolicy::a3s_bash_baseline();
    next.features.mediated_network = true;
    next.network.allow.push(NetworkAllowRule {
        host: "api.example.com".into(),
        port: Some(443),
        path_prefix: None,
    });
    let error = sandbox
        .replace_policy(next.clone(), PolicyUpdateOptions::default())
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("broaden")
            || error.contains("allow_broadening")
            || error.contains("fail closed")
            || error.contains("incompatible")
            || error.contains("mediated_network"),
        "{error}"
    );

    if sandbox.capabilities().mediated_http {
        sandbox
            .replace_policy(
                next,
                PolicyUpdateOptions {
                    allow_broadening: true,
                },
            )
            .expect("explicit broadening opt-in");
        assert!(sandbox.policy().features.mediated_network);
    }
}

#[test]
fn gate6_replace_policy_allows_narrowing_without_opt_in() {
    let workspace = tempfile::tempdir().unwrap();
    let mut baseline = SandboxPolicy::a3s_bash_baseline();
    if !BackendCapabilities::native_gate2().mediated_http {
        return;
    }
    baseline.features.mediated_network = true;
    baseline.network.allow.push(NetworkAllowRule {
        host: "api.example.com".into(),
        port: Some(443),
        path_prefix: None,
    });
    let mut sandbox = NativeSandbox::with_policy(workspace.path(), baseline).unwrap();
    sandbox
        .replace_policy(
            SandboxPolicy::a3s_bash_baseline(),
            PolicyUpdateOptions::default(),
        )
        .expect("narrowing must not require allow_broadening");
    assert!(!sandbox.policy().features.mediated_network);
}
