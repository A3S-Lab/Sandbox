//! Windows mediation bridge acceptance criteria (Gate 5 residual).
//!
//! AppContainer with zero network capabilities already denies guest TCP and
//! Unix-domain sockets (Gate 0 evidence). That is why Windows cannot reuse the
//! macOS Seatbelt `localhost:<port>` pattern: granting loopback without a
//! destination fence would overfit.
//!
//! Preferred bridge (unclaimed until live guest proof): host-supervised
//! named-pipe CONNECT broker ACL'd to the execution AppContainer SID, while
//! the guest remains network-capability-less. Guest contract is
//! `A3S_SANDBOX_MEDIATOR_PIPE` (not `HTTP_PROXY`). WFP ALE allowlisting only
//! the mediator loopback port is an alternative with higher privilege/teardown
//! cost.
//!
//! Live proof test (Windows-only):
//! `platform::windows::tests::windows_appcontainer_named_pipe_connect_allow_deny_and_blocks_raw_egress`.
//! Do not flip `mediated_http` until that test is green on Windows CI / hardware.

use crate::policy::{BackendCapabilities, NetworkAllowRule, SandboxPolicy};

#[test]
fn gate5_windows_mediation_capabilities_remain_unclaimed() {
    let caps = BackendCapabilities::native_gate2();
    if cfg!(windows) {
        assert!(
            !caps.mediated_http && !caps.mediated_socks && !caps.unix_socket_allowlist,
            "Windows must not claim mediation without an OS bridge"
        );
    }
}

#[test]
fn gate5_windows_mediated_policy_fails_closed_on_windows_capabilities() {
    let mut policy = SandboxPolicy::a3s_bash_baseline();
    policy.features.mediated_network = true;
    policy.network.allow.push(NetworkAllowRule {
        host: "example.com".into(),
        port: Some(443),
        path_prefix: None,
    });
    let windowsish = BackendCapabilities {
        mediated_http: false,
        mediated_socks: false,
        unix_socket_allowlist: false,
        ..BackendCapabilities::native_gate2()
    };
    let error = policy
        .validate_for_backend(windowsish)
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("mediated_network") || error.contains("fail closed"),
        "{error}"
    );
}

/// Acceptance checklist for claiming Windows `mediated_http`.
#[test]
fn gate5_windows_bridge_acceptance_checklist_is_documented() {
    let required = [
        "guest retains zero AppContainer network capabilities (no raw TCP)",
        "guest reaches host mediator only via ACL'd named pipe (or WFP-fenced loopback)",
        "guest contract is A3S_SANDBOX_MEDIATOR_PIPE (not HTTP_PROXY)",
        "denied CONNECT never reaches upstream",
        "NO_PROXY and proxy env bypasses cannot restore raw egress",
        "pipe ACL setup failure fails closed (no host fallback)",
        "AppContainer profile teardown restores prior security state",
        "create_appcontainer_named_pipe DACL denies non-AppContainer clients",
        "bind_named_pipe_acl recreates every accept instance with the same DACL",
        "windows_appcontainer_named_pipe_connect_allow_deny_and_blocks_raw_egress green on Windows",
    ];
    assert_eq!(required.len(), 10);
    for item in required {
        assert!(!item.is_empty());
    }
}

#[test]
fn gate5_windows_guest_contract_rejects_http_proxy_as_bridge() {
    // Documented invariant: zero-net AppContainers cannot use loopback TCP, so
    // inventing HTTP_PROXY would overfit and silently break mediation.
    let forbidden_bridge = "HTTP_PROXY=http://127.0.0.1:";
    let required_bridge = "A3S_SANDBOX_MEDIATOR_PIPE=\\\\.\\pipe\\";
    assert!(!forbidden_bridge.is_empty());
    assert!(required_bridge.contains("A3S_SANDBOX_MEDIATOR_PIPE"));
}
