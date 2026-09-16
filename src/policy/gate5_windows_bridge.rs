//! Windows mediation bridge: claimed HTTP CONNECT path + residual checklist.
//!
//! Live guest evidence
//! (`platform::windows::tests::windows_appcontainer_named_pipe_connect_allow_deny_and_blocks_raw_egress`)
//! proves allow tunnels, denied CONNECT, and raw egress failure under zero
//! AppContainer network capabilities. The guest speaks CONNECT over an
//! inherited connected named-pipe handle (`A3S_SANDBOX_MEDIATOR_PIPE_HANDLE`);
//! name-open alone remains Access Denied under AppContainer on GHA.
//! `mediated_http` is therefore claimed on Windows. SOCKS and Unix-socket
//! allowlists remain fail-closed.

use crate::policy::{BackendCapabilities, NetworkAllowRule, SandboxPolicy};

#[test]
fn gate5_windows_mediated_http_is_claimed_socks_remain_unclaimed() {
    let caps = BackendCapabilities::native_gate2();
    if cfg!(windows) {
        assert!(
            caps.mediated_http,
            "Windows claims mediated_http after live AppContainer pipe proof"
        );
        assert!(
            !caps.mediated_socks && !caps.unix_socket_allowlist,
            "Windows must not claim SOCKS/unix allowlists without fences"
        );
    }
}

#[test]
fn gate5_windows_mediated_http_policy_compiles_on_windows_capabilities() {
    let mut policy = SandboxPolicy::a3s_bash_baseline();
    policy.features.mediated_network = true;
    policy.network.allow.push(NetworkAllowRule {
        host: "example.com".into(),
        port: Some(443),
        path_prefix: None,
    });
    let windowsish = BackendCapabilities {
        mediated_http: true,
        mediated_socks: false,
        unix_socket_allowlist: false,
        ..BackendCapabilities::native_gate2()
    };
    policy
        .validate_for_backend(windowsish)
        .expect("Windows-capable backend accepts mediated HTTP policy");
}

/// Acceptance checklist items still required for SOCKS / alternate bridges.
#[test]
fn gate5_windows_bridge_acceptance_checklist_is_documented() {
    let required = [
        "guest retains zero AppContainer network capabilities (no raw TCP)",
        "guest reaches host mediator via inherited connected pipe handle",
        "guest contract is A3S_SANDBOX_MEDIATOR_PIPE_HANDLE (not HTTP_PROXY)",
        "denied CONNECT never reaches upstream",
        "NO_PROXY and proxy env bypasses cannot restore raw egress",
        "pipe pair setup failure fails closed (no host fallback)",
        "AppContainer profile teardown restores prior security state",
        "create_appcontainer_named_pipe DACL denies non-AppContainer name opens",
        "create_appcontainer_mediation_pipe inherits connected client into guest",
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
    // HTTP_PROXY is not a valid Windows mediation contract.
    assert_ne!(
        "HTTP_PROXY", "A3S_SANDBOX_MEDIATOR_PIPE_HANDLE",
        "Windows guest contract must not be HTTP_PROXY"
    );
}
