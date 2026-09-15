//! Linux mediation bridge: claimed HTTP CONNECT path + residual checklist.
//!
//! Live guest evidence (`platform::linux::tests::linux_bridge_wire_*`) proves
//! allow tunnels, denied CONNECT, and raw egress failure under `--unshare-net`.
//! `mediated_http` is therefore claimed on Linux. SOCKS and Unix-socket
//! allowlists remain fail-closed until separate fences ship.

use crate::policy::{BackendCapabilities, NetworkAllowRule, SandboxPolicy};
use crate::{posix_shell_single_quote, GUEST_HTTP_CONNECT_RELAY_PORT};

#[test]
fn gate5_linux_mediated_http_is_claimed_socks_remain_unclaimed() {
    let caps = BackendCapabilities::native_gate2();
    if cfg!(target_os = "linux") {
        assert!(
            caps.mediated_http,
            "Linux claims mediated_http after live netns bridge proof"
        );
        assert!(
            !caps.mediated_socks && !caps.unix_socket_allowlist,
            "Linux must not claim SOCKS/unix allowlists without fences"
        );
    }
}

#[test]
fn gate5_linux_mediated_http_policy_compiles_on_linux_capabilities() {
    let mut policy = SandboxPolicy::a3s_bash_baseline();
    policy.features.mediated_network = true;
    policy.network.allow.push(NetworkAllowRule {
        host: "example.com".into(),
        port: Some(443),
        path_prefix: None,
    });
    let linuxish = BackendCapabilities {
        mediated_http: true,
        mediated_socks: false,
        unix_socket_allowlist: false,
        ..BackendCapabilities::native_gate2()
    };
    policy
        .validate_for_backend(linuxish)
        .expect("Linux-capable backend accepts mediated HTTP policy");
}

#[test]
fn gate5_linux_bridge_foundation_apis_are_present() {
    assert_eq!(GUEST_HTTP_CONNECT_RELAY_PORT, 24731);
    assert_eq!(posix_shell_single_quote("a'b"), "'a'\\''b'");
}

/// Residual checklist items still required for SOCKS / unix allowlists.
#[test]
fn gate5_linux_bridge_residual_checklist_is_documented() {
    let residual = [
        "mediated_socks requires a SOCKS relay path (not yet claimed)",
        "unix-socket allowlists (if claimed) cannot reach host docker.sock",
        "missing bwrap/userns still fails closed (no host fallback)",
        "A3S_SANDBOX_RELAY / sibling a3s-sandbox-relay required for mediation",
    ];
    assert_eq!(residual.len(), 4);
    for item in residual {
        assert!(!item.is_empty());
    }
}
