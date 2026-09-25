//! Gate 7 release-checklist invariants that must stay true for every release.

use crate::policy::{BackendCapabilities, FeatureFlags, SandboxPolicy};
use crate::NativeSandbox;

#[test]
fn gate7_release_default_profile_keeps_mediation_off() {
    let policy = SandboxPolicy::a3s_bash_baseline();
    assert!(
        !policy.features.mediated_network && !policy.features.mediated_socks,
        "default A3S Bash profile must keep mediation flags off"
    );
    assert!(
        policy.network.allow.is_empty(),
        "default profile must not ship network allow rules"
    );
    // Explicit FeatureFlags defaults are false (#[derive(Default)]).
    let flags = FeatureFlags::default();
    assert!(!flags.mediated_network && !flags.mediated_socks);
}

#[test]
fn gate7_release_capability_probe_lists_unavailable_surfaces() {
    let workspace = tempfile::tempdir().unwrap();
    let sandbox = NativeSandbox::new(workspace.path()).unwrap();
    let report = sandbox.capability_report();
    let caps = BackendCapabilities::native_gate2();
    if !caps.mediated_http {
        assert!(
            report.unavailable.contains(&"mediated_http"),
            "unavailable must list mediated_http when unclaimed: {:?}",
            report.unavailable
        );
    }
    if !caps.mediated_socks {
        assert!(report.unavailable.contains(&"mediated_socks"));
    }
    if !caps.unix_socket_allowlist {
        assert!(report.unavailable.contains(&"unix_socket_allowlist"));
    }
    assert_eq!(report.backend, crate::NATIVE_SANDBOX_BACKEND);
}

#[test]
fn gate7_release_claims_match_capability_matrix() {
    let caps = BackendCapabilities::native_gate2();
    #[cfg(target_os = "macos")]
    {
        assert!(caps.mediated_http);
        assert!(caps.mediated_socks);
        assert!(caps.unix_socket_allowlist);
    }
    #[cfg(target_os = "linux")]
    {
        assert!(caps.mediated_http);
        assert!(
            caps.mediated_socks,
            "claimed after linux_socks_bridge_wire_*"
        );
        assert!(!caps.unix_socket_allowlist);
    }
    #[cfg(windows)]
    {
        assert!(caps.mediated_http);
        assert!(!caps.mediated_socks);
        assert!(!caps.unix_socket_allowlist);
    }
}
