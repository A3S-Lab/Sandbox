#![cfg(test)]

use a3s_sandbox::{ExecutionUnavailable, NativeSandbox};

#[tokio::test]
async fn launch_probe_does_not_grant_missing_lifetime_guarantees() {
    let workspace = tempfile::tempdir().unwrap();
    let sandbox = NativeSandbox::new(workspace.path()).unwrap();
    assert_eq!(
        sandbox.capability_report().require_lifetime_containment(),
        Err(ExecutionUnavailable::RuntimeProbeRequired)
    );

    let report = sandbox.probe().await.unwrap();
    assert!(report.runtime_probed);
    #[cfg(target_os = "macos")]
    {
        assert!(report.unavailable.contains(&"process_tree_cleanup"));
        assert!(report.unavailable.contains(&"host_exit_cleanup"));
        assert_eq!(
            report.require_lifetime_containment(),
            Err(ExecutionUnavailable::ProcessTreeCleanup)
        );
    }
    #[cfg(windows)]
    assert_eq!(
        report.require_lifetime_containment(),
        Err(ExecutionUnavailable::HostExitCleanup)
    );
    #[cfg(target_os = "linux")]
    assert_eq!(report.require_lifetime_containment(), Ok(()));
}

#[test]
fn unavailability_reasons_are_stable_and_unknown_values_refuse() {
    for (code, reason) in [
        (
            "runtime_probe_required",
            ExecutionUnavailable::RuntimeProbeRequired,
        ),
        (
            "process_tree_cleanup_unavailable",
            ExecutionUnavailable::ProcessTreeCleanup,
        ),
        (
            "host_exit_cleanup_unavailable",
            ExecutionUnavailable::HostExitCleanup,
        ),
    ] {
        assert_eq!(ExecutionUnavailable::parse(code).unwrap(), reason);
        assert_eq!(reason.as_str(), code);
    }
    assert!(ExecutionUnavailable::parse("available").is_err());
}
