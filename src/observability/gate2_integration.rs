//! Gate 2 integration: audit attribution on live execute.

use crate::observability::{AuditSurface, ReasonCode};
use crate::policy::AccessDecision;
use crate::{CommandRequest, NativeSandbox};

#[tokio::test]
async fn gate2_execute_records_attributable_audit_events() {
    let workspace = tempfile::tempdir().unwrap();
    let sandbox = NativeSandbox::new(workspace.path()).unwrap();
    let digest = sandbox.policy_digest();
    let session = sandbox.session_id().to_string();

    sandbox
        .execute(CommandRequest {
            command: if cfg!(windows) {
                "Write-Output gate2-ok".into()
            } else {
                "printf gate2-ok".into()
            },
            timeout_ms: 30_000,
            output_observer: None,
            env: None,
        })
        .await
        .unwrap();

    let events = sandbox.audit_log().snapshot();
    assert!(
        events.len() >= 2,
        "expected compile + network deny events, got {}",
        events.len()
    );
    for event in &events {
        assert_eq!(event.session_id, session);
        assert_eq!(event.policy_digest, digest);
        assert_eq!(event.backend, sandbox.backend());
        assert!(!event.command_id.is_empty());
    }

    let compile = events
        .iter()
        .find(|e| e.surface == AuditSurface::PolicyCompile)
        .expect("policy compile event");
    assert_eq!(compile.decision, AccessDecision::Allow);
    assert_eq!(compile.reason_code, ReasonCode::PolicyAllow);

    let network = events
        .iter()
        .find(|e| e.surface == AuditSurface::Network)
        .expect("network deny event");
    assert_eq!(network.decision, AccessDecision::Deny);
    assert_eq!(network.reason_code, ReasonCode::NetworkDenyAll);
    assert_eq!(network.target_redacted, "<network>");
}
