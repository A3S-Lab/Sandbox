//! Gate 10 (optimization roadmap): approval-to-policy loop integration.
//!
//! The crate owns typed grant objects and digest-pinned application; the
//! host owns prompting. These tests prove the structural contract: grants
//! are the only sanctioned broadening path, they are pinned to the policy
//! digest the approval was made against, they widen exactly the granted
//! subject, and every application is auditable. The live test runs the full
//! product loop: denied command → host approval → grant → same command
//! flows through the mediation boundary.

use super::{NetworkAllowRule, SandboxPolicy};
use crate::{NativeSandbox, NetworkGrant, ReasonCode};

#[test]
fn stale_base_digest_refuses_and_leaves_policy_unchanged() {
    let workspace = tempfile::tempdir().unwrap();
    let sandbox = NativeSandbox::new(workspace.path()).unwrap();
    let digest_before = sandbox.policy_digest();
    let grant = NetworkGrant::new("api.example.com", Some(443)).unwrap();
    let error = sandbox
        .apply_network_grant(grant, "not-the-current-digest")
        .expect_err("stale lineage must refuse");
    assert!(
        error.to_string().contains("digest"),
        "refusal must explain the lineage failure: {error}"
    );
    assert_eq!(
        sandbox.policy_digest(),
        digest_before,
        "a refused grant must not touch the policy"
    );
    let denial = sandbox
        .audit_log()
        .snapshot()
        .into_iter()
        .find(|event| {
            event
                .target_redacted
                .contains("<network-grant:api.example.com:443")
        })
        .expect("stale refusal must be auditable");
    assert_eq!(denial.decision, crate::AccessDecision::Deny);
    assert!(!denial.target_redacted.contains("not-the-current-digest"));
}

#[test]
fn applied_grant_is_auditable_with_new_digest_and_updates_the_session() {
    let workspace = tempfile::tempdir().unwrap();
    let sandbox = NativeSandbox::new(workspace.path()).unwrap();
    let base = sandbox.policy_digest();
    let grant = NetworkGrant::new("api.example.com", Some(443)).unwrap();
    let new_digest = sandbox.apply_network_grant(grant, &base).unwrap();
    assert_ne!(new_digest, base, "an applied grant must change the digest");
    assert_eq!(sandbox.policy_digest(), new_digest);
    assert!(sandbox.policy().features.mediated_network);
    assert_eq!(sandbox.policy().network.allow.len(), 1);

    let event = sandbox
        .audit_log()
        .snapshot()
        .into_iter()
        .find(|event| event.reason_code == ReasonCode::GrantApplied)
        .expect("grant application must be auditable");
    assert_eq!(event.decision, crate::AccessDecision::Allow);
    assert_eq!(event.policy_digest, new_digest);
    assert_eq!(event.target_redacted, "<network-grant:api.example.com:443>");
}

#[test]
fn idempotent_regrant_changes_nothing_and_records_no_new_allow_rule() {
    let workspace = tempfile::tempdir().unwrap();
    let sandbox = NativeSandbox::new(workspace.path()).unwrap();
    let base = sandbox.policy_digest();
    let grant = NetworkGrant::new("api.example.com", Some(443)).unwrap();
    let first = sandbox.apply_network_grant(grant.clone(), &base).unwrap();
    let second = sandbox.apply_network_grant(grant, &first).unwrap();
    assert_eq!(first, second, "regranting the same subject is a no-op");
    assert_eq!(sandbox.policy().network.allow.len(), 1);
}

#[test]
fn hand_built_broadening_still_refuses_without_the_explicit_opt_in() {
    let workspace = tempfile::tempdir().unwrap();
    let sandbox = NativeSandbox::new(workspace.path()).unwrap();
    let mut widened = sandbox.policy().clone();
    widened.features.mediated_network = true;
    widened.network.allow.push(NetworkAllowRule {
        host: "sideload.example.com".into(),
        port: None,
        path_prefix: None,
    });
    let error = sandbox
        .replace_policy(
            widened,
            crate::PolicyUpdateOptions {
                allow_broadening: false,
            },
        )
        .expect_err("hand-built broadening keeps failing closed");
    assert!(error.to_string().contains("broadening"), "{error}");
}

#[test]
fn granted_policy_authorizes_only_the_granted_subject() {
    let workspace = tempfile::tempdir().unwrap();
    let sandbox = NativeSandbox::new(workspace.path()).unwrap();
    let base = sandbox.policy_digest();
    sandbox
        .apply_network_grant(
            NetworkGrant::new("api.example.com", Some(443)).unwrap(),
            &base,
        )
        .unwrap();
    let policy = sandbox.policy();
    assert_eq!(
        super::decide_mediated_connect(&policy, "api.example.com", 443),
        crate::AccessDecision::Allow
    );
    assert_eq!(
        super::decide_mediated_connect(&policy, "other.example.com", 443),
        crate::AccessDecision::Deny
    );
    assert_eq!(
        super::decide_mediated_connect(&policy, "api.example.com", 8443),
        crate::AccessDecision::Deny
    );
}

/// Full product loop on a mediated-capable host: deny → approve → allow.
#[cfg(target_os = "macos")]
#[tokio::test]
async fn grant_loop_unblocks_a_denied_command_end_to_end() {
    use crate::CommandRequest;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let upstream = TcpListener::bind(std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .unwrap();
    let upstream_port = upstream.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.unwrap();
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        stream.write_all(b"pong").await.unwrap();
    });

    let workspace = tempfile::tempdir().unwrap();
    let sandbox = NativeSandbox::new(workspace.path()).unwrap();
    let script = format!(
        r#"python3 - <<'PY'
import os, socket
proxy = os.environ["HTTPS_PROXY"].rsplit(":", 1)
s = socket.create_connection(("127.0.0.1", int(proxy[-1])))
s.sendall("CONNECT 127.0.0.1:{upstream_port} HTTP/1.1\r\n\r\n".encode())
data = b""
while b"\r\n\r\n" not in data:
    chunk = s.recv(1)
    assert chunk, "closed"
    data += chunk
assert data.startswith(b"HTTP/1.1 200"), data
s.sendall(b"ping")
print(s.recv(4).decode())
PY"#
    );
    let request = || CommandRequest {
        command: script.clone(),
        timeout_ms: 30_000,
        output_observer: None,
        env: None,
    };

    // Step 1: deny-all baseline — the command cannot reach the network.
    let denied = sandbox.execute(request()).await.unwrap();
    assert_ne!(
        denied.exit_code, 0,
        "baseline must deny network egress; stdout={}",
        denied.stdout
    );

    // Step 2: the host approves exactly this origin.
    let base = sandbox.policy_digest();
    sandbox
        .apply_network_grant(
            NetworkGrant::new("127.0.0.1", Some(upstream_port)).unwrap(),
            &base,
        )
        .unwrap();

    // Step 3: the same command now flows through the mediation boundary.
    let allowed = sandbox.execute(request()).await.unwrap();
    assert_eq!(allowed.exit_code, 0, "stderr={}", allowed.stderr);
    assert_eq!(allowed.stdout.trim(), "pong");
    assert!(
        sandbox
            .audit_log()
            .snapshot()
            .iter()
            .any(|event| event.reason_code == ReasonCode::GrantApplied),
        "the unblocking grant must be in the audit trail"
    );
}

#[test]
fn baseline_policy_fixture_matches_default() {
    let policy = SandboxPolicy::a3s_bash_baseline();
    assert!(!policy.features.mediated_network);
    assert!(policy.network.allow.is_empty());
}
