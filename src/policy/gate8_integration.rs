//! Gate 8: credential containment — host-held secret env never lands.
//!
//! Slice 1 proves the sentinel + fail-closed spine: secret values supplied by
//! the host reach the child environment only as redacted sentinels, the real
//! bytes never reach the child environment, captured output, audit log, or
//! policy digest, and secret env without an active mediated-network boundary
//! refuses before spawn. Egress re-injection at the mediation point is the
//! next slice; until then a mediated run yields sentinels only, never
//! literals.

use std::collections::HashMap;
use std::sync::Arc;

#[cfg(not(windows))]
use crate::policy::SecretHeaderInjection;
use crate::policy::{AccessDecision, NetworkAllowRule, SandboxPolicy};
use crate::{AuditSurface, CommandRequest, NativeSandbox, ReasonCode, SECRET_ENV_SENTINEL_PREFIX};

const SECRET_NAME: &str = "A3S_GATE8_TOKEN";
const SECRET_VALUE: &str = "gate8-super-secret-7f3a";

fn mediated_policy() -> SandboxPolicy {
    let mut policy = SandboxPolicy::a3s_bash_baseline();
    policy.features.mediated_network = true;
    policy.network.allow.push(NetworkAllowRule {
        host: "api.example.com".into(),
        port: Some(443),
        path_prefix: None,
    });
    policy
}

fn secret_map(name: &str, value: &str) -> Option<Arc<HashMap<String, String>>> {
    Some(Arc::new(HashMap::from([(
        name.to_string(),
        value.to_string(),
    )])))
}

fn print_secret_command() -> String {
    #[cfg(windows)]
    {
        "[Console]::Out.Write($env:A3S_GATE8_TOKEN)".to_string()
    }
    #[cfg(not(windows))]
    {
        "printf %s \"$A3S_GATE8_TOKEN\"".to_string()
    }
}

fn dump_env_command() -> String {
    #[cfg(windows)]
    {
        "Get-ChildItem Env: | Out-String".to_string()
    }
    #[cfg(not(windows))]
    {
        "env".to_string()
    }
}

fn mediated_sandbox(workspace: &std::path::Path) -> NativeSandbox {
    NativeSandbox::with_policy(workspace, mediated_policy()).unwrap()
}

fn secret_request(command: String) -> CommandRequest {
    CommandRequest {
        command,
        timeout_ms: 30_000,
        output_observer: None,
        env: None,
    }
}

#[tokio::test]
async fn gate8_secret_env_delivers_sentinel_not_secret_to_child() {
    let workspace = tempfile::tempdir().unwrap();
    let sandbox = mediated_sandbox(workspace.path());
    let output = sandbox
        .execute_with_secrets(
            secret_request(print_secret_command()),
            secret_map(SECRET_NAME, SECRET_VALUE),
        )
        .await
        .unwrap();
    assert_eq!(output.exit_code, 0, "stderr: {}", output.stderr);
    let sentinel = format!("{SECRET_ENV_SENTINEL_PREFIX}{SECRET_NAME}");
    assert_eq!(output.stdout, sentinel, "child must observe the sentinel");
    assert!(
        !output.stdout.contains(SECRET_VALUE) && !output.stderr.contains(SECRET_VALUE),
        "secret bytes must never reach captured output"
    );
}

#[tokio::test]
async fn gate8_secret_bytes_never_appear_in_child_environment_dump() {
    let workspace = tempfile::tempdir().unwrap();
    let sandbox = mediated_sandbox(workspace.path());
    let output = sandbox
        .execute_with_secrets(
            secret_request(dump_env_command()),
            secret_map(SECRET_NAME, SECRET_VALUE),
        )
        .await
        .unwrap();
    assert_eq!(output.exit_code, 0, "stderr: {}", output.stderr);
    let environment = format!("{}{}", output.stdout, output.stderr);
    assert!(
        environment.contains(&format!("{SECRET_ENV_SENTINEL_PREFIX}{SECRET_NAME}")),
        "sentinel must be present in the child environment"
    );
    assert!(
        !environment.contains(SECRET_VALUE),
        "secret bytes must never appear in the child environment dump"
    );
}

#[tokio::test]
async fn gate8_secret_env_without_mediation_fails_closed() {
    let workspace = tempfile::tempdir().unwrap();
    // Default baseline keeps mediated_network off; secrets must refuse before
    // spawn instead of silently degrading to literal injection.
    let sandbox = NativeSandbox::new(workspace.path()).unwrap();
    let error = sandbox
        .execute_with_secrets(
            secret_request(print_secret_command()),
            secret_map(SECRET_NAME, SECRET_VALUE),
        )
        .await
        .expect_err("secret env must fail closed without mediated_network");
    assert!(
        error.to_string().contains("mediated"),
        "refusal must explain the mediation requirement: {error}"
    );
    let denial = sandbox
        .audit_log()
        .snapshot()
        .into_iter()
        .find(|event| {
            event.surface == AuditSurface::Environment
                && event.decision == AccessDecision::Deny
                && event.reason_code == ReasonCode::SecretRequiresMediation
        })
        .expect("refusal must be auditable");
    assert!(
        !denial.target_redacted.contains(SECRET_VALUE),
        "audit targets must stay redacted"
    );
}

#[tokio::test]
async fn gate8_reserved_secret_names_refuse() {
    let workspace = tempfile::tempdir().unwrap();
    let sandbox = mediated_sandbox(workspace.path());
    for name in [
        "HOME",
        "TMP",
        "PATH",
        "http_proxy",
        "NO_PROXY",
        "A3S_SANDBOX_MEDIATOR_PIPE",
        "BASH_ENV",
        "LD_PRELOAD",
    ] {
        let error = sandbox
            .execute_with_secrets(
                secret_request(print_secret_command()),
                secret_map(name, SECRET_VALUE),
            )
            .await
            .expect_err("reserved env names must refuse for secrets");
        assert!(
            error.to_string().contains("reserved"),
            "refusal must explain the reserved-name rule for {name}: {error}"
        );
    }
}

#[tokio::test]
async fn gate8_secret_colliding_with_explicit_env_refuses() {
    let workspace = tempfile::tempdir().unwrap();
    let sandbox = mediated_sandbox(workspace.path());
    let error = sandbox
        .execute_with_secrets(
            CommandRequest {
                command: print_secret_command(),
                timeout_ms: 30_000,
                output_observer: None,
                env: Some(Arc::new(HashMap::from([(
                    SECRET_NAME.to_string(),
                    "literal".to_string(),
                )]))),
            },
            secret_map(SECRET_NAME, SECRET_VALUE),
        )
        .await
        .expect_err("a secret name colliding with an explicit env entry is ambiguous");
    assert!(
        error.to_string().contains("collide"),
        "refusal must explain the collision: {error}"
    );
}

#[tokio::test]
async fn gate8_invalid_secret_entries_refuse() {
    let workspace = tempfile::tempdir().unwrap();
    let sandbox = mediated_sandbox(workspace.path());
    for (name, value) in [
        ("", SECRET_VALUE),
        ("BAD=NAME", SECRET_VALUE),
        ("A\0B", SECRET_VALUE),
        ("OK_NAME", "va\0lue"),
    ] {
        let error = sandbox
            .execute_with_secrets(
                secret_request(print_secret_command()),
                secret_map(name, value),
            )
            .await
            .expect_err("malformed secret entries must refuse");
        assert!(
            error.to_string().contains("invalid"),
            "refusal must explain the entry rule for {name:?}: {error}"
        );
    }
}

#[tokio::test]
async fn gate8_secret_bytes_absent_from_audit_and_digest_stable() {
    let workspace = tempfile::tempdir().unwrap();
    let sandbox = mediated_sandbox(workspace.path());
    let digest_before = sandbox.policy_digest();
    let output = sandbox
        .execute_with_secrets(
            secret_request(print_secret_command()),
            secret_map(SECRET_NAME, SECRET_VALUE),
        )
        .await
        .unwrap();
    assert_eq!(output.exit_code, 0);
    assert_eq!(sandbox.policy_digest(), digest_before);
    let audit_dump = format!("{:?}", sandbox.audit_log().snapshot());
    assert!(
        !audit_dump.contains(SECRET_VALUE),
        "secret bytes must never reach the audit log"
    );
    let injection = sandbox
        .audit_log()
        .snapshot()
        .into_iter()
        .find(|event| {
            event.surface == AuditSurface::Environment && event.decision == AccessDecision::Allow
        })
        .expect("sentinel injection must be auditable");
    assert!(
        injection.target_redacted.contains(SECRET_NAME),
        "secret names are not secret and may appear for attribution"
    );
    assert!(
        !injection.target_redacted.contains(SECRET_VALUE),
        "audit targets must stay redacted"
    );
}

// -- Gate 8 slice 2: egress re-injection at the mediation point --------------

#[cfg(not(windows))]
#[tokio::test]
async fn gate8_egress_reinjection_delivers_secret_without_landing_it() {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let upstream = TcpListener::bind(std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .unwrap();
    let upstream_port = upstream.local_addr().unwrap().port();
    let upstream_task = tokio::spawn(async move {
        let (raw, _) = upstream.accept().await.unwrap();
        let mut stream = tokio::io::BufReader::new(raw);
        let mut head = Vec::new();
        loop {
            let mut line = Vec::new();
            match stream.read_until(b'\n', &mut line).await {
                Ok(0) | Err(_) => return String::new(),
                Ok(_) if line == b"\r\n" || line == b"\n" => break,
                Ok(_) => head.extend_from_slice(&line),
            }
        }
        let head = String::from_utf8_lossy(&head).into_owned();
        assert!(
            head.contains(&format!("Authorization: Bearer {SECRET_VALUE}")),
            "upstream must observe the injected secret: {head:?}"
        );
        assert!(
            !head.contains("a3s:secret:"),
            "sentinels must never be forwarded upstream: {head:?}"
        );
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\ntoken-ok")
            .await
            .unwrap();
        head
    });

    let workspace = tempfile::tempdir().unwrap();
    let mut policy = mediated_policy_for_port(upstream_port);
    policy.secret_injections.push(SecretHeaderInjection {
        host: "127.0.0.1".into(),
        port: Some(upstream_port),
        path_prefix: Some("/v1".into()),
        header: "Authorization".into(),
        value_prefix: "Bearer ".into(),
        secret_env: SECRET_NAME.into(),
    });
    let sandbox = NativeSandbox::with_policy(workspace.path(), policy).unwrap();

    let script = format!(
        r#"python3 - <<'PY'
import os, socket
proxy = os.environ["HTTP_PROXY"].rsplit(":", 1)
port = int(proxy[-1])
s = socket.create_connection(("127.0.0.1", port))
s.sendall("GET http://127.0.0.1:{upstream_port}/v1/token HTTP/1.1\r\nAccept: */*\r\n\r\n".encode())
data = b""
while True:
    chunk = s.recv(4096)
    if not chunk:
        break
    data += chunk
body = data.split(b"\r\n\r\n", 1)[1]
print(body.decode())
PY"#
    );
    let output = sandbox
        .execute_with_secrets(
            CommandRequest {
                command: script,
                timeout_ms: 30_000,
                output_observer: None,
                env: None,
            },
            secret_map(SECRET_NAME, SECRET_VALUE),
        )
        .await
        .unwrap();
    assert_eq!(output.exit_code, 0, "stderr: {}", output.stderr);
    assert!(
        output.stdout.contains("token-ok"),
        "stdout={} stderr={}",
        output.stdout,
        output.stderr
    );
    assert!(
        !output.stdout.contains(SECRET_VALUE) && !output.stderr.contains(SECRET_VALUE),
        "secret bytes must not appear in guest-visible output"
    );
    assert!(
        !format!("{:?}", sandbox.audit_log().snapshot()).contains(SECRET_VALUE),
        "secret bytes must never reach the audit log"
    );
    upstream_task.await.unwrap();
}

#[cfg(not(windows))]
fn mediated_policy_for_port(port: u16) -> SandboxPolicy {
    let mut policy = SandboxPolicy::a3s_bash_baseline();
    policy.features.mediated_network = true;
    policy.network.allow.push(NetworkAllowRule {
        host: "127.0.0.1".into(),
        port: Some(port),
        path_prefix: None,
    });
    policy
}
