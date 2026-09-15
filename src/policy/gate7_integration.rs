//! Gate 7 assurance: adversarial negative coverage for claimed surfaces.
//!
//! These tests prove fail-closed behaviour for proxy bypass, host aliasing,
//! mediator protocol abuse, and silent policy broadening. They do not claim
//! cross-OS fences that are still residual.

use crate::policy::{
    decide_mediated_connect, decide_mediated_socks, ensure_policy_not_broader, AccessDecision,
    BackendCapabilities, NetworkAllowRule, PolicyUpdateOptions, SandboxPolicy,
};
use crate::NativeSandbox;

fn mediated_http_policy(host: &str, port: u16) -> SandboxPolicy {
    let mut policy = SandboxPolicy::a3s_bash_baseline();
    policy.features.mediated_network = true;
    policy.network.allow.push(NetworkAllowRule {
        host: host.into(),
        port: Some(port),
        path_prefix: None,
    });
    policy
}

fn mediated_socks_policy(host: &str, port: u16) -> SandboxPolicy {
    let mut policy = SandboxPolicy::a3s_bash_baseline();
    policy.features.mediated_socks = true;
    policy.network.allow.push(NetworkAllowRule {
        host: host.into(),
        port: Some(port),
        path_prefix: None,
    });
    policy
}

#[test]
fn gate7_connect_does_not_alias_localhost_to_loopback_ip() {
    let policy = mediated_http_policy("127.0.0.1", 443);
    assert_eq!(
        decide_mediated_connect(&policy, "localhost", 443),
        AccessDecision::Deny,
        "string allowlists must not silently equate localhost and 127.0.0.1"
    );
    assert_eq!(
        decide_mediated_connect(&policy, "127.0.0.1", 443),
        AccessDecision::Allow
    );
}

#[test]
fn gate7_socks_does_not_authorize_literal_ip_when_hostname_allowlisted() {
    let policy = mediated_socks_policy("api.example.com", 22);
    assert_eq!(
        decide_mediated_socks(&policy, "203.0.113.10", 22),
        AccessDecision::Deny,
        "DNS rebinding / literal-IP substitution must not bypass hostname rules"
    );
}

#[test]
fn gate7_path_prefix_never_authorizes_opaque_tunnels() {
    let mut policy = SandboxPolicy::a3s_bash_baseline();
    policy.features.mediated_network = true;
    policy.features.mediated_socks = true;
    policy.network.allow.push(NetworkAllowRule {
        host: "api.example.com".into(),
        port: Some(443),
        path_prefix: Some("/v1".into()),
    });
    assert_eq!(
        decide_mediated_connect(&policy, "api.example.com", 443),
        AccessDecision::Deny
    );
    assert_eq!(
        decide_mediated_socks(&policy, "api.example.com", 443),
        AccessDecision::Deny
    );
}

#[test]
fn gate7_replace_policy_still_refuses_mediation_enablement() {
    let workspace = tempfile::tempdir().unwrap();
    let mut sandbox = NativeSandbox::new(workspace.path()).unwrap();
    let next = mediated_http_policy("api.example.com", 443);
    let error = sandbox
        .replace_policy(next, PolicyUpdateOptions::default())
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("broaden") || error.contains("allow_broadening"),
        "{error}"
    );
}

#[test]
fn gate7_capability_report_never_hides_unavailable_mediation() {
    let workspace = tempfile::tempdir().unwrap();
    let sandbox = NativeSandbox::new(workspace.path()).unwrap();
    let report = sandbox.capability_report();
    let caps = BackendCapabilities::native_gate2();
    if !caps.mediated_http {
        assert!(report.unavailable.contains(&"mediated_http"));
    }
    if !caps.mediated_socks {
        assert!(report.unavailable.contains(&"mediated_socks"));
    }
    if !caps.unix_socket_allowlist {
        assert!(report.unavailable.contains(&"unix_socket_allowlist"));
    }
}

#[test]
fn gate7_narrowing_then_rebroadening_requires_opt_in_each_time() {
    let mut tight = SandboxPolicy::a3s_bash_baseline();
    tight.resources.timeout_ms = 5_000;
    let mut wider = tight.clone();
    wider.resources.timeout_ms = 10_000;
    ensure_policy_not_broader(&wider, &tight).unwrap();
    let error = ensure_policy_not_broader(&tight, &wider)
        .unwrap_err()
        .to_string();
    assert!(error.contains("timeout_ms"), "{error}");
}

#[tokio::test]
async fn gate7_connect_mediator_rejects_non_connect_method() {
    use crate::ConnectMediator;
    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let mediator = ConnectMediator::bind(mediated_http_policy("127.0.0.1", 9))
        .await
        .unwrap();
    let mut client = TcpStream::connect(mediator.listen_addr()).await.unwrap();
    client
        .write_all(b"GET http://127.0.0.1:9/ HTTP/1.1\r\nHost: 127.0.0.1:9\r\n\r\n")
        .await
        .unwrap();
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(
        std::time::Duration::from_millis(500),
        client.read_to_end(&mut buf),
    )
    .await;
    let body = String::from_utf8_lossy(&buf);
    assert!(
        !body.starts_with("HTTP/1.1 200"),
        "non-CONNECT must not establish a tunnel: {body:?}"
    );
    // Ensure bind stayed loopback-only.
    assert_eq!(
        mediator.listen_addr().ip(),
        SocketAddr::from(([127, 0, 0, 1], 0)).ip()
    );
    mediator.shutdown().await;
}

#[tokio::test]
async fn gate7_socks_mediator_rejects_bind_command() {
    use crate::Socks5Mediator;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let mediator = Socks5Mediator::bind(mediated_socks_policy("127.0.0.1", 9))
        .await
        .unwrap();
    let mut client = TcpStream::connect(mediator.listen_addr()).await.unwrap();
    client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut method = [0u8; 2];
    client.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [0x05, 0x00]);

    // CMD=0x02 BIND to 127.0.0.1:9
    let host = b"127.0.0.1";
    let mut request = vec![0x05, 0x02, 0x00, 0x03, host.len() as u8];
    request.extend_from_slice(host);
    request.extend_from_slice(&9u16.to_be_bytes());
    client.write_all(&request).await.unwrap();
    let mut reply = [0u8; 10];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(
        reply[1], 0x07,
        "BIND must be command-not-supported: {reply:?}"
    );
    mediator.shutdown().await;
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn gate7_macos_explicit_no_proxy_cannot_bypass_mediator_fence() {
    use crate::CommandRequest;
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let upstream = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .unwrap();
    let upstream_port = upstream.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.unwrap();
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await.unwrap();
        stream.write_all(b"pong").await.unwrap();
    });

    let workspace = tempfile::tempdir().unwrap();
    let policy = mediated_http_policy("127.0.0.1", upstream_port);
    let sandbox = NativeSandbox::with_policy(workspace.path(), policy).unwrap();

    // Guest tries to bypass via NO_PROXY / custom proxy env; child_environment
    // must scrub and force empty NO_PROXY + host mediator only.
    let mut env = HashMap::new();
    env.insert("NO_PROXY".into(), "*".into());
    env.insert("no_proxy".into(), "127.0.0.1,localhost".into());
    env.insert("HTTPS_PROXY".into(), "http://evil.example:9".into());

    let script = format!(
        r#"python3 - <<'PY'
import os, socket
assert os.environ.get("NO_PROXY", "") == "", os.environ.get("NO_PROXY")
assert os.environ.get("no_proxy", "") == "", os.environ.get("no_proxy")
proxy = os.environ["HTTPS_PROXY"]
assert proxy.startswith("http://127.0.0.1:"), proxy
port = int(proxy.rsplit(":", 1)[-1])
s = socket.create_connection(("127.0.0.1", port))
s.sendall(b"CONNECT 127.0.0.1:{upstream_port} HTTP/1.1\r\n\r\n")
data = b""
while b"\r\n\r\n" not in data:
    chunk = s.recv(1)
    assert chunk, "closed"
    data += chunk
assert data.startswith(b"HTTP/1.1 200"), data
s.sendall(b"ping")
assert s.recv(4) == b"pong"
# Direct outbound to a non-mediator port must remain OS-denied.
bad = socket.socket()
bad.settimeout(0.5)
try:
    bad.connect(("1.1.1.1", 443))
    raise SystemExit("direct egress unexpectedly allowed")
except OSError:
    pass
finally:
    bad.close()
print("gate7-no-bypass")
PY"#
    );

    let output = sandbox
        .execute(CommandRequest {
            command: script,
            timeout_ms: 30_000,
            output_observer: None,
            env: Some(Arc::new(env)),
        })
        .await
        .unwrap();
    assert!(
        output.stdout.contains("gate7-no-bypass"),
        "stdout={} stderr={} exit={}",
        output.stdout,
        output.stderr,
        output.exit_code
    );
}

#[test]
fn gate7_policy_validate_rejects_malformed_network_hosts() {
    let malformed = [
        "",
        "evil example.com",
        "evil/example.com",
        r"evil\example.com",
        "host with spaces",
    ];
    for host in malformed {
        let mut policy = SandboxPolicy::a3s_bash_baseline();
        policy.features.mediated_network = true;
        policy.network.allow.push(NetworkAllowRule {
            host: host.into(),
            port: Some(443),
            path_prefix: None,
        });
        let error = policy.validate().unwrap_err().to_string();
        assert!(
            error.contains("host") || error.contains("invalid"),
            "host={host:?} error={error}"
        );
    }
}

#[test]
fn gate7_policy_validate_rejects_zero_resource_ceilings() {
    let mut policy = SandboxPolicy::a3s_bash_baseline();
    policy.resources.max_output_bytes = 0;
    assert!(policy
        .validate()
        .unwrap_err()
        .to_string()
        .contains("max_output_bytes"));
    policy.resources.max_output_bytes = 1024;
    policy.resources.timeout_ms = 0;
    assert!(policy
        .validate()
        .unwrap_err()
        .to_string()
        .contains("timeout_ms"));
}

#[cfg(unix)]
#[tokio::test]
async fn gate7_tocu_symlink_planted_between_executes_does_not_leak_outside_secret() {
    use crate::CommandRequest;
    use std::os::unix::fs::symlink;

    let workspace = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let secret = outside.path().join("secret");
    std::fs::write(&secret, "outside-secret-tocu").unwrap();
    let decoy = workspace.path().join("decoy.txt");
    std::fs::write(&decoy, "ordinary").unwrap();

    let sandbox = NativeSandbox::new(workspace.path()).unwrap();
    let first = sandbox
        .execute(CommandRequest {
            command: "cat decoy.txt".into(),
            timeout_ms: 5_000,
            output_observer: None,
            env: None,
        })
        .await
        .unwrap();
    assert!(
        first.stdout.contains("ordinary"),
        "stdout={} stderr={}",
        first.stdout,
        first.stderr
    );

    // Classic TOCTOU: replace the ordinary path with a symlink to an outside secret
    // after the session is live. The next execute must recompile and fail closed.
    std::fs::remove_file(&decoy).unwrap();
    symlink(&secret, &decoy).unwrap();

    let second = sandbox
        .execute(CommandRequest {
            command: "cat decoy.txt".into(),
            timeout_ms: 5_000,
            output_observer: None,
            env: None,
        })
        .await
        .unwrap();
    assert!(
        !second.stdout.contains("outside-secret-tocu"),
        "TOCTOU symlink read leaked outside secret: stdout={} stderr={} exit={}",
        second.stdout,
        second.stderr,
        second.exit_code
    );
    assert_ne!(
        second.exit_code, 0,
        "TOCTOU symlink read unexpectedly succeeded"
    );
    assert_eq!(
        std::fs::read_to_string(&secret).unwrap(),
        "outside-secret-tocu"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn gate7_direct_symlink_to_outside_file_does_not_leak_on_read() {
    use crate::CommandRequest;
    use std::os::unix::fs::symlink;

    let workspace = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let secret = outside.path().join("secret");
    std::fs::write(&secret, "outside-secret-direct").unwrap();
    symlink(&secret, workspace.path().join("alias")).unwrap();

    let sandbox = NativeSandbox::new(workspace.path()).unwrap();
    let output = sandbox
        .execute(CommandRequest {
            command: "cat alias".into(),
            timeout_ms: 5_000,
            output_observer: None,
            env: None,
        })
        .await
        .unwrap();
    assert!(
        !output.stdout.contains("outside-secret-direct"),
        "direct symlink read leaked: stdout={} stderr={} exit={}",
        output.stdout,
        output.stderr,
        output.exit_code
    );
    assert_ne!(
        output.exit_code, 0,
        "direct symlink read unexpectedly succeeded"
    );
}

/// In-command race: while a guest sleeps before reading, swap the path for a
/// symlink to an outside secret. The OS fence must still deny the leak.
#[cfg(unix)]
#[tokio::test]
async fn gate7_in_command_symlink_swap_during_sleep_does_not_leak() {
    use crate::CommandRequest;
    use std::os::unix::fs::symlink;

    let workspace = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let secret = outside.path().join("secret");
    std::fs::write(&secret, "outside-secret-race").unwrap();
    let decoy = workspace.path().join("race.txt");
    std::fs::write(&decoy, "ordinary-race").unwrap();

    let sandbox = NativeSandbox::new(workspace.path()).unwrap();
    let exec = sandbox.execute(CommandRequest {
        command: "sleep 0.4; cat race.txt".into(),
        timeout_ms: 10_000,
        output_observer: None,
        env: None,
    });

    let plant = async {
        tokio::time::sleep(std::time::Duration::from_millis(80)).await;
        let _ = std::fs::remove_file(&decoy);
        symlink(&secret, &decoy).expect("plant race symlink");
    };

    let (output, _) = tokio::join!(exec, plant);
    let output = output.expect("in-command race execute");
    assert!(
        !output.stdout.contains("outside-secret-race"),
        "in-command symlink race leaked secret: stdout={} stderr={} exit={}",
        output.stdout,
        output.stderr,
        output.exit_code
    );
    // Either denied (non-zero) or still saw the pre-swap ordinary bytes.
    if output.exit_code == 0 {
        assert!(
            output.stdout.contains("ordinary-race"),
            "unexpected success payload: {}",
            output.stdout
        );
    }
    assert_eq!(
        std::fs::read_to_string(&secret).unwrap(),
        "outside-secret-race"
    );
}

/// Same-workspace concurrent executes must serialize without cross-talk even
/// when one command is slow enough to overlap the next schedule attempt.
#[tokio::test]
async fn gate7_same_workspace_overlapping_executes_stay_isolated() {
    use crate::CommandRequest;

    let workspace = tempfile::tempdir().unwrap();
    let left = NativeSandbox::new(workspace.path()).unwrap();
    let right = NativeSandbox::new(workspace.path()).unwrap();

    #[cfg(windows)]
    let (slow, fast) = (
        "Start-Sleep -Milliseconds 300; [Console]::Out.Write('slow-done')",
        "[Console]::Out.Write('fast-done')",
    );
    #[cfg(not(windows))]
    let (slow, fast) = ("sleep 0.3; printf %s slow-done", "printf %s fast-done");

    let (slow_out, fast_out) = tokio::join!(
        left.execute(CommandRequest {
            command: slow.into(),
            timeout_ms: 15_000,
            output_observer: None,
            env: None,
        }),
        async {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            right
                .execute(CommandRequest {
                    command: fast.into(),
                    timeout_ms: 15_000,
                    output_observer: None,
                    env: None,
                })
                .await
        }
    );

    let slow_out = slow_out.expect("slow execute");
    let fast_out = fast_out.expect("fast execute");
    assert_eq!(slow_out.exit_code, 0, "stderr={}", slow_out.stderr);
    assert_eq!(fast_out.exit_code, 0, "stderr={}", fast_out.stderr);
    assert!(
        slow_out.stdout.contains("slow-done"),
        "slow stdout={}",
        slow_out.stdout
    );
    assert!(
        fast_out.stdout.contains("fast-done"),
        "fast stdout={}",
        fast_out.stdout
    );
    assert!(
        !slow_out.stdout.contains("fast-done") && !fast_out.stdout.contains("slow-done"),
        "overlapping same-workspace executes mixed streams: slow={:?} fast={:?}",
        slow_out.stdout,
        fast_out.stdout
    );
}

#[tokio::test]
async fn gate7_soak_repeated_baseline_executes_stay_stable() {
    use crate::CommandRequest;

    let workspace = tempfile::tempdir().unwrap();
    let sandbox = NativeSandbox::new(workspace.path()).unwrap();
    #[cfg(windows)]
    let command = "[Console]::Out.Write('soak-ok')";
    #[cfg(not(windows))]
    let command = "printf %s soak-ok";

    // Default 64 for CI. Longer multi-hour soaks: GATE7_SOAK_ROUNDS=10000 cargo test ...
    let rounds = std::env::var("GATE7_SOAK_ROUNDS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(64)
        .clamp(1, 100_000);

    for round in 0..rounds {
        let output = sandbox
            .execute(CommandRequest {
                command: command.into(),
                timeout_ms: 10_000,
                output_observer: None,
                env: None,
            })
            .await
            .unwrap_or_else(|error| panic!("soak round {round} failed: {error:#}"));
        assert_eq!(
            output.exit_code, 0,
            "round={round} stderr={}",
            output.stderr
        );
        assert!(
            output.stdout.contains("soak-ok"),
            "round={round} stdout={}",
            output.stdout
        );
    }
}

#[tokio::test]
async fn gate7_benchmark_baseline_exec_p50_under_budget() {
    use crate::CommandRequest;
    use std::time::Instant;

    let workspace = tempfile::tempdir().unwrap();
    let sandbox = NativeSandbox::new(workspace.path()).unwrap();
    #[cfg(windows)]
    let command = "[Console]::Out.Write('bench')";
    #[cfg(not(windows))]
    let command = "printf %s bench";

    // Warmup.
    for _ in 0..2 {
        let _ = sandbox
            .execute(CommandRequest {
                command: command.into(),
                timeout_ms: 10_000,
                output_observer: None,
                env: None,
            })
            .await
            .unwrap();
    }

    let mut samples = Vec::with_capacity(12);
    for _ in 0..12 {
        let started = Instant::now();
        let output = sandbox
            .execute(CommandRequest {
                command: command.into(),
                timeout_ms: 10_000,
                output_observer: None,
                env: None,
            })
            .await
            .unwrap();
        assert_eq!(output.exit_code, 0, "stderr={}", output.stderr);
        samples.push(started.elapsed());
    }
    samples.sort();
    let p50 = samples[samples.len() / 2];
    // Loose ceiling: catches pathological regressions, not a marketing number.
    assert!(
        p50.as_secs() < 5,
        "baseline exec p50 too slow: {p50:?} samples={samples:?}"
    );
}

#[tokio::test]
async fn gate7_soak_same_workspace_concurrent_sessions_keep_outputs_distinct() {
    use crate::CommandRequest;

    let workspace = tempfile::tempdir().unwrap();
    let left = NativeSandbox::new(workspace.path()).unwrap();
    let mid = NativeSandbox::new(workspace.path()).unwrap();
    let right = NativeSandbox::new(workspace.path()).unwrap();

    #[cfg(windows)]
    let (left_cmd, mid_cmd, right_cmd) = (
        "[Console]::Out.Write('alpha')",
        "[Console]::Out.Write('bravo')",
        "[Console]::Out.Write('charlie')",
    );
    #[cfg(not(windows))]
    let (left_cmd, mid_cmd, right_cmd) =
        ("printf %s alpha", "printf %s bravo", "printf %s charlie");

    let (left_out, mid_out, right_out) = tokio::join!(
        left.execute(CommandRequest {
            command: left_cmd.into(),
            timeout_ms: 15_000,
            output_observer: None,
            env: None,
        }),
        mid.execute(CommandRequest {
            command: mid_cmd.into(),
            timeout_ms: 15_000,
            output_observer: None,
            env: None,
        }),
        right.execute(CommandRequest {
            command: right_cmd.into(),
            timeout_ms: 15_000,
            output_observer: None,
            env: None,
        }),
    );

    let mut bodies = [left_out.unwrap(), mid_out.unwrap(), right_out.unwrap()]
        .into_iter()
        .map(|output| {
            assert_eq!(output.exit_code, 0, "stderr={}", output.stderr);
            output.stdout
        })
        .collect::<Vec<_>>();
    bodies.sort();
    assert_eq!(
        bodies,
        vec![
            String::from("alpha"),
            String::from("bravo"),
            String::from("charlie")
        ]
    );
}

#[tokio::test]
async fn gate7_benchmark_connect_mediator_allow_p50_under_budget() {
    use crate::ConnectMediator;
    use std::time::Instant;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    if !BackendCapabilities::native_gate2().mediated_http {
        return;
    }

    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_port = upstream.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = upstream.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 4];
                let _ = sock.read_exact(&mut buf).await;
                let _ = sock.write_all(b"pong").await;
            });
        }
    });

    let mediator = ConnectMediator::bind(mediated_http_policy("127.0.0.1", upstream_port))
        .await
        .unwrap();
    let addr = mediator.listen_addr();

    let mut samples = Vec::with_capacity(20);
    for _ in 0..20 {
        let started = Instant::now();
        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        client
            .write_all(
                format!("CONNECT 127.0.0.1:{upstream_port} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .unwrap();
        let mut header = [0u8; 64];
        let n = client.read(&mut header).await.unwrap();
        assert!(
            std::str::from_utf8(&header[..n])
                .unwrap_or("")
                .contains("200"),
            "CONNECT failed: {:?}",
            &header[..n]
        );
        client.write_all(b"ping").await.unwrap();
        let mut body = [0u8; 4];
        client.read_exact(&mut body).await.unwrap();
        assert_eq!(&body, b"pong");
        samples.push(started.elapsed());
    }
    samples.sort();
    let p50 = samples[samples.len() / 2];
    assert!(
        p50.as_millis() < 2_000,
        "CONNECT mediator allow p50 too slow: {p50:?} samples={samples:?}"
    );
    mediator.shutdown().await;
}
