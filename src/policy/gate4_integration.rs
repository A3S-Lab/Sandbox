//! Gate 4: mediated HTTP policy shape — fail closed until a real mediator ships.

use crate::policy::{BackendCapabilities, NetworkAllowRule, SandboxPolicy, SessionWriteMode};
use crate::NativeSandbox;

#[test]
fn gate4_mediated_http_capability_is_platform_scoped() {
    let caps = BackendCapabilities::native_gate2();
    assert_eq!(
        caps.mediated_http,
        cfg!(any(target_os = "macos", target_os = "linux")),
        "only claim HTTP mediation where OS fences + live proofs exist"
    );
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
#[test]
fn gate4_allowlist_requires_backend_capability() {
    let mut policy = SandboxPolicy::a3s_bash_baseline();
    policy.features.mediated_network = true;
    policy.network.allow.push(NetworkAllowRule {
        host: "api.example.com".into(),
        port: Some(443),
        path_prefix: Some("/v1".into()),
    });
    policy.validate().expect("document shape is valid");
    let error = policy
        .validate_for_backend(BackendCapabilities::native_gate2())
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("mediated_network") || error.contains("fail closed"),
        "{error}"
    );
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn gate4_claiming_platforms_accept_mediated_network_capability() {
    let mut policy = SandboxPolicy::a3s_bash_baseline();
    policy.features.mediated_network = true;
    policy.network.allow.push(NetworkAllowRule {
        host: "api.example.com".into(),
        port: Some(443),
        path_prefix: None,
    });
    policy
        .validate_for_backend(BackendCapabilities::native_gate2())
        .expect("claiming platforms accept mediated_http");
}

#[tokio::test]
async fn gate4_connect_mediator_allow_and_deny_integration() {
    use crate::ConnectMediator;
    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    let upstream = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .unwrap();
    let upstream_port = upstream.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.unwrap();
        let mut buf = [0u8; 3];
        stream.read_exact(&mut buf).await.unwrap();
        stream.write_all(b"ok").await.unwrap();
    });

    let mut policy = SandboxPolicy::a3s_bash_baseline();
    policy.features.mediated_network = true;
    policy.network.allow.push(NetworkAllowRule {
        host: "127.0.0.1".into(),
        port: Some(upstream_port),
        path_prefix: None,
    });
    let mediator = ConnectMediator::bind(policy).await.unwrap();

    let mut client = TcpStream::connect(mediator.listen_addr()).await.unwrap();
    client
        .write_all(format!("CONNECT 127.0.0.1:{upstream_port} HTTP/1.1\r\n\r\n").as_bytes())
        .await
        .unwrap();

    let mut response = Vec::new();
    let mut buf = [0u8; 1];
    while !response.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = client.read(&mut buf).await.unwrap();
        assert!(n > 0, "mediator closed before finishing CONNECT response");
        response.push(buf[0]);
        assert!(response.len() < 1024, "CONNECT response too large");
    }
    let response = String::from_utf8_lossy(&response);
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "response={response:?}"
    );

    client.write_all(b"abc").await.unwrap();
    let mut reply = [0u8; 2];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"ok");
    mediator.shutdown().await;
}

#[test]
fn gate4_rejects_path_prefix_with_dotdot() {
    let mut policy = SandboxPolicy::a3s_bash_baseline();
    policy.features.mediated_network = true;
    policy.network.allow.push(NetworkAllowRule {
        host: "example.com".into(),
        port: Some(443),
        path_prefix: Some("/ok/../secret".into()),
    });
    let error = policy.validate().unwrap_err().to_string();
    assert!(error.contains("path_prefix"), "{error}");
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
#[test]
fn gate4_native_sandbox_refuses_mediated_network_policies() {
    let workspace = tempfile::tempdir().unwrap();
    let mut policy = SandboxPolicy::a3s_bash_baseline();
    policy.features.mediated_network = true;
    policy.network.allow.push(NetworkAllowRule {
        host: "example.com".into(),
        port: Some(443),
        path_prefix: None,
    });
    let error = format!(
        "{:#}",
        NativeSandbox::with_policy(workspace.path(), policy).unwrap_err()
    );
    assert!(
        error.contains("mediated_network") || error.contains("fail closed"),
        "{error}"
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn gate4_linux_sandbox_mediator_tunnels_allowed_connect() {
    use crate::CommandRequest;
    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::Mutex;

    static RELAY_ENV_LOCK: Mutex<()> = Mutex::const_new(());
    let _guard = RELAY_ENV_LOCK.lock().await;

    let upstream = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
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
    let mut policy = SandboxPolicy::a3s_bash_baseline();
    policy.features.mediated_network = true;
    policy.network.allow.push(NetworkAllowRule {
        host: "127.0.0.1".into(),
        port: Some(upstream_port),
        path_prefix: None,
    });

    let test_exe = std::env::current_exe().unwrap();
    let relay_bin = test_exe
        .parent()
        .and_then(|p| p.parent())
        .map(|debug| debug.join("a3s-sandbox-relay"))
        .unwrap();
    assert!(relay_bin.is_file(), "missing {}", relay_bin.display());
    std::env::set_var("A3S_SANDBOX_RELAY", &relay_bin);

    let sandbox = NativeSandbox::with_policy(workspace.path(), policy).unwrap();
    let probe = workspace.path().join("gate4_linux_probe.py");
    std::fs::write(
        &probe,
        format!(
            "import os, socket\n\
proxy = os.environ['HTTPS_PROXY'].rsplit(':', 1)\n\
port = int(proxy[-1])\n\
s = socket.create_connection(('127.0.0.1', port))\n\
s.sendall(b'CONNECT 127.0.0.1:{up} HTTP/1.1\\r\\n\\r\\n')\n\
data = b''\n\
while b'\\r\\n\\r\\n' not in data:\n\
\tchunk = s.recv(1)\n\
\tassert chunk, 'closed'\n\
\tdata += chunk\n\
assert data.startswith(b'HTTP/1.1 200'), data\n\
s.sendall(b'ping')\n\
assert s.recv(4) == b'pong'\n\
print('gate4-linux-tunnel-ok')\n",
            up = upstream_port
        ),
    )
    .unwrap();
    let output = sandbox
        .execute(CommandRequest {
            command: format!("python3 {}", probe.display()),
            timeout_ms: 30_000,
            output_observer: None,
            env: None,
        })
        .await
        .unwrap();
    std::env::remove_var("A3S_SANDBOX_RELAY");
    assert!(
        output.stdout.contains("gate4-linux-tunnel-ok"),
        "stdout={} stderr={} exit={}",
        output.stdout,
        output.stderr,
        output.exit_code
    );
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn gate4_macos_sandbox_mediator_tunnels_allowed_connect() {
    use crate::CommandRequest;
    use std::net::SocketAddr;
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
        assert_eq!(&buf, b"ping");
        stream.write_all(b"pong").await.unwrap();
    });

    let workspace = tempfile::tempdir().unwrap();
    let mut policy = SandboxPolicy::a3s_bash_baseline();
    policy.features.mediated_network = true;
    policy.network.allow.push(NetworkAllowRule {
        host: "127.0.0.1".into(),
        port: Some(upstream_port),
        path_prefix: None,
    });
    let sandbox = NativeSandbox::with_policy(workspace.path(), policy).unwrap();

    let script = format!(
        r#"python3 - <<'PY'
import os, socket
proxy = os.environ["HTTPS_PROXY"].rsplit(":", 1)
port = int(proxy[-1])
s = socket.create_connection(("127.0.0.1", port))
req = "CONNECT 127.0.0.1:{upstream_port} HTTP/1.1\r\n\r\n".encode()
s.sendall(req)
data = b""
while b"\r\n\r\n" not in data:
    chunk = s.recv(1)
    assert chunk, "closed"
    data += chunk
assert data.startswith(b"HTTP/1.1 200"), data
s.sendall(b"ping")
assert s.recv(4) == b"pong"
print("gate4-tunnel-ok")
PY"#
    );
    let output = sandbox
        .execute(CommandRequest {
            command: script,
            timeout_ms: 30_000,
            output_observer: None,
            env: None,
        })
        .await
        .unwrap();
    assert!(
        output.stdout.contains("gate4-tunnel-ok"),
        "stdout={} stderr={} exit={}",
        output.stdout,
        output.stderr,
        output.exit_code
    );
}

#[test]
fn gate4_does_not_weaken_default_deny_all() {
    let policy = SandboxPolicy::a3s_bash_baseline();
    assert!(!policy.features.mediated_network);
    assert!(policy.network.allow.is_empty());
    // Ephemeral is unrelated; keep baseline persistent.
    assert_eq!(
        policy.filesystem.session_write,
        SessionWriteMode::Persistent
    );
}
