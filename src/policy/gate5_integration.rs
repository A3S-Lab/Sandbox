//! Gate 5: Unix-domain socket allowlists and SOCKS5 mediation.

use crate::policy::{BackendCapabilities, NetworkAllowRule, PathRule, SandboxPolicy};
#[cfg(target_os = "macos")]
use crate::NativeSandbox;

#[test]
fn gate5_unix_socket_allowlist_capability_is_platform_scoped() {
    let caps = BackendCapabilities::native_gate2();
    assert_eq!(
        caps.unix_socket_allowlist,
        cfg!(target_os = "macos"),
        "only claim Unix-socket allowlists where Seatbelt can fence them"
    );
}

#[test]
fn gate5_mediated_socks_capability_is_platform_scoped() {
    let caps = BackendCapabilities::native_gate2();
    assert_eq!(
        caps.mediated_socks,
        cfg!(any(target_os = "macos", target_os = "linux")),
        "SOCKS5 mediation is claimed only where a live fence exists: macOS \
         Seatbelt loopback and the Linux netns + Unix SOCKS mediator bridge"
    );
}

#[cfg(not(target_os = "macos"))]
#[test]
fn gate5_non_macos_refuses_unix_socket_allow_rules() {
    let mut policy = SandboxPolicy::a3s_bash_baseline();
    policy
        .sockets
        .allow_unix
        .push(PathRule::Exact("/tmp/a3s-gate5.sock".into()));
    let error = policy
        .validate_for_backend(BackendCapabilities::native_gate2())
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("unix socket") || error.contains("fail closed"),
        "{error}"
    );
}

#[cfg(not(target_os = "macos"))]
#[test]
fn gate5_non_macos_refuses_mediated_socks() {
    // Linux now claims mediated_socks via the netns + Unix SOCKS mediator
    // bridge (Gate 9 slice 1), so only platforms without a live fence —
    // Windows — must still refuse the feature at policy validation.
    let mut policy = SandboxPolicy::a3s_bash_baseline();
    policy.features.mediated_socks = true;
    policy.network.allow.push(NetworkAllowRule {
        host: "example.com".into(),
        port: Some(443),
        path_prefix: None,
    });
    if cfg!(target_os = "linux") {
        policy
            .validate_for_backend(BackendCapabilities::native_gate2())
            .expect("Linux accepts mediated SOCKS after live wire proof");
        return;
    }
    let error = policy
        .validate_for_backend(BackendCapabilities::native_gate2())
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("mediated_socks") || error.contains("fail closed"),
        "{error}"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn gate5_macos_accepts_exact_unix_socket_allow_rules() {
    let mut policy = SandboxPolicy::a3s_bash_baseline();
    policy
        .sockets
        .allow_unix
        .push(PathRule::Exact("/tmp/a3s-gate5.sock".into()));
    policy
        .validate_for_backend(BackendCapabilities::native_gate2())
        .expect("macOS claims unix_socket_allowlist");
}

#[cfg(target_os = "macos")]
#[test]
fn gate5_macos_accepts_mediated_socks_capability() {
    let mut policy = SandboxPolicy::a3s_bash_baseline();
    policy.features.mediated_socks = true;
    policy.network.allow.push(NetworkAllowRule {
        host: "api.example.com".into(),
        port: Some(443),
        path_prefix: None,
    });
    policy
        .validate_for_backend(BackendCapabilities::native_gate2())
        .expect("macOS claims mediated_socks with Seatbelt loopback fence");
}

#[tokio::test]
async fn gate5_socks_mediator_allow_and_deny_integration() {
    use crate::Socks5Mediator;
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
    policy.features.mediated_socks = true;
    policy.network.allow.push(NetworkAllowRule {
        host: "127.0.0.1".into(),
        port: Some(upstream_port),
        path_prefix: None,
    });
    let mediator = Socks5Mediator::bind(policy).await.unwrap();

    let mut client = TcpStream::connect(mediator.listen_addr()).await.unwrap();
    client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut method = [0u8; 2];
    client.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [0x05, 0x00]);

    let host = b"127.0.0.1";
    let mut request = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    request.extend_from_slice(host);
    request.extend_from_slice(&upstream_port.to_be_bytes());
    client.write_all(&request).await.unwrap();

    let mut reply = [0u8; 10];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0x00, "reply={reply:?}");

    client.write_all(b"abc").await.unwrap();
    let mut body = [0u8; 2];
    client.read_exact(&mut body).await.unwrap();
    assert_eq!(&body, b"ok");
    mediator.shutdown().await;
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn gate5_macos_allows_listed_unix_socket_and_denies_others() {
    use crate::CommandRequest;
    use std::os::unix::net::UnixListener;

    let scratch = tempfile::tempdir().unwrap();
    let allowed = scratch.path().join("allowed.sock");
    let denied = scratch.path().join("denied.sock");
    let _allowed_listener = UnixListener::bind(&allowed).unwrap();
    let _denied_listener = UnixListener::bind(&denied).unwrap();

    let workspace = tempfile::tempdir().unwrap();
    let mut policy = SandboxPolicy::a3s_bash_baseline();
    policy.sockets.allow_unix.push(PathRule::Exact(
        allowed
            .canonicalize()
            .unwrap()
            .to_string_lossy()
            .into_owned(),
    ));
    // Scratch must be readable so the guest can open the socket path under it.
    // Session scratch is already writable; host tempfile path needs an RO mount.
    policy
        .filesystem
        .mounts
        .push(crate::policy::FilesystemMount {
            root: PathRule::Exact(
                scratch
                    .path()
                    .canonicalize()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned(),
            ),
            mode: crate::policy::MountMode::ReadOnly,
        });
    let sandbox = NativeSandbox::with_policy(workspace.path(), policy).unwrap();

    let allowed_display = allowed.canonicalize().unwrap().display().to_string();
    let denied_display = denied.canonicalize().unwrap().display().to_string();
    let script = format!(
        r#"python3 - <<'PY'
import socket, sys
allowed = {allowed_display:?}
denied = {denied_display:?}

def try_connect(path):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.connect(path)
        return True
    except Exception:
        return False
    finally:
        s.close()

ok = try_connect(allowed)
bad = try_connect(denied)
print(f"allowed={{ok}} denied={{bad}}")
sys.exit(0 if ok and not bad else 1)
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
        output.stdout.contains("allowed=True") && output.stdout.contains("denied=False"),
        "stdout={} stderr={} exit={}",
        output.stdout,
        output.stderr,
        output.exit_code
    );
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn gate5_macos_sandbox_socks_tunnels_allowed_connect() {
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
    policy.features.mediated_socks = true;
    policy.network.allow.push(NetworkAllowRule {
        host: "127.0.0.1".into(),
        port: Some(upstream_port),
        path_prefix: None,
    });
    let sandbox = NativeSandbox::with_policy(workspace.path(), policy).unwrap();

    let script = format!(
        r#"python3 - <<'PY'
import os, socket, struct
proxy = os.environ["ALL_PROXY"]
assert proxy.startswith("socks5://"), proxy
port = int(proxy.rsplit(":", 1)[-1])
s = socket.create_connection(("127.0.0.1", port))
s.sendall(b"\x05\x01\x00")
assert s.recv(2) == b"\x05\x00"
host = b"127.0.0.1"
req = b"\x05\x01\x00\x03" + bytes([len(host)]) + host + struct.pack("!H", {upstream_port})
s.sendall(req)
reply = s.recv(10)
assert reply[1] == 0, reply
s.sendall(b"ping")
assert s.recv(4) == b"pong"
print("gate5-socks-ok")
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
        output.stdout.contains("gate5-socks-ok"),
        "stdout={} stderr={} exit={}",
        output.stdout,
        output.stderr,
        output.exit_code
    );
}
