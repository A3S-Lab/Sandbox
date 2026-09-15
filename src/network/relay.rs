//! Guest-side TCP→Unix relay for Linux netns mediation bridges.
//!
//! Inside an unshared network namespace the guest has only loopback. The host
//! CONNECT mediator listens on a Unix socket bind-mounted into the guest.
//! This relay accepts TCP on guest loopback and forwards bytes to that Unix
//! socket so ordinary `HTTP_PROXY=http://127.0.0.1:PORT` clients work without
//! teaching every tool about AF_UNIX CONNECT.
//!
//! This module is a building block only. Claiming `mediated_http` on Linux
//! also requires live OS fencing (`--unshare-net`, lo up, seccomp that still
//! blocks escape) plus an end-to-end guest test.

use anyhow::{bail, Context, Result};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

/// Fixed guest TCP port for HTTP CONNECT → Unix mediator relay.
///
/// Injected as `HTTP_PROXY` / `HTTPS_PROXY` when the Linux bridge is armed.
pub const GUEST_HTTP_CONNECT_RELAY_PORT: u16 = 24731;

/// Running TCP→Unix byte relay.
pub struct TcpUnixRelayHandle {
    listen_addr: SocketAddr,
    shutdown: Option<oneshot::Sender<()>>,
    join: Option<JoinHandle<()>>,
}

impl TcpUnixRelayHandle {
    pub fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }

    pub async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(join) = self.join.take() {
            let _ = join.await;
        }
    }
}

impl Drop for TcpUnixRelayHandle {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
    }
}

/// Spawn a TCP listener that copies each accepted stream to `unix_path`.
pub struct TcpUnixRelay;

impl TcpUnixRelay {
    /// Bind `listen` and forward accepted TCP streams to `unix_path`.
    #[cfg(unix)]
    pub async fn bind(
        listen: SocketAddr,
        unix_path: impl AsRef<Path>,
    ) -> Result<TcpUnixRelayHandle> {
        let unix_path = unix_path.as_ref().to_path_buf();
        let listener = tokio::net::TcpListener::bind(listen)
            .await
            .with_context(|| format!("failed to bind TCP→Unix relay on {listen}"))?;
        let listen_addr = listener
            .local_addr()
            .context("failed to read TCP→Unix relay listen address")?;
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();

        let join = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => break,
                    accepted = listener.accept() => {
                        match accepted {
                            Ok((mut tcp, _)) => {
                                let path = unix_path.clone();
                                tokio::spawn(async move {
                                    if let Ok(mut unix) =
                                        tokio::net::UnixStream::connect(&path).await
                                    {
                                        let _ = tokio::io::copy_bidirectional(
                                            &mut tcp, &mut unix,
                                        )
                                        .await;
                                    }
                                });
                            }
                            Err(_) => break,
                        }
                    }
                }
            }
        });

        Ok(TcpUnixRelayHandle {
            listen_addr,
            shutdown: Some(shutdown_tx),
            join: Some(join),
        })
    }

    /// Bind and run until the process is stopped (CLI entrypoint).
    #[cfg(unix)]
    pub async fn run_forever(listen: SocketAddr, unix_path: PathBuf) -> Result<()> {
        let _handle = Self::bind(listen, unix_path).await?;
        std::future::pending::<()>().await;
        #[allow(unreachable_code)]
        Ok(())
    }

    #[cfg(not(unix))]
    pub async fn bind(
        _listen: SocketAddr,
        _unix_path: impl AsRef<Path>,
    ) -> Result<TcpUnixRelayHandle> {
        bail!("TCP→Unix relay requires a Unix platform");
    }

    #[cfg(not(unix))]
    pub async fn run_forever(_listen: SocketAddr, _unix_path: PathBuf) -> Result<()> {
        bail!("TCP→Unix relay requires a Unix platform");
    }
}

/// Resolve the guest TCP→Unix relay executable.
///
/// Order: `A3S_SANDBOX_RELAY` env, then `a3s-sandbox-relay` next to the
/// current executable. Linux mediation fails closed if neither is found.
pub fn resolve_relay_executable() -> Result<PathBuf> {
    if let Ok(path) = std::env::var("A3S_SANDBOX_RELAY") {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Ok(path);
        }
        bail!(
            "A3S_SANDBOX_RELAY points to missing relay binary {}",
            path.display()
        );
    }
    let exe = std::env::current_exe().context("failed to resolve current executable")?;
    let sibling = exe.with_file_name("a3s-sandbox-relay");
    if sibling.is_file() {
        return Ok(sibling);
    }
    bail!(
        "Linux mediation requires a3s-sandbox-relay next to {} or A3S_SANDBOX_RELAY",
        exe.display()
    );
}

/// Quote a string for POSIX `sh` single-quoted context.
pub fn posix_shell_single_quote(value: &str) -> String {
    let mut out = String::from("'");
    for ch in value.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

/// Copy the host relay binary into `scratch` so the guest can execute it.
///
/// Linux bwrap masks `$HOME` / temp roots with tmpfs and only re-binds explicit
/// allow_read paths. The cargo `target/debug` tree is usually invisible inside
/// that mount namespace, so mediation must stage a guest-visible copy under
/// session scratch (which is always allow_read + allow_write).
pub fn stage_relay_into_scratch(scratch: &Path) -> Result<PathBuf> {
    let host = resolve_relay_executable()?;
    let guest = scratch.join("a3s-sandbox-relay");
    std::fs::copy(&host, &guest).with_context(|| {
        format!(
            "failed to stage relay {} into {}",
            host.display(),
            guest.display()
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&guest)
            .with_context(|| format!("failed to stat staged relay {}", guest.display()))?
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&guest, perms).with_context(|| {
            format!("failed to mark staged relay executable {}", guest.display())
        })?;
    }
    Ok(guest)
}

/// Wrap a guest command so the TCP→Unix CONNECT relay starts before it.
///
/// Brings loopback up inside an unshared netns, backgrounds the relay, and
/// tears it down on exit. `user_command` is interpolated as a shell fragment
/// (same contract as the outer `bash -c`).
///
/// `relay_bin` must be a path the guest can execute (typically the result of
/// [`stage_relay_into_scratch`]).
pub fn wrap_command_with_guest_relay(
    relay_bin: &Path,
    unix_socket: &Path,
    user_command: &str,
) -> Result<String> {
    if !relay_bin.is_file() {
        bail!(
            "guest CONNECT relay binary missing at {}",
            relay_bin.display()
        );
    }
    let relay_q = posix_shell_single_quote(&relay_bin.to_string_lossy());
    let sock_q = posix_shell_single_quote(&unix_socket.to_string_lossy());
    let listen = format!("127.0.0.1:{GUEST_HTTP_CONNECT_RELAY_PORT}");
    Ok(format!(
        "ip link set lo up 2>/dev/null || true; \
         {relay_q} --unix {sock_q} --listen {listen} & \
         _a3s_relay_pid=$!; \
         trap 'kill $_a3s_relay_pid 2>/dev/null || true' EXIT INT TERM; \
         {user_command}"
    ))
}

/// Default guest listen address for the HTTP CONNECT relay.
pub fn default_guest_relay_addr() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], GUEST_HTTP_CONNECT_RELAY_PORT))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::network::ConnectMediator;
    use crate::policy::{NetworkAllowRule, SandboxPolicy};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    fn origin_policy(host: &str, port: u16) -> SandboxPolicy {
        let mut policy = SandboxPolicy::a3s_bash_baseline();
        policy.features.mediated_network = true;
        policy.network.allow.push(NetworkAllowRule {
            host: host.into(),
            port: Some(port),
            path_prefix: None,
        });
        policy
    }

    #[tokio::test]
    async fn tcp_unix_relay_forwards_connect_to_unix_mediator() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("bridge.sock");

        let upstream = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_task = tokio::spawn(async move {
            let (mut stream, _) = upstream.accept().await.unwrap();
            let mut buf = [0u8; 5];
            stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"hello");
            stream.write_all(b"world").await.unwrap();
        });

        let mediator =
            ConnectMediator::bind_unix(origin_policy("127.0.0.1", upstream_addr.port()), &sock)
                .await
                .unwrap();

        let relay = TcpUnixRelay::bind(SocketAddr::from(([127, 0, 0, 1], 0)), &sock)
            .await
            .unwrap();

        let mut client = TcpStream::connect(relay.listen_addr()).await.unwrap();
        let request = format!(
            "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
            upstream_addr.port(),
            upstream_addr.port()
        );
        client.write_all(request.as_bytes()).await.unwrap();

        let mut response = [0u8; 64];
        let n = client.read(&mut response).await.unwrap();
        assert!(
            std::str::from_utf8(&response[..n])
                .unwrap()
                .starts_with("HTTP/1.1 200"),
            "response={:?}",
            std::str::from_utf8(&response[..n])
        );

        client.write_all(b"hello").await.unwrap();
        let mut reply = [0u8; 5];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"world");

        upstream_task.await.unwrap();
        relay.shutdown().await;
        mediator.shutdown().await;
    }

    #[tokio::test]
    async fn default_guest_relay_port_is_stable() {
        assert_eq!(GUEST_HTTP_CONNECT_RELAY_PORT, 24731);
        assert_eq!(default_guest_relay_addr().port(), 24731);
    }

    #[test]
    fn posix_shell_single_quote_escapes_apostrophes() {
        assert_eq!(posix_shell_single_quote("plain"), "'plain'");
        assert_eq!(posix_shell_single_quote("a'b"), "'a'\\''b'");
    }

    #[test]
    fn wrap_command_with_guest_relay_embeds_relay_and_socket() {
        let dir = tempfile::tempdir().unwrap();
        let relay = dir.path().join("a3s-sandbox-relay");
        std::fs::write(&relay, b"#!/bin/true\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&relay).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&relay, perms).unwrap();
        }
        let sock = dir.path().join("m.sock");
        let wrapped = wrap_command_with_guest_relay(&relay, &sock, "echo hi").unwrap();
        assert!(wrapped.contains("ip link set lo up"));
        assert!(wrapped.contains("--unix"));
        assert!(wrapped.contains("echo hi"));
        assert!(wrapped.contains(&format!("127.0.0.1:{GUEST_HTTP_CONNECT_RELAY_PORT}")));
    }

    #[test]
    fn stage_relay_into_scratch_copies_executable() {
        let dir = tempfile::tempdir().unwrap();
        let host = dir.path().join("host-relay");
        std::fs::write(&host, b"relay-bytes").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&host).unwrap().permissions();
            perms.set_mode(0o700);
            std::fs::set_permissions(&host, perms).unwrap();
        }
        std::env::set_var("A3S_SANDBOX_RELAY", &host);
        let scratch = tempfile::tempdir().unwrap();
        let staged = stage_relay_into_scratch(scratch.path()).unwrap();
        std::env::remove_var("A3S_SANDBOX_RELAY");
        assert_eq!(staged, scratch.path().join("a3s-sandbox-relay"));
        assert_eq!(std::fs::read(&staged).unwrap(), b"relay-bytes");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&staged).unwrap().permissions().mode() & 0o111,
                0o111
            );
        }
    }
}
