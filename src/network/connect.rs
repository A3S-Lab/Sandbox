//! Host-supervised HTTP CONNECT mediator.
//!
//! TCP bind listens on `127.0.0.1` only (macOS Seatbelt path). Unix bind is
//! for Linux netns bridges: the guest reaches the host mediator via a
//! bind-mounted socket and an in-guest TCP→Unix relay.
//!
//! Guests must be OS-fenced before `BackendCapabilities::mediated_http` may be
//! claimed. The mediator never broadens policy: denied CONNECT requests never
//! reach upstream.

use crate::policy::{decide_mediated_connect, AccessDecision, SandboxPolicy};
use anyhow::{bail, Context, Result};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

/// Running CONNECT mediator (TCP loopback, Unix path, and/or Windows named pipe).
pub struct ConnectMediatorHandle {
    addr: Option<SocketAddr>,
    unix_path: Option<PathBuf>,
    #[cfg(windows)]
    pipe_name: Option<String>,
    shutdown: Option<oneshot::Sender<()>>,
    join: Option<JoinHandle<()>>,
}

impl ConnectMediatorHandle {
    /// TCP listen address. Panics if this handle was bound with [`ConnectMediator::bind_unix`].
    pub fn listen_addr(&self) -> SocketAddr {
        self.addr
            .expect("ConnectMediatorHandle::listen_addr requires a TCP-bound mediator")
    }

    /// Unix socket path when bound with [`ConnectMediator::bind_unix`].
    pub fn unix_path(&self) -> Option<&Path> {
        self.unix_path.as_deref()
    }

    /// Named pipe path when bound with [`ConnectMediator::bind_named_pipe`].
    #[cfg(windows)]
    pub fn pipe_name(&self) -> Option<&str> {
        self.pipe_name.as_deref()
    }

    pub async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(join) = self.join.take() {
            let _ = join.await;
        }
        if let Some(path) = self.unix_path.take() {
            let _ = std::fs::remove_file(path);
        }
    }
}

impl Drop for ConnectMediatorHandle {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(path) = self.unix_path.take() {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// Spawn a host-supervised CONNECT proxy for `policy`.
pub struct ConnectMediator;

impl ConnectMediator {
    /// Bind on `127.0.0.1:0` (host loopback TCP).
    pub async fn bind(policy: SandboxPolicy) -> Result<ConnectMediatorHandle> {
        prepare_policy(&policy)?;
        let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .context("failed to bind CONNECT mediator on 127.0.0.1")?;
        let addr = listener
            .local_addr()
            .context("failed to read CONNECT mediator listen address")?;
        let policy = Arc::new(policy);
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();

        let join = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => break,
                    accepted = listener.accept() => {
                        match accepted {
                            Ok((stream, _)) => {
                                let policy = Arc::clone(&policy);
                                tokio::spawn(async move {
                                    let _ = handle_client(stream, policy).await;
                                });
                            }
                            Err(_) => break,
                        }
                    }
                }
            }
        });

        Ok(ConnectMediatorHandle {
            addr: Some(addr),
            unix_path: None,
            #[cfg(windows)]
            pipe_name: None,
            shutdown: Some(shutdown_tx),
            join: Some(join),
        })
    }

    /// Bind a Unix-domain CONNECT mediator at `path`.
    ///
    /// Used by the Linux netns bridge: the socket is created on the host and
    /// bind-mounted into the guest; an in-guest TCP relay forwards
    /// `HTTP_PROXY` CONNECT clients to this path.
    #[cfg(unix)]
    pub async fn bind_unix(
        policy: SandboxPolicy,
        path: impl AsRef<Path>,
    ) -> Result<ConnectMediatorHandle> {
        prepare_policy(&policy)?;
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("failed to create mediator socket dir {}", parent.display())
            })?;
        }
        let _ = std::fs::remove_file(&path);
        let listener = tokio::net::UnixListener::bind(&path).with_context(|| {
            format!(
                "failed to bind CONNECT mediator on unix socket {}",
                path.display()
            )
        })?;
        let policy = Arc::new(policy);
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
        let socket_path = path.clone();

        let join = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => break,
                    accepted = listener.accept() => {
                        match accepted {
                            Ok((stream, _)) => {
                                let policy = Arc::clone(&policy);
                                tokio::spawn(async move {
                                    let _ = handle_client(stream, policy).await;
                                });
                            }
                            Err(_) => break,
                        }
                    }
                }
            }
            let _ = std::fs::remove_file(socket_path);
        });

        Ok(ConnectMediatorHandle {
            addr: None,
            unix_path: Some(path),
            #[cfg(windows)]
            pipe_name: None,
            shutdown: Some(shutdown_tx),
            join: Some(join),
        })
    }

    /// Bind a Windows named-pipe CONNECT mediator.
    ///
    /// Foundation for the AppContainer bridge: the guest keeps zero network
    /// capabilities and speaks CONNECT over an ACL'd pipe. Calling this does
    /// **not** claim `mediated_http`; AppContainer SID ACL + live guest proof
    /// are still required before the capability flip.
    ///
    /// Prefer [`ConnectMediator::bind_named_pipe_acl`] for production wiring so
    /// every pipe instance keeps the AppContainer-only DACL.
    #[cfg(windows)]
    pub async fn bind_named_pipe(
        policy: SandboxPolicy,
        pipe_name: impl AsRef<str>,
    ) -> Result<ConnectMediatorHandle> {
        prepare_policy(&policy)?;
        let pipe_name = pipe_name.as_ref().to_string();
        if !pipe_name.starts_with(r"\\.\pipe\") {
            bail!("named pipe CONNECT mediator requires a \\\\.\\pipe\\... path");
        }
        let mut server = tokio::net::windows::named_pipe::ServerOptions::new()
            .first_pipe_instance(true)
            .create(&pipe_name)
            .with_context(|| format!("failed to create CONNECT named pipe {pipe_name}"))?;
        let policy = Arc::new(policy);
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
        let accept_name = pipe_name.clone();

        let join = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => break,
                    connected = server.connect() => {
                        if connected.is_err() {
                            break;
                        }
                        let client = server;
                        match tokio::net::windows::named_pipe::ServerOptions::new()
                            .create(&accept_name)
                        {
                            Ok(next) => server = next,
                            Err(_) => break,
                        }
                        let policy = Arc::clone(&policy);
                        tokio::spawn(async move {
                            let _ = handle_client(client, policy).await;
                        });
                    }
                }
            }
        });

        Ok(ConnectMediatorHandle {
            addr: None,
            unix_path: None,
            pipe_name: Some(pipe_name),
            shutdown: Some(shutdown_tx),
            join: Some(join),
        })
    }

    /// Bind a CONNECT mediator to an already-connected named-pipe server handle.
    ///
    /// Paired with `create_appcontainer_mediation_pipe`: the host opens the
    /// client end and inherits it into the AppContainer guest. Live guests
    /// cannot name-open the pipe (`ERROR_ACCESS_DENIED` on GHA even with
    /// package SID + Low IL DACLs).
    #[cfg(windows)]
    pub async fn bind_named_pipe_connected(
        policy: SandboxPolicy,
        pipe_name: impl AsRef<str>,
        server: std::os::windows::io::OwnedHandle,
    ) -> Result<ConnectMediatorHandle> {
        use std::os::windows::io::IntoRawHandle;
        use tokio::net::windows::named_pipe::NamedPipeServer;

        prepare_policy(&policy)?;
        let pipe_name = pipe_name.as_ref().to_string();
        if !pipe_name.starts_with(r"\\.\pipe\") {
            bail!("named pipe CONNECT mediator requires a \\\\.\\pipe\\... path");
        }

        let raw = server.into_raw_handle();
        // SAFETY: CreateNamedPipeW duplex overlapped server with a connected client.
        let server = unsafe { NamedPipeServer::from_raw_handle(raw) }
            .context("failed to wrap connected AppContainer named pipe as Tokio server")?;
        server
            .connect()
            .await
            .context("failed to finalize connected AppContainer named pipe")?;

        let policy = Arc::new(policy);
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
        let join = tokio::spawn(async move {
            tokio::select! {
                _ = &mut shutdown_rx => {}
                _ = handle_client(server, policy) => {}
            }
        });

        Ok(ConnectMediatorHandle {
            addr: None,
            unix_path: None,
            pipe_name: Some(pipe_name),
            shutdown: Some(shutdown_tx),
            join: Some(join),
        })
    }

    /// Bind a CONNECT mediator whose every pipe instance is created by `create_next`.
    ///
    /// Prefer [`Self::bind_named_pipe_connected`] for live AppContainer guests.
    /// Use with `PlatformSandbox::mediator_named_pipe_factory` for accept-loop
    /// name-open clients. Fail closed if a later instance cannot be created.
    #[cfg(windows)]
    pub async fn bind_named_pipe_acl<F>(
        policy: SandboxPolicy,
        pipe_name: impl AsRef<str>,
        mut create_next: F,
    ) -> Result<ConnectMediatorHandle>
    where
        F: FnMut() -> Result<std::os::windows::io::OwnedHandle> + Send + 'static,
    {
        use std::os::windows::io::IntoRawHandle;
        use tokio::net::windows::named_pipe::NamedPipeServer;

        prepare_policy(&policy)?;
        let pipe_name = pipe_name.as_ref().to_string();
        if !pipe_name.starts_with(r"\\.\pipe\") {
            bail!("named pipe CONNECT mediator requires a \\\\.\\pipe\\... path");
        }

        fn server_from_owned(handle: std::os::windows::io::OwnedHandle) -> Result<NamedPipeServer> {
            let raw = handle.into_raw_handle();
            // SAFETY: handle is a CreateNamedPipeW duplex overlapped server pipe.
            unsafe { NamedPipeServer::from_raw_handle(raw) }
                .context("failed to wrap AppContainer named pipe as Tokio server")
        }

        let mut server = server_from_owned(
            create_next()
                .context("failed to create first AppContainer-ACL'd CONNECT named pipe")?,
        )?;
        let policy = Arc::new(policy);
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();

        let join = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => break,
                    connected = server.connect() => {
                        if connected.is_err() {
                            break;
                        }
                        let client = server;
                        match create_next() {
                            Ok(next_handle) => match server_from_owned(next_handle) {
                                Ok(next) => server = next,
                                Err(_) => break,
                            },
                            // Fail closed: do not fall back to an un-ACL'd pipe.
                            Err(_) => break,
                        }
                        let policy = Arc::clone(&policy);
                        tokio::spawn(async move {
                            let _ = handle_client(client, policy).await;
                        });
                    }
                }
            }
        });

        Ok(ConnectMediatorHandle {
            addr: None,
            unix_path: None,
            pipe_name: Some(pipe_name),
            shutdown: Some(shutdown_tx),
            join: Some(join),
        })
    }
}

fn prepare_policy(policy: &SandboxPolicy) -> Result<()> {
    if !policy.features.mediated_network {
        bail!("CONNECT mediator requires features.mediated_network");
    }
    policy
        .validate()
        .context("invalid mediated network policy")?;
    Ok(())
}

async fn handle_client<S>(mut client: S, policy: Arc<SandboxPolicy>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Bound CONNECT request-line and header drain to resist memory DoS.
    const MAX_REQUEST_LINE_BYTES: usize = 8 * 1024;
    const MAX_HEADER_BYTES: usize = 16 * 1024;

    let mut reader = BufReader::new(&mut client);
    let mut request_line = String::new();
    reader
        .read_line(&mut request_line)
        .await
        .context("failed to read CONNECT request line")?;
    if request_line.len() > MAX_REQUEST_LINE_BYTES {
        bail!("CONNECT request line exceeds {MAX_REQUEST_LINE_BYTES} bytes");
    }

    // Drain headers until blank line.
    let mut header_bytes = 0usize;
    loop {
        let mut header = String::new();
        reader
            .read_line(&mut header)
            .await
            .context("failed to read CONNECT headers")?;
        header_bytes = header_bytes.saturating_add(header.len());
        if header_bytes > MAX_HEADER_BYTES {
            bail!("CONNECT headers exceed {MAX_HEADER_BYTES} bytes");
        }
        if header == "\r\n" || header == "\n" || header.is_empty() {
            break;
        }
    }

    let (host, port) = parse_connect_target(&request_line)?;
    match decide_mediated_connect(&policy, &host, port) {
        AccessDecision::Allow => {
            let mut upstream = TcpStream::connect((host.as_str(), port))
                .await
                .with_context(|| format!("failed to connect upstream {host}:{port}"))?;
            client
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .context("failed to write CONNECT success response")?;
            let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
        }
        AccessDecision::Deny => {
            client
                .write_all(
                    b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await
                .context("failed to write CONNECT deny response")?;
        }
    }
    Ok(())
}

pub(crate) fn parse_connect_target(request_line: &str) -> Result<(String, u16)> {
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 || parts.len() > 3 {
        bail!("CONNECT request line must be 'CONNECT host:port [HTTP/x.y]', got {request_line:?}");
    }
    let method = parts[0];
    let target = parts[1];
    if !method.eq_ignore_ascii_case("CONNECT") {
        bail!("CONNECT mediator only accepts CONNECT method, got {method:?}");
    }
    let (host, port) = match target.rsplit_once(':') {
        Some((host, port)) => (host, port),
        None => bail!("CONNECT target missing port: {target:?}"),
    };
    if host.is_empty() || host.contains('/') {
        bail!("invalid CONNECT host: {host:?}");
    }
    let port: u16 = port
        .parse()
        .with_context(|| format!("invalid CONNECT port in {target:?}"))?;
    Ok((host.to_string(), port))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::NetworkAllowRule;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

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
    async fn connect_allow_tunnels_bytes_to_upstream() {
        let upstream = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_task = tokio::spawn(async move {
            let (mut stream, _) = upstream.accept().await.unwrap();
            let mut buf = [0u8; 4];
            stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"ping");
            stream.write_all(b"pong").await.unwrap();
        });

        let mediator = ConnectMediator::bind(origin_policy("127.0.0.1", upstream_addr.port()))
            .await
            .unwrap();
        let mut client = TcpStream::connect(mediator.listen_addr()).await.unwrap();
        let request = format!(
            "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
            upstream_addr.port(),
            upstream_addr.port()
        );
        client.write_all(request.as_bytes()).await.unwrap();

        let mut response = [0u8; 64];
        let n = client.read(&mut response).await.unwrap();
        let response = std::str::from_utf8(&response[..n]).unwrap();
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "response={response:?}"
        );

        client.write_all(b"ping").await.unwrap();
        let mut reply = [0u8; 4];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"pong");
        upstream_task.await.unwrap();
        mediator.shutdown().await;
    }

    #[tokio::test]
    async fn connect_deny_never_reaches_upstream() {
        let upstream = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_task = tokio::spawn(async move {
            let result =
                tokio::time::timeout(std::time::Duration::from_millis(200), upstream.accept())
                    .await;
            assert!(result.is_err() || matches!(result, Ok(Err(_))));
        });

        let mediator = ConnectMediator::bind(origin_policy("allowed.example", 443))
            .await
            .unwrap();
        let mut client = TcpStream::connect(mediator.listen_addr()).await.unwrap();
        let request = format!(
            "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
            upstream_addr.port(),
            upstream_addr.port()
        );
        client.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        let response = String::from_utf8_lossy(&response);
        assert!(
            response.starts_with("HTTP/1.1 403"),
            "response={response:?}"
        );
        upstream_task.await.unwrap();
        mediator.shutdown().await;
    }

    #[tokio::test]
    async fn path_prefixed_rule_does_not_authorize_connect() {
        let mut policy = SandboxPolicy::a3s_bash_baseline();
        policy.features.mediated_network = true;
        policy.network.allow.push(NetworkAllowRule {
            host: "127.0.0.1".into(),
            port: Some(9),
            path_prefix: Some("/v1".into()),
        });
        let mediator = ConnectMediator::bind(policy).await.unwrap();
        let mut client = TcpStream::connect(mediator.listen_addr()).await.unwrap();
        client
            .write_all(b"CONNECT 127.0.0.1:9 HTTP/1.1\r\nHost: 127.0.0.1:9\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 403"));
        mediator.shutdown().await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unix_connect_allow_tunnels_bytes_to_upstream() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("mediator.sock");

        let upstream = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_task = tokio::spawn(async move {
            let (mut stream, _) = upstream.accept().await.unwrap();
            let mut buf = [0u8; 4];
            stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"unix");
            stream.write_all(b"ok!!").await.unwrap();
        });

        let mediator =
            ConnectMediator::bind_unix(origin_policy("127.0.0.1", upstream_addr.port()), &sock)
                .await
                .unwrap();
        assert_eq!(mediator.unix_path(), Some(sock.as_path()));

        let mut client = tokio::net::UnixStream::connect(&sock).await.unwrap();
        let request = format!(
            "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
            upstream_addr.port(),
            upstream_addr.port()
        );
        client.write_all(request.as_bytes()).await.unwrap();

        let mut response = [0u8; 64];
        let n = client.read(&mut response).await.unwrap();
        assert!(std::str::from_utf8(&response[..n])
            .unwrap()
            .starts_with("HTTP/1.1 200"));

        client.write_all(b"unix").await.unwrap();
        let mut reply = [0u8; 4];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"ok!!");
        upstream_task.await.unwrap();
        mediator.shutdown().await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unix_connect_deny_never_reaches_upstream() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("deny.sock");

        let upstream = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_task = tokio::spawn(async move {
            let result =
                tokio::time::timeout(std::time::Duration::from_millis(200), upstream.accept())
                    .await;
            assert!(result.is_err() || matches!(result, Ok(Err(_))));
        });

        let mediator = ConnectMediator::bind_unix(origin_policy("allowed.example", 443), &sock)
            .await
            .unwrap();
        let mut client = tokio::net::UnixStream::connect(&sock).await.unwrap();
        let request = format!(
            "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
            upstream_addr.port(),
            upstream_addr.port()
        );
        client.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 403"));
        upstream_task.await.unwrap();
        mediator.shutdown().await;
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn named_pipe_connect_allow_tunnels_bytes_to_upstream() {
        use tokio::net::windows::named_pipe::ClientOptions;

        let pipe_name = format!(r"\\.\pipe\a3s-sandbox-connect-{}", std::process::id());

        let upstream = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_task = tokio::spawn(async move {
            let (mut stream, _) = upstream.accept().await.unwrap();
            let mut buf = [0u8; 4];
            stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"pipe");
            stream.write_all(b"ok!!").await.unwrap();
        });

        let mediator = ConnectMediator::bind_named_pipe(
            origin_policy("127.0.0.1", upstream_addr.port()),
            &pipe_name,
        )
        .await
        .unwrap();
        assert_eq!(mediator.pipe_name(), Some(pipe_name.as_str()));

        let mut client = ClientOptions::new().open(&pipe_name).unwrap();
        let request = format!(
            "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
            upstream_addr.port(),
            upstream_addr.port()
        );
        client.write_all(request.as_bytes()).await.unwrap();

        let mut response = [0u8; 64];
        let n = client.read(&mut response).await.unwrap();
        assert!(std::str::from_utf8(&response[..n])
            .unwrap()
            .starts_with("HTTP/1.1 200"));

        client.write_all(b"pipe").await.unwrap();
        let mut reply = [0u8; 4];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"ok!!");
        upstream_task.await.unwrap();
        mediator.shutdown().await;
    }
}
