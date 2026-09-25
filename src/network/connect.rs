//! Host-supervised HTTP CONNECT mediator.
//!
//! TCP bind listens on `127.0.0.1` only (macOS Seatbelt path). Unix bind is
//! for Linux netns bridges: the guest reaches the host mediator via a
//! bind-mounted socket and an in-guest TCP→Unix relay.
//!
//! Guests must be OS-fenced before `BackendCapabilities::mediated_http` may be
//! claimed. The mediator never broadens policy: denied CONNECT requests never
//! reach upstream.

use crate::policy::{
    decide_mediated_connect, decide_mediated_http, matching_secret_injections, AccessDecision,
    MediatedHttpRequest, SandboxPolicy,
};
use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

/// Host-held secret values for one mediated execution. Never logged, never
/// forwarded upstream except through a matching `SecretHeaderInjection`.
pub(crate) type SharedSecrets = Option<Arc<HashMap<String, String>>>;

/// Policy plus secrets for one mediator accept loop.
#[derive(Clone)]
pub(crate) struct MediationContext {
    policy: Arc<SandboxPolicy>,
    secrets: SharedSecrets,
}

impl MediationContext {
    pub(crate) fn new(policy: SandboxPolicy, secrets: SharedSecrets) -> Self {
        Self {
            policy: Arc::new(policy),
            secrets,
        }
    }

    fn for_connection(&self) -> (Arc<SandboxPolicy>, SharedSecrets) {
        (Arc::clone(&self.policy), self.secrets.clone())
    }
}

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
    pub async fn bind(
        policy: SandboxPolicy,
        secrets: SharedSecrets,
    ) -> Result<ConnectMediatorHandle> {
        prepare_policy(&policy)?;
        let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .context("failed to bind CONNECT mediator on 127.0.0.1")?;
        let addr = listener
            .local_addr()
            .context("failed to read CONNECT mediator listen address")?;
        let context = Arc::new(MediationContext::new(policy, secrets));
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();

        let join = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => break,
                    accepted = listener.accept() => {
                        match accepted {
                            Ok((stream, _)) => {
                                let context = Arc::clone(&context);
                                tokio::spawn(async move {
                                    let _ = handle_client(stream, context).await;
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
        secrets: SharedSecrets,
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
        let context = Arc::new(MediationContext::new(policy, secrets));
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
        let socket_path = path.clone();

        let join = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => break,
                    accepted = listener.accept() => {
                        match accepted {
                            Ok((stream, _)) => {
                                let context = Arc::clone(&context);
                                tokio::spawn(async move {
                                    let _ = handle_client(stream, context).await;
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
        secrets: SharedSecrets,
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
        let context = Arc::new(MediationContext::new(policy, secrets));
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
                        let context = Arc::clone(&context);
                        tokio::spawn(async move {
                            let _ = handle_client(client, context).await;
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
        secrets: SharedSecrets,
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

        let context = Arc::new(MediationContext::new(policy, secrets));
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
        let join = tokio::spawn(async move {
            tokio::select! {
                _ = &mut shutdown_rx => {}
                _ = handle_client(server, context) => {}
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
        secrets: SharedSecrets,
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
        let context = Arc::new(MediationContext::new(policy, secrets));
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
                        let context = Arc::clone(&context);
                        tokio::spawn(async move {
                            let _ = handle_client(client, context).await;
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

async fn handle_client<S>(client: S, context: Arc<MediationContext>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Bound request-line and header drain to resist memory DoS.
    const MAX_REQUEST_LINE_BYTES: usize = 8 * 1024;
    const MAX_HEADER_BYTES: usize = 16 * 1024;

    let mut client = client;
    let mut reader = BufReader::new(&mut client);
    let mut request_line = String::new();
    reader
        .read_line(&mut request_line)
        .await
        .context("failed to read mediator request line")?;
    if request_line.len() > MAX_REQUEST_LINE_BYTES {
        bail!("mediator request line exceeds {MAX_REQUEST_LINE_BYTES} bytes");
    }

    // Drain (and for absolute-form HTTP, collect) headers until blank line.
    let mut header_bytes = 0usize;
    let mut headers: Vec<String> = Vec::new();
    loop {
        let mut header = String::new();
        reader
            .read_line(&mut header)
            .await
            .context("failed to read mediator headers")?;
        header_bytes = header_bytes.saturating_add(header.len());
        if header_bytes > MAX_HEADER_BYTES {
            bail!("mediator headers exceed {MAX_HEADER_BYTES} bytes");
        }
        if header == "\r\n" || header == "\n" || header.is_empty() {
            break;
        }
        headers.push(header.trim_end_matches(['\r', '\n']).to_string());
    }

    let method = request_line
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_string();
    if method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = parse_connect_target(&request_line)?;
        let policy = Arc::clone(&context.policy);
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
    } else {
        let (policy, secrets) = context.for_connection();
        handle_absolute_form_http(&mut reader, &policy, secrets, &request_line, &headers).await?;
    }
    Ok(())
}

/// Standard methods the absolute-form mediator forwards. Everything else,
/// including CONNECT (handled above), fails closed.
const FORWARDED_HTTP_METHODS: &[&str] =
    &["GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"];

/// Body cap for forwarded absolute-form requests.
const MAX_FORWARDED_BODY_BYTES: usize = 1024 * 1024;

/// Mediate one absolute-form plain-HTTP request.
///
/// TLS interception is a non-goal: `https://` targets refuse instead of
/// tunneling, so injection stays honest. `network.allow` is the only
/// authority; matching `SecretHeaderInjection` rules add their host-held
/// header and replace any client-supplied instance of that header.
async fn handle_absolute_form_http<S>(
    reader: &mut BufReader<&mut S>,
    policy: &SandboxPolicy,
    secrets: SharedSecrets,
    request_line: &str,
    headers: &[String],
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    async fn respond<W>(writer: &mut W, status: &str) -> Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        writer
            .write_all(
                format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .context("failed to write mediator HTTP response")
    }

    let (method, host, port, path) = match parse_absolute_form_target(request_line) {
        Ok(parsed) => parsed,
        Err(_) => {
            respond(reader.get_mut(), "403 Forbidden").await?;
            return Ok(());
        }
    };
    let request = MediatedHttpRequest {
        host: host.clone(),
        port,
        path: path.clone(),
    };
    if decide_mediated_http(policy, &request) != AccessDecision::Allow {
        respond(reader.get_mut(), "403 Forbidden").await?;
        return Ok(());
    }

    // Resolve injections up front: a missing or control-character-bearing
    // secret must fail closed before any upstream byte is sent.
    let mut injected: Vec<(&str, &str, &str)> = Vec::new();
    for injection in matching_secret_injections(policy, &request) {
        let Some(value) = secrets
            .as_ref()
            .and_then(|map| map.get(&injection.secret_env))
            .map(String::as_str)
        else {
            respond(reader.get_mut(), "403 Forbidden").await?;
            return Ok(());
        };
        if value.bytes().any(|byte| matches!(byte, b'\r' | b'\n' | 0)) {
            respond(reader.get_mut(), "403 Forbidden").await?;
            return Ok(());
        }
        injected.push((
            injection.header.as_str(),
            injection.value_prefix.as_str(),
            value,
        ));
    }

    let mut forwarded = format!("{method} {path} HTTP/1.1\r\n");
    if port == 80 {
        forwarded.push_str(&format!("Host: {host}\r\n"));
    } else {
        forwarded.push_str(&format!("Host: {host}:{port}\r\n"));
    }
    forwarded.push_str("Connection: close\r\n");
    let mut content_length: Option<u64> = None;
    for header in headers {
        let Some((name, value)) = header.split_once(':') else {
            continue;
        };
        let lower = name.trim().to_ascii_lowercase();
        // Hop-by-hop and proxy headers are re-authored here; injected header
        // names are replaced wholesale so client sentinels cannot leak.
        if lower == "host"
            || lower == "connection"
            || lower == "proxy-connection"
            || lower == "proxy-authorization"
            || injected
                .iter()
                .any(|(header, _, _)| header.eq_ignore_ascii_case(name.trim()))
        {
            continue;
        }
        if lower == "content-length" {
            content_length = value.trim().parse().ok();
        }
        if lower == "transfer-encoding" {
            // Chunked bodies need framing logic this mediator refuses.
            respond(reader.get_mut(), "400 Bad Request").await?;
            return Ok(());
        }
        forwarded.push_str(header);
        forwarded.push_str("\r\n");
    }
    for (header, prefix, value) in &injected {
        forwarded.push_str(&format!("{header}: {prefix}{value}\r\n"));
    }
    forwarded.push_str("\r\n");

    if content_length.is_some_and(|length| length > MAX_FORWARDED_BODY_BYTES as u64) {
        respond(reader.get_mut(), "413 Content Too Large").await?;
        return Ok(());
    }

    let mut upstream = TcpStream::connect((host.as_str(), port))
        .await
        .with_context(|| format!("failed to connect upstream {host}:{port}"))?;
    upstream
        .write_all(forwarded.as_bytes())
        .await
        .context("failed to write forwarded request head")?;
    if let Some(length) = content_length {
        let mut body = vec![0u8; length as usize];
        reader
            .read_exact(&mut body)
            .await
            .context("failed to read forwarded request body")?;
        upstream
            .write_all(&body)
            .await
            .context("failed to write forwarded request body")?;
    }

    let mut response = vec![0u8; 16 * 1024];
    loop {
        let read = upstream
            .read(&mut response)
            .await
            .context("failed to read upstream response")?;
        if read == 0 {
            break;
        }
        reader
            .get_mut()
            .write_all(&response[..read])
            .await
            .context("failed to write upstream response")?;
    }
    Ok(())
}

/// Parse an absolute-form proxy request line into `(method, host, port, path)`.
pub(crate) fn parse_absolute_form_target(
    request_line: &str,
) -> Result<(String, String, u16, String)> {
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 || parts.len() > 3 {
        bail!(
            "absolute-form request line must be 'METHOD http://host[:port]/path [HTTP/x.y]', \
             got {request_line:?}"
        );
    }
    let method = parts[0];
    if !FORWARDED_HTTP_METHODS.contains(&method) {
        bail!("absolute-form mediator refuses method {method:?}");
    }
    let target = parts[1];
    let lowered = target.to_ascii_lowercase();
    if lowered.starts_with("https://") {
        bail!("https absolute-form requires TLS interception; refuse instead of tunneling blind");
    }
    if !lowered.starts_with("http://") {
        bail!("absolute-form mediator requires an http:// absolute URI, got {target:?}");
    }
    let rest = &target["http://".len()..];
    let (authority, path) = match rest.find('/') {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, "/"),
    };
    if authority.is_empty() || authority.contains(['@', '?', '#']) {
        bail!("invalid absolute-form authority: {authority:?}");
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => {
            let port: u16 = port
                .parse()
                .with_context(|| format!("invalid absolute-form port in {target:?}"))?;
            (host, port)
        }
        None => (authority, 80),
    };
    if host.is_empty() {
        bail!("invalid absolute-form host: {host:?}");
    }
    Ok((method.to_string(), host.to_string(), port, path.to_string()))
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
    use crate::policy::{NetworkAllowRule, SecretHeaderInjection};
    use std::collections::HashMap;
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

        let mediator =
            ConnectMediator::bind(origin_policy("127.0.0.1", upstream_addr.port()), None)
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

        let mediator = ConnectMediator::bind(origin_policy("allowed.example", 443), None)
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
        let mediator = ConnectMediator::bind(policy, None).await.unwrap();
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

        let mediator = ConnectMediator::bind_unix(
            origin_policy("127.0.0.1", upstream_addr.port()),
            &sock,
            None,
        )
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

        let mediator =
            ConnectMediator::bind_unix(origin_policy("allowed.example", 443), &sock, None)
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
            None,
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

    // -- Gate 8 slice 2: absolute-form plain-HTTP mediation with secret header
    //    injection. TLS interception stays a non-goal; only http:// absolute
    //    forms are transformable.

    const GATE8_SECRET: &str = "gate8-egress-secret-11c9";

    /// One-shot upstream: reads the request head, records it, replies `ok`,
    /// closes. Returns through the channel after the response is written.
    async fn echo_upstream_listener() -> (TcpListener, SocketAddr) {
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        (listener, addr)
    }

    fn injection_policy(
        upstream_port: u16,
        with_allow: bool,
        with_injection: bool,
    ) -> SandboxPolicy {
        let mut policy = SandboxPolicy::a3s_bash_baseline();
        policy.features.mediated_network = true;
        if with_allow {
            policy.network.allow.push(NetworkAllowRule {
                host: "127.0.0.1".into(),
                port: Some(upstream_port),
                path_prefix: None,
            });
        }
        if with_injection {
            policy.secret_injections.push(SecretHeaderInjection {
                host: "127.0.0.1".into(),
                port: Some(upstream_port),
                path_prefix: Some("/v1".into()),
                header: "Authorization".into(),
                value_prefix: "Bearer ".into(),
                secret_env: "GATE8_TOKEN".into(),
            });
        }
        policy
    }

    async fn gate8_secrets() -> std::sync::Arc<HashMap<String, String>> {
        std::sync::Arc::new(HashMap::from([(
            "GATE8_TOKEN".to_string(),
            GATE8_SECRET.to_string(),
        )]))
    }

    async fn run_absolute_form(
        policy: SandboxPolicy,
        secrets: Option<std::sync::Arc<HashMap<String, String>>>,
        upstream_port: u16,
        request_head: &str,
    ) -> String {
        let mediator = ConnectMediator::bind(policy, secrets).await.unwrap();
        let mut client = TcpStream::connect(mediator.listen_addr()).await.unwrap();
        let request = format!("{request_head}\r\n");
        client.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client.read_to_end(&mut response),
        )
        .await;
        let _ = upstream_port;
        mediator.shutdown().await;
        String::from_utf8_lossy(&response).into_owned()
    }

    #[tokio::test]
    async fn absolute_form_http_injects_secret_header_upstream() {
        let (upstream, addr) = echo_upstream_listener().await;
        let upstream_task = tokio::spawn(async move {
            let (raw, _) = upstream.accept().await.unwrap();
            let mut stream = BufReader::new(raw);
            let mut head = Vec::new();
            tokio::io::AsyncBufReadExt::read_until(&mut stream, b'\n', &mut head)
                .await
                .unwrap();
            let mut rest = Vec::new();
            loop {
                rest.clear();
                match tokio::io::AsyncBufReadExt::read_until(&mut stream, b'\n', &mut rest).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) if rest == b"\r\n" || rest == b"\n" => break,
                    Ok(_) => head.extend_from_slice(&rest),
                }
            }
            let head = String::from_utf8_lossy(&head).into_owned();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .unwrap();
            head
        });

        let response = run_absolute_form(
            injection_policy(addr.port(), true, true),
            Some(gate8_secrets().await),
            addr.port(),
            &format!(
                "GET http://127.0.0.1:{}/v1/token HTTP/1.1\r\nAccept: */*\r\n",
                addr.port()
            ),
        )
        .await;

        assert!(
            response.starts_with("HTTP/1.1 200"),
            "response={response:?}"
        );
        assert!(response.ends_with("ok"), "response={response:?}");
        let head = upstream_task.await.unwrap();
        assert!(
            head.contains(&format!("Authorization: Bearer {GATE8_SECRET}")),
            "upstream must observe the injected secret header, got: {head:?}"
        );
        assert!(
            !head.contains("a3s:secret:"),
            "sentinels must never be forwarded upstream: {head:?}"
        );
    }

    #[tokio::test]
    async fn absolute_form_denied_origin_never_reaches_upstream() {
        let (upstream, addr) = echo_upstream_listener().await;
        let upstream_task = tokio::spawn(async move {
            let result =
                tokio::time::timeout(std::time::Duration::from_millis(300), upstream.accept())
                    .await;
            assert!(result.is_err() || matches!(result, Ok(Err(_))));
        });

        // The allow rule authorizes a different origin: mediation denies
        // 127.0.0.1 regardless of the matching injection rule, because
        // network.allow stays the only authority.
        let mut policy = injection_policy(addr.port(), false, true);
        policy.network.allow.push(NetworkAllowRule {
            host: "allowed.example".into(),
            port: None,
            path_prefix: None,
        });
        let response = run_absolute_form(
            policy,
            Some(gate8_secrets().await),
            addr.port(),
            &format!("GET http://127.0.0.1:{}/v1/token HTTP/1.1\r\n", addr.port()),
        )
        .await;
        assert!(
            response.starts_with("HTTP/1.1 403"),
            "denied absolute-form request must never reach upstream: {response:?}"
        );
        upstream_task.await.unwrap();
    }

    #[tokio::test]
    async fn absolute_form_https_target_refused_fail_closed() {
        let (upstream, addr) = echo_upstream_listener().await;
        let upstream_task = tokio::spawn(async move {
            let result =
                tokio::time::timeout(std::time::Duration::from_millis(300), upstream.accept())
                    .await;
            assert!(result.is_err() || matches!(result, Ok(Err(_))));
        });

        let response = run_absolute_form(
            injection_policy(addr.port(), true, true),
            Some(gate8_secrets().await),
            addr.port(),
            &format!(
                "GET https://127.0.0.1:{}/v1/token HTTP/1.1\r\n",
                addr.port()
            ),
        )
        .await;
        assert!(
            response.starts_with("HTTP/1.1 403") || response.is_empty(),
            "https absolute-form must fail closed, got: {response:?}"
        );
        upstream_task.await.unwrap();
    }

    #[tokio::test]
    async fn absolute_form_without_matching_injection_forwards_no_authorization() {
        let (upstream, addr) = echo_upstream_listener().await;
        let upstream_task = tokio::spawn(async move {
            let (raw, _) = upstream.accept().await.unwrap();
            let mut stream = BufReader::new(raw);
            let mut head = Vec::new();
            tokio::io::AsyncBufReadExt::read_until(&mut stream, b'\n', &mut head)
                .await
                .unwrap();
            let mut rest = Vec::new();
            loop {
                rest.clear();
                match tokio::io::AsyncBufReadExt::read_until(&mut stream, b'\n', &mut rest).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) if rest == b"\r\n" || rest == b"\n" => break,
                    Ok(_) => head.extend_from_slice(&rest),
                }
            }
            let head = String::from_utf8_lossy(&head).into_owned();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .unwrap();
            head
        });

        // Allowed origin, but the request path does not match the injection
        // rule: forwarded without any Authorization header.
        let response = run_absolute_form(
            injection_policy(addr.port(), true, true),
            Some(gate8_secrets().await),
            addr.port(),
            &format!("GET http://127.0.0.1:{}/v2/other HTTP/1.1\r\n", addr.port()),
        )
        .await;
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "response={response:?}"
        );
        let head = upstream_task.await.unwrap();
        assert!(
            !head.to_ascii_lowercase().contains("authorization:"),
            "non-matching path must not receive the secret header: {head:?}"
        );
        assert!(!head.contains(GATE8_SECRET), "head={head:?}");
    }

    #[tokio::test]
    async fn client_supplied_authorization_is_replaced_by_injection() {
        let (upstream, addr) = echo_upstream_listener().await;
        let upstream_task = tokio::spawn(async move {
            let (raw, _) = upstream.accept().await.unwrap();
            let mut stream = BufReader::new(raw);
            let mut head = Vec::new();
            tokio::io::AsyncBufReadExt::read_until(&mut stream, b'\n', &mut head)
                .await
                .unwrap();
            let mut rest = Vec::new();
            loop {
                rest.clear();
                match tokio::io::AsyncBufReadExt::read_until(&mut stream, b'\n', &mut rest).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) if rest == b"\r\n" || rest == b"\n" => break,
                    Ok(_) => head.extend_from_slice(&rest),
                }
            }
            let head = String::from_utf8_lossy(&head).into_owned();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .unwrap();
            head
        });

        // Guest only has the sentinel; a tool forwarding it upstream must not
        // leak it, and the injected header must replace the client's.
        let response = run_absolute_form(
            injection_policy(addr.port(), true, true),
            Some(gate8_secrets().await),
            addr.port(),
            &format!(
                "GET http://127.0.0.1:{}/v1/token HTTP/1.1\r\nAuthorization: Bearer a3s:secret:GATE8_TOKEN\r\n",
                addr.port()
            ),
        )
        .await;
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "response={response:?}"
        );
        let head = upstream_task.await.unwrap();
        let authorization_lines = head
            .lines()
            .filter(|line| line.to_ascii_lowercase().starts_with("authorization:"))
            .count();
        assert_eq!(
            authorization_lines, 1,
            "exactly one Authorization header may reach upstream: {head:?}"
        );
        assert!(
            !head.contains("a3s:secret:"),
            "sentinel must be swallowed, not forwarded: {head:?}"
        );
        assert!(
            head.contains(&format!("Authorization: Bearer {GATE8_SECRET}")),
            "upstream must observe the injected value: {head:?}"
        );
    }
}
