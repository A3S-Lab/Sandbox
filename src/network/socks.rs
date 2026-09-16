//! Host-loopback SOCKS5 CONNECT mediator.
//!
//! Listens on `127.0.0.1` only. Guests must be OS-fenced to this port before
//! `BackendCapabilities::mediated_socks` may be claimed. Denied CONNECT
//! requests never reach upstream. No BIND/UDP ASSOCIATE; no authentication
//! methods other than "no auth".

use crate::policy::{decide_mediated_socks, AccessDecision, SandboxPolicy};
use anyhow::{bail, Context, Result};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

/// Running SOCKS5 mediator bound to loopback.
pub struct Socks5MediatorHandle {
    addr: SocketAddr,
    shutdown: Option<oneshot::Sender<()>>,
    join: Option<JoinHandle<()>>,
}

impl Socks5MediatorHandle {
    pub fn listen_addr(&self) -> SocketAddr {
        self.addr
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

impl Drop for Socks5MediatorHandle {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
    }
}

/// Spawn a host-supervised SOCKS5 CONNECT proxy for `policy`.
pub struct Socks5Mediator;

impl Socks5Mediator {
    pub async fn bind(policy: SandboxPolicy) -> Result<Socks5MediatorHandle> {
        if !policy.features.mediated_socks {
            bail!("SOCKS5 mediator requires features.mediated_socks");
        }
        policy.validate().context("invalid mediated SOCKS policy")?;

        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .context("failed to bind SOCKS5 mediator on 127.0.0.1")?;
        let addr = listener
            .local_addr()
            .context("failed to read SOCKS5 mediator listen address")?;
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

        Ok(Socks5MediatorHandle {
            addr,
            shutdown: Some(shutdown_tx),
            join: Some(join),
        })
    }
}

async fn handle_client(mut client: TcpStream, policy: Arc<SandboxPolicy>) -> Result<()> {
    // Greeting: VER NMETHODS METHODS...
    let mut head = [0u8; 2];
    client
        .read_exact(&mut head)
        .await
        .context("failed to read SOCKS5 greeting")?;
    if head[0] != 0x05 {
        bail!("SOCKS5 mediator only accepts version 5, got {}", head[0]);
    }
    let nmethods = head[1] as usize;
    let mut methods = vec![0u8; nmethods];
    client
        .read_exact(&mut methods)
        .await
        .context("failed to read SOCKS5 methods")?;
    if !methods.contains(&0x00) {
        client.write_all(&[0x05, 0xFF]).await?;
        bail!("SOCKS5 client offered no no-auth method");
    }
    client
        .write_all(&[0x05, 0x00])
        .await
        .context("failed to write SOCKS5 method selection")?;

    let mut req_head = [0u8; 4];
    client
        .read_exact(&mut req_head)
        .await
        .context("failed to read SOCKS5 request header")?;
    if req_head[0] != 0x05 {
        bail!("invalid SOCKS5 request version {}", req_head[0]);
    }
    let cmd = req_head[1];
    let atyp = req_head[3];
    let (host, port) = read_socks_address(&mut client, atyp).await?;

    if cmd != 0x01 {
        write_socks_reply(&mut client, 0x07).await?; // Command not supported
        bail!("SOCKS5 mediator only supports CONNECT, got cmd {cmd}");
    }

    match decide_mediated_socks(&policy, &host, port) {
        AccessDecision::Allow => {
            let mut upstream = match TcpStream::connect((host.as_str(), port)).await {
                Ok(stream) => stream,
                Err(_) => {
                    write_socks_reply(&mut client, 0x05).await?; // Connection refused
                    bail!("failed to connect upstream {host}:{port}");
                }
            };
            write_socks_reply(&mut client, 0x00).await?;
            let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
        }
        AccessDecision::Deny => {
            write_socks_reply(&mut client, 0x02).await?; // Not allowed by ruleset
        }
    }
    Ok(())
}

async fn read_socks_address(client: &mut TcpStream, atyp: u8) -> Result<(String, u16)> {
    let host = match atyp {
        0x01 => {
            let mut addr = [0u8; 4];
            client.read_exact(&mut addr).await?;
            Ipv4Addr::from(addr).to_string()
        }
        0x03 => {
            let mut len = [0u8; 1];
            client.read_exact(&mut len).await?;
            let mut name = vec![0u8; len[0] as usize];
            client.read_exact(&mut name).await?;
            String::from_utf8(name).context("SOCKS5 domain is not UTF-8")?
        }
        0x04 => {
            let mut addr = [0u8; 16];
            client.read_exact(&mut addr).await?;
            Ipv6Addr::from(addr).to_string()
        }
        other => bail!("unsupported SOCKS5 address type {other}"),
    };
    let mut port_bytes = [0u8; 2];
    client.read_exact(&mut port_bytes).await?;
    let port = u16::from_be_bytes(port_bytes);
    if host.is_empty() {
        bail!("empty SOCKS5 host");
    }
    Ok((host, port))
}

async fn write_socks_reply(client: &mut TcpStream, rep: u8) -> Result<()> {
    // VER REP RSV ATYP BND.ADDR BND.PORT — bind address left as 0.0.0.0:0
    client
        .write_all(&[0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
        .context("failed to write SOCKS5 reply")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::NetworkAllowRule;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn socks_policy(host: &str, port: u16) -> SandboxPolicy {
        let mut policy = SandboxPolicy::a3s_bash_baseline();
        policy.features.mediated_socks = true;
        policy.network.allow.push(NetworkAllowRule {
            host: host.into(),
            port: Some(port),
            path_prefix: None,
        });
        policy
    }

    async fn socks_connect(client: &mut TcpStream, host: &str, port: u16) -> Result<(u8, Vec<u8>)> {
        client.write_all(&[0x05, 0x01, 0x00]).await?;
        let mut method = [0u8; 2];
        client.read_exact(&mut method).await?;
        assert_eq!(method, [0x05, 0x00]);

        let mut request = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
        request.extend_from_slice(host.as_bytes());
        request.extend_from_slice(&port.to_be_bytes());
        client.write_all(&request).await?;

        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).await?;
        Ok((reply[1], reply.to_vec()))
    }

    #[tokio::test]
    async fn socks_allow_tunnels_bytes_to_upstream() {
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

        let mediator = Socks5Mediator::bind(socks_policy("127.0.0.1", upstream_addr.port()))
            .await
            .unwrap();
        let mut client = TcpStream::connect(mediator.listen_addr()).await.unwrap();
        let (rep, _) = socks_connect(&mut client, "127.0.0.1", upstream_addr.port())
            .await
            .unwrap();
        assert_eq!(rep, 0x00, "expected SOCKS success");

        client.write_all(b"ping").await.unwrap();
        let mut reply = [0u8; 4];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"pong");
        upstream_task.await.unwrap();
        mediator.shutdown().await;
    }

    #[tokio::test]
    async fn socks_deny_never_reaches_upstream() {
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

        let mediator = Socks5Mediator::bind(socks_policy("allowed.example", 443))
            .await
            .unwrap();
        let mut client = TcpStream::connect(mediator.listen_addr()).await.unwrap();
        let (rep, _) = socks_connect(&mut client, "127.0.0.1", upstream_addr.port())
            .await
            .unwrap();
        assert_eq!(rep, 0x02, "expected ruleset deny");
        upstream_task.await.unwrap();
        mediator.shutdown().await;
    }

    #[tokio::test]
    async fn path_prefixed_rule_does_not_authorize_socks() {
        let mut policy = SandboxPolicy::a3s_bash_baseline();
        policy.features.mediated_socks = true;
        policy.network.allow.push(NetworkAllowRule {
            host: "127.0.0.1".into(),
            port: Some(9),
            path_prefix: Some("/v1".into()),
        });
        let mediator = Socks5Mediator::bind(policy).await.unwrap();
        let mut client = TcpStream::connect(mediator.listen_addr()).await.unwrap();
        let (rep, _) = socks_connect(&mut client, "127.0.0.1", 9).await.unwrap();
        assert_eq!(rep, 0x02);
        mediator.shutdown().await;
    }
}
