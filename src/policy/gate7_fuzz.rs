//! Gate 7 protocol fuzz harness for CONNECT mediation.
//!
//! Deterministic corpus (CI-runnable). Does not replace libFuzzer; it proves
//! the mediator rejects malformed inputs without panicking and without opening
//! upstream for garbage. Header/request-line size bounds are also exercised.

use crate::network::parse_connect_target;
use crate::policy::{NetworkAllowRule, SandboxPolicy};
use crate::ConnectMediator;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn allow_policy(host: &str, port: u16) -> SandboxPolicy {
    let mut policy = SandboxPolicy::a3s_bash_baseline();
    policy.features.mediated_network = true;
    policy.network.allow.push(NetworkAllowRule {
        host: host.into(),
        port: Some(port),
        path_prefix: None,
    });
    policy
}

/// Corpus of request lines that must never parse as an allowed CONNECT target.
const MALFORMED_REQUEST_LINES: &[&str] = &[
    "",
    "GET / HTTP/1.1",
    "CONNECT",
    "CONNECT ",
    "CONNECT :443",
    "CONNECT /evil:443",
    "CONNECT example.com",
    "CONNECT example.com:",
    "CONNECT example.com:65536",
    "CONNECT example.com:-1",
    "CONNECT example.com:0x50",
    "CONNECT example.com:abc",
    "CONNECT example.com:443 extra junk trailing",
    "CONNECT  HTTP/1.1",
    "POST CONNECT example.com:443 HTTP/1.1",
];

#[test]
fn gate7_fuzz_parse_connect_target_rejects_malformed_corpus() {
    for line in MALFORMED_REQUEST_LINES {
        let result = parse_connect_target(line);
        assert!(
            result.is_err(),
            "expected reject for {line:?}, got {result:?}"
        );
    }
}

#[test]
fn gate7_fuzz_ipv6_literal_parses_but_requires_exact_allowlist() {
    use crate::policy::{decide_mediated_connect, AccessDecision};

    let (host, port) = parse_connect_target("CONNECT [::1]:443 HTTP/1.1").unwrap();
    assert_eq!(host, "[::1]");
    assert_eq!(port, 443);
    let policy = allow_policy("127.0.0.1", 443);
    assert_eq!(
        decide_mediated_connect(&policy, &host, port),
        AccessDecision::Deny,
        "IPv6 loopback must not ride a 127.0.0.1 allow rule"
    );
}

#[test]
fn gate7_fuzz_parse_connect_target_accepts_canonical_shapes() {
    let (host, port) = parse_connect_target("CONNECT api.example.com:443 HTTP/1.1\r\n").unwrap();
    assert_eq!(host, "api.example.com");
    assert_eq!(port, 443);
    let (host, port) = parse_connect_target("connect 127.0.0.1:9 HTTP/1.0").unwrap();
    assert_eq!(host, "127.0.0.1");
    assert_eq!(port, 9);
}

#[tokio::test]
async fn gate7_fuzz_mediator_survives_malformed_tcp_payloads_without_upstream() {
    let upstream = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_task = tokio::spawn(async move {
        let result =
            tokio::time::timeout(std::time::Duration::from_millis(400), upstream.accept()).await;
        assert!(
            result.is_err() || matches!(result, Ok(Err(_))),
            "malformed CONNECT must not reach upstream"
        );
    });

    let mediator = ConnectMediator::bind(allow_policy("127.0.0.1", upstream_addr.port()))
        .await
        .unwrap();

    let payloads: &[&[u8]] = &[
        b"",
        b"\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: x\r\n\r\n",
        b"CONNECT\r\n\r\n",
        b"CONNECT :443 HTTP/1.1\r\n\r\n",
        b"CONNECT /nope:443 HTTP/1.1\r\n\r\n",
    ];

    for payload in payloads {
        let mut client = TcpStream::connect(mediator.listen_addr()).await.unwrap();
        let _ = client.write_all(payload).await;
        let _ = client.shutdown().await;
        // Drain any response; mediator may close without writing.
        let mut buf = Vec::new();
        let _ = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            client.read_to_end(&mut buf),
        )
        .await;
    }

    // Oversized request line.
    {
        let mut huge = Vec::from(&b"CONNECT "[..]);
        huge.extend(std::iter::repeat_n(b'a', 9 * 1024));
        huge.extend_from_slice(b":443 HTTP/1.1\r\n\r\n");
        let mut client = TcpStream::connect(mediator.listen_addr()).await.unwrap();
        let _ = client.write_all(&huge).await;
        let _ = client.shutdown().await;
        let mut buf = Vec::new();
        let _ = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            client.read_to_end(&mut buf),
        )
        .await;
    }

    // Oversized headers after a valid request line targeting the allowlisted
    // upstream — must still not complete a tunnel if headers never finish / overflow.
    {
        let mut client = TcpStream::connect(mediator.listen_addr()).await.unwrap();
        let head = format!("CONNECT 127.0.0.1:{} HTTP/1.1\r\n", upstream_addr.port());
        client.write_all(head.as_bytes()).await.unwrap();
        let mut headers = Vec::new();
        while headers.len() < 20 * 1024 {
            headers.extend_from_slice(b"X-Pad: ");
            headers.extend(std::iter::repeat_n(b'x', 200));
            headers.extend_from_slice(b"\r\n");
        }
        let _ = client.write_all(&headers).await;
        let _ = client.shutdown().await;
        let mut buf = Vec::new();
        let _ = tokio::time::timeout(
            std::time::Duration::from_millis(300),
            client.read_to_end(&mut buf),
        )
        .await;
    }

    upstream_task.await.unwrap();
    mediator.shutdown().await;
}

#[tokio::test]
async fn gate7_fuzz_mediator_still_allows_well_formed_connect_after_garbage() {
    let upstream = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.unwrap();
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"fuzz");
        stream.write_all(b"ok!!").await.unwrap();
    });

    let mediator = ConnectMediator::bind(allow_policy("127.0.0.1", upstream_addr.port()))
        .await
        .unwrap();

    // Garbage first.
    {
        let mut client = TcpStream::connect(mediator.listen_addr()).await.unwrap();
        client.write_all(b"NOT-CONNECT\r\n\r\n").await.unwrap();
        let _ = client.shutdown().await;
        let mut buf = Vec::new();
        let _ = client.read_to_end(&mut buf).await;
    }

    // Then a valid tunnel.
    let mut client = TcpStream::connect(mediator.listen_addr()).await.unwrap();
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
    client.write_all(b"fuzz").await.unwrap();
    let mut reply = [0u8; 4];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"ok!!");

    upstream_task.await.unwrap();
    mediator.shutdown().await;
}
