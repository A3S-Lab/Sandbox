use super::*;
use std::collections::HashMap;

const TEST_COMMAND_TIMEOUT_MS: u64 = 5_000;
#[cfg(windows)]
const WINDOWS_PROBE_MARKER: &str = "a3s-sandbox-probe";

fn create_test_sandbox(workspace: &std::path::Path) -> NativeSandbox {
    NativeSandbox::new(workspace).unwrap()
}

async fn execute_test_command(
    sandbox: &NativeSandbox,
    command: impl Into<String>,
) -> anyhow::Result<CommandOutput> {
    let command = command.into();
    sandbox
        .execute(CommandRequest {
            command,
            timeout_ms: TEST_COMMAND_TIMEOUT_MS,
            output_observer: None,
            env: None,
        })
        .await
}

#[tokio::test]
async fn native_backend_starts_and_writes_only_ordinary_workspace_content() {
    let workspace = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(workspace.path().join(".git")).unwrap();
    std::fs::create_dir_all(workspace.path().join(".a3s")).unwrap();
    std::fs::write(workspace.path().join(".git/config"), "original-git").unwrap();
    std::fs::write(workspace.path().join(".a3s/policy.acl"), "original-policy").unwrap();
    std::fs::write(workspace.path().join(".env"), "workspace-secret").unwrap();
    let sandbox = create_test_sandbox(workspace.path());

    sandbox.probe().await.unwrap();
    #[cfg(not(windows))]
    let ordinary_command = "printf changed > ordinary.txt";
    #[cfg(windows)]
    let ordinary_command = r#"
$ErrorActionPreference = 'Stop'
$secretDenied = $false
try {
    $null = [IO.File]::ReadAllText((Join-Path (Get-Location) '.env'))
} catch {
    $secretDenied = $true
}
if (-not $secretDenied) {
    throw 'workspace credential read unexpectedly succeeded'
}
if ([IO.File]::ReadAllText((Join-Path (Get-Location) '.git/config')) -ne 'original-git') {
    throw 'read-only control metadata is unavailable'
}
[IO.File]::WriteAllText((Join-Path (Get-Location) 'ordinary.txt'), 'changed')
"#;
    let ordinary = execute_test_command(&sandbox, ordinary_command)
        .await
        .unwrap();
    assert_eq!(ordinary.exit_code, 0, "{}", ordinary.stderr);
    assert_eq!(
        std::fs::read_to_string(workspace.path().join("ordinary.txt")).unwrap(),
        "changed"
    );
    assert_eq!(
        std::fs::read_to_string(workspace.path().join(".env")).unwrap(),
        "workspace-secret",
        "sandbox cleanup did not restore host credential access"
    );

    #[cfg(not(windows))]
    let protected_writes = [
        (
            "printf changed > .git/config",
            ".git/config",
            "original-git",
        ),
        (
            "printf changed > .a3s/policy.acl",
            ".a3s/policy.acl",
            "original-policy",
        ),
    ];
    #[cfg(windows)]
    let protected_writes = [
        (
            "[IO.File]::WriteAllText((Join-Path (Get-Location) '.git/config'), 'changed')",
            ".git/config",
            "original-git",
        ),
        (
            "[IO.File]::WriteAllText((Join-Path (Get-Location) '.a3s/policy.acl'), 'changed')",
            ".a3s/policy.acl",
            "original-policy",
        ),
    ];
    for (command, path, expected) in protected_writes {
        let output = execute_test_command(&sandbox, command).await.unwrap();
        assert_ne!(
            output.exit_code, 0,
            "write unexpectedly succeeded: {command}"
        );
        assert_eq!(
            std::fs::read_to_string(workspace.path().join(path)).unwrap(),
            expected
        );
    }

    #[cfg(not(windows))]
    let create_command = "mkdir .codex";
    #[cfg(windows)]
    let create_command = "New-Item -ItemType Directory -Path '.codex' -ErrorAction Stop";
    let create = execute_test_command(&sandbox, create_command)
        .await
        .unwrap();
    assert_ne!(
        create.exit_code, 0,
        "protected directory creation succeeded"
    );
    assert!(!workspace.path().join(".codex").exists());
}

#[cfg(unix)]
#[tokio::test]
async fn native_backend_blocks_symlink_hardlink_and_credential_escape() {
    use std::os::unix::fs::symlink;

    let workspace = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("secret"), "outside-secret").unwrap();
    std::fs::hard_link(
        outside.path().join("secret"),
        workspace.path().join("outside-hardlink"),
    )
    .unwrap();
    symlink(outside.path(), workspace.path().join("outside-link")).unwrap();
    std::fs::write(workspace.path().join(".env"), "workspace-secret").unwrap();
    let sandbox = create_test_sandbox(workspace.path());

    for command in [
        "cat .env",
        "cat outside-hardlink",
        "printf escaped > outside-hardlink",
        "printf escaped > outside-link/symlink-escape",
    ] {
        let output = execute_test_command(&sandbox, command).await.unwrap();
        assert_ne!(
            output.exit_code, 0,
            "escape unexpectedly succeeded: {command}"
        );
        assert!(!output.stdout.contains("secret"));
    }
    assert_eq!(
        std::fs::read_to_string(outside.path().join("secret")).unwrap(),
        "outside-secret"
    );
    assert!(!outside.path().join("symlink-escape").exists());

    std::fs::write(workspace.path().join("link-source"), "ordinary").unwrap();
    let output = execute_test_command(&sandbox, "ln link-source new-hardlink")
        .await
        .unwrap();
    assert_ne!(output.exit_code, 0, "runtime hard-link creation succeeded");
    assert!(!workspace.path().join("new-hardlink").exists());
}

#[cfg(windows)]
#[tokio::test]
async fn windows_backend_blocks_preexisting_hardlink_escape() {
    let workspace = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let outside_secret = outside.path().join("secret");
    std::fs::write(&outside_secret, "outside-secret").unwrap();
    std::fs::hard_link(&outside_secret, workspace.path().join("outside-hardlink")).unwrap();
    let sandbox = create_test_sandbox(workspace.path());

    let output = execute_test_command(
        &sandbox,
        "[Console]::Out.Write('a3s-sandbox-probe'); $ErrorActionPreference = 'Stop'; [IO.File]::WriteAllText((Join-Path (Get-Location) 'outside-hardlink'), 'escaped')",
    )
    .await
    .unwrap();
    assert_eq!(output.stdout, WINDOWS_PROBE_MARKER, "{}", output.stderr);
    assert_ne!(output.exit_code, 0, "hard-link write escape succeeded");
    assert_eq!(
        std::fs::read_to_string(outside_secret).unwrap(),
        "outside-secret"
    );
}

#[tokio::test]
async fn native_backend_blocks_ip_and_host_unix_socket_communication() {
    let workspace = tempfile::tempdir().unwrap();
    let sandbox = create_test_sandbox(workspace.path());

    #[cfg(windows)]
    {
        let ipv4_listener =
            std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let ipv6_listener =
            std::net::TcpListener::bind((std::net::Ipv6Addr::LOCALHOST, 0)).unwrap();
        let unix_parent = tempfile::tempdir().unwrap();
        let unix_socket = unix_parent
            .path()
            .join("blocked.sock")
            .to_string_lossy()
            .replace('\'', "''");
        let probe = format!(
            r#"
[Console]::Out.Write('{WINDOWS_PROBE_MARKER}')
$ErrorActionPreference = 'Stop'

$client = [Net.Sockets.TcpClient]::new()
$ipv4Allowed = $false
try {{
    $task = $client.ConnectAsync([Net.IPAddress]::Loopback, {ipv4_port})
    if ($task.Wait(500)) {{
        $task.GetAwaiter().GetResult()
        $ipv4Allowed = $true
    }}
}} catch {{
}} finally {{
    $client.Dispose()
}}
if ($ipv4Allowed) {{ throw 'IPv4 loopback communication unexpectedly succeeded' }}

$client = [Net.Sockets.TcpClient]::new([Net.Sockets.AddressFamily]::InterNetworkV6)
$ipv6Allowed = $false
try {{
    $task = $client.ConnectAsync([Net.IPAddress]::IPv6Loopback, {ipv6_port})
    if ($task.Wait(500)) {{
        $task.GetAwaiter().GetResult()
        $ipv6Allowed = $true
    }}
}} catch {{
}} finally {{
    $client.Dispose()
}}
if ($ipv6Allowed) {{ throw 'IPv6 loopback communication unexpectedly succeeded' }}

$socket = [Net.Sockets.Socket]::new(
    [Net.Sockets.AddressFamily]::Unix,
    [Net.Sockets.SocketType]::Stream,
    [Net.Sockets.ProtocolType]::Unspecified
)
$unixAllowed = $false
try {{
    $socket.Bind([Net.Sockets.UnixDomainSocketEndPoint]::new('{unix_socket}'))
    $unixAllowed = $true
}} catch {{
}} finally {{
    $socket.Dispose()
}}
if ($unixAllowed) {{ throw 'host Unix socket creation unexpectedly succeeded' }}
"#,
            ipv4_port = ipv4_listener.local_addr().unwrap().port(),
            ipv6_port = ipv6_listener.local_addr().unwrap().port(),
        );
        let output = execute_test_command(&sandbox, probe).await.unwrap();
        assert_eq!(output.stdout, WINDOWS_PROBE_MARKER, "{}", output.stderr);
        assert_eq!(output.exit_code, 0, "{}", output.stderr);
        assert!(!unix_parent.path().join("blocked.sock").exists());
    }

    #[cfg(not(windows))]
    let probes = [
        "python3 -c 'import socket; s=socket.socket(); s.bind((\"127.0.0.1\", 0))'",
        "python3 -c 'import socket; s=socket.socket(socket.AF_UNIX); s.bind(\"blocked.sock\")'",
    ];

    #[cfg(not(windows))]
    for probe in probes {
        let output = execute_test_command(&sandbox, probe).await.unwrap();
        assert_ne!(
            output.exit_code, 0,
            "network or host IPC probe unexpectedly succeeded: {}{}",
            output.stdout, output.stderr
        );
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn linux_backend_drops_all_process_capabilities_before_bash() {
    let workspace = tempfile::tempdir().unwrap();
    let sandbox = create_test_sandbox(workspace.path());
    let output = execute_test_command(
        &sandbox,
        "grep '^Cap\\(Inh\\|Prm\\|Eff\\|Bnd\\|Amb\\):' /proc/self/status",
    )
    .await
    .unwrap();
    assert_eq!(output.exit_code, 0, "{}", output.stderr);
    let capabilities = output.stdout.lines().collect::<Vec<_>>();
    assert_eq!(capabilities.len(), 5, "{}", output.stdout);
    assert!(
        capabilities
            .iter()
            .all(|line| line.ends_with("0000000000000000")),
        "sandboxed Bash retained Linux capabilities: {}",
        output.stdout
    );
}

#[tokio::test]
async fn native_backend_sanitizes_environment_and_kills_timed_out_descendants() {
    let workspace = tempfile::tempdir().unwrap();
    let sandbox = create_test_sandbox(workspace.path());
    let request = CommandRequest {
        #[cfg(not(windows))]
        command: "printf '%s|%s|%s' \"${SAFE_VALUE:-}\" \"${BASH_ENV:-}\" \"$HOME\"".to_string(),
        #[cfg(windows)]
        command: "[Console]::Out.Write(\"$env:SAFE_VALUE|$env:BASH_ENV|$env:HOME\")".to_string(),
        timeout_ms: 5_000,
        output_observer: None,
        env: Some(std::sync::Arc::new(HashMap::from([
            ("SAFE_VALUE".to_string(), "visible".to_string()),
            ("BASH_ENV".to_string(), "attack".to_string()),
        ]))),
    };
    let output = sandbox.execute(request).await.unwrap();
    assert_eq!(output.exit_code, 0, "{}", output.stderr);
    assert!(output.stdout.starts_with("visible||"), "{}", output.stdout);
    assert!(!output
        .stdout
        .contains(workspace.path().to_string_lossy().as_ref()));

    #[cfg(not(windows))]
    let command = "(sleep 0.30; touch timeout-leak) & wait";
    #[cfg(windows)]
    let command = "Start-Job { Start-Sleep -Milliseconds 300; New-Item timeout-leak } | Wait-Job";
    let output = sandbox
        .execute(CommandRequest {
            command: command.to_string(),
            timeout_ms: 50,
            output_observer: None,
            env: None,
        })
        .await
        .unwrap();
    assert!(output.timed_out);
    tokio::time::sleep(std::time::Duration::from_millis(450)).await;
    assert!(!workspace.path().join("timeout-leak").exists());
}
