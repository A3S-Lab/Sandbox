use super::*;
use std::collections::HashMap;

#[tokio::test]
async fn native_backend_starts_and_writes_only_ordinary_workspace_content() {
    let workspace = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(workspace.path().join(".git")).unwrap();
    std::fs::create_dir_all(workspace.path().join(".a3s")).unwrap();
    std::fs::write(workspace.path().join(".git/config"), "original-git").unwrap();
    std::fs::write(workspace.path().join(".a3s/policy.acl"), "original-policy").unwrap();
    let sandbox = NativeSandbox::new(workspace.path()).unwrap();

    sandbox.probe().await.unwrap();
    #[cfg(not(windows))]
    let ordinary_command = "printf changed > ordinary.txt";
    #[cfg(windows)]
    let ordinary_command =
        "[IO.File]::WriteAllText((Join-Path (Get-Location) 'ordinary.txt'), 'changed')";
    let ordinary = sandbox.exec_command(ordinary_command).await.unwrap();
    assert_eq!(ordinary.exit_code, 0, "{}", ordinary.stderr);
    assert_eq!(
        std::fs::read_to_string(workspace.path().join("ordinary.txt")).unwrap(),
        "changed"
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
        let output = sandbox.exec_command(command).await.unwrap();
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
    let create = sandbox.exec_command(create_command).await.unwrap();
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
    let sandbox = NativeSandbox::new(workspace.path()).unwrap();

    for command in [
        "cat .env",
        "cat outside-hardlink",
        "printf escaped > outside-hardlink",
        "printf escaped > outside-link/symlink-escape",
    ] {
        let output = sandbox.exec_command(command).await.unwrap();
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
    let output = sandbox
        .exec_command("ln link-source new-hardlink")
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
    let sandbox = NativeSandbox::new(workspace.path()).unwrap();

    let output = sandbox
        .exec_command(
            "[IO.File]::WriteAllText((Join-Path (Get-Location) 'outside-hardlink'), 'escaped')",
        )
        .await
        .unwrap();
    assert_ne!(output.exit_code, 0, "hard-link write escape succeeded");
    assert_eq!(
        std::fs::read_to_string(outside_secret).unwrap(),
        "outside-secret"
    );
}

#[tokio::test]
async fn native_backend_blocks_ip_binding_and_unix_sockets() {
    let workspace = tempfile::tempdir().unwrap();
    let sandbox = NativeSandbox::new(workspace.path()).unwrap();

    #[cfg(windows)]
    let probes = [
        "$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0); $listener.Start()",
        "$socket = [System.Net.Sockets.Socket]::new([System.Net.Sockets.AddressFamily]::Unix, [System.Net.Sockets.SocketType]::Stream, [System.Net.Sockets.ProtocolType]::Unspecified)",
    ];
    #[cfg(not(windows))]
    let probes = [
        "python3 -c 'import socket; s=socket.socket(); s.bind((\"127.0.0.1\", 0))'",
        "python3 -c 'import socket; s=socket.socket(socket.AF_UNIX); s.bind(\"blocked.sock\")'",
    ];

    for probe in probes {
        let output = sandbox.exec_command(probe).await.unwrap();
        assert_ne!(
            output.exit_code, 0,
            "socket probe unexpectedly succeeded: {}{}",
            output.stdout, output.stderr
        );
    }
}

#[tokio::test]
async fn native_backend_sanitizes_environment_and_kills_timed_out_descendants() {
    let workspace = tempfile::tempdir().unwrap();
    let sandbox = NativeSandbox::new(workspace.path()).unwrap();
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
