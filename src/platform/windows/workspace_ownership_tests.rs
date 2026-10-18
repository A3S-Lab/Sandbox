#![cfg(test)]

use super::*;
use std::io::{Read, Write};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

async fn acquire(workspace: &Path) -> tokio::sync::OwnedMutexGuard<()> {
    workspace_execution_gate(workspace).lock_owned().await
}

#[tokio::test]
async fn same_physical_workspace_is_serialized_across_hosts() {
    const CHILD: &str = "A3S_SANDBOX_TEST_WORKSPACE_LEASE_CHILD";
    if let Some(workspace) = std::env::var_os(CHILD) {
        let workspace = PathBuf::from(workspace);
        if tokio::time::timeout(Duration::from_millis(250), acquire(&workspace))
            .await
            .is_ok()
        {
            println!("A3S_LEASE_ENTERED_WHILE_PARENT_OWNS");
            std::io::stdout().flush().unwrap();
            panic!("another host still owns this workspace");
        }
        println!("A3S_LEASE_WAIT_BLOCKED");
        std::io::stdout().flush().unwrap();
        std::io::stdin().read_exact(&mut [0]).unwrap();
        let _lease = tokio::time::timeout(Duration::from_secs(5), acquire(&workspace))
            .await
            .unwrap();
        std::fs::write(workspace.join("child-acquired"), b"after release").unwrap();
        return;
    }

    let workspace = tempfile::tempdir().unwrap();
    let lease = acquire(workspace.path()).await;
    let mut child = tokio::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "platform::windows::workspace_ownership_tests::same_physical_workspace_is_serialized_across_hosts",
            "--nocapture",
        ])
        .env(CHILD, workspace.path())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let mut line = String::new();
            assert!(output.read_line(&mut line).await.unwrap() > 0);
            assert!(
                !line.contains("A3S_LEASE_ENTERED_WHILE_PARENT_OWNS"),
                "a second host acquired the live workspace lease"
            );
            if line.contains("A3S_LEASE_WAIT_BLOCKED") {
                break;
            }
        }
    })
    .await
    .expect("the child must make an acquisition attempt before parent release");
    assert!(!workspace.path().join("child-acquired").exists());
    drop(lease);
    child.stdin.take().unwrap().write_all(b"r").await.unwrap();
    let status = tokio::time::timeout(Duration::from_secs(10), child.wait())
        .await
        .unwrap()
        .unwrap();
    assert!(status.success(), "{status}");
    assert_eq!(
        std::fs::read(workspace.path().join("child-acquired")).unwrap(),
        b"after release"
    );
}

#[tokio::test]
async fn case_aliases_share_one_workspace_owner() {
    let workspace = tempfile::tempdir().unwrap();
    let alias = PathBuf::from(workspace.path().to_string_lossy().to_uppercase());
    assert!(
        alias.is_dir(),
        "the fixture requires a case-insensitive directory"
    );
    let _lease = acquire(workspace.path()).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(100), acquire(&alias))
            .await
            .is_err(),
        "a differently cased path bypassed ownership of the physical directory"
    );
}
