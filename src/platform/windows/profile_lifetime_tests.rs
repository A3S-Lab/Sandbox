#![cfg(test)]

use super::super::windows_recovery::RecoveryJournal;
use super::*;
use std::time::Duration;
use windows_sys::Win32::Security::FreeSid;
use windows_sys::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeleteAppContainerProfile,
};

fn profile_journal(lease: &WorkspaceLease) -> RecoveryJournal {
    RecoveryJournal::open(&format!("{}.profile", lease.journal_name)).unwrap()
}

fn registered_profile_remains(name: &str) -> bool {
    let name = wide_null(OsStr::new(name));
    let label = wide_null(OsStr::new("A3S profile lifetime oracle"));
    let mut sid = null_mut();
    let status = unsafe {
        CreateAppContainerProfile(
            name.as_ptr(),
            label.as_ptr(),
            label.as_ptr(),
            null(),
            0,
            &mut sid,
        )
    };
    if !sid.is_null() {
        unsafe { FreeSid(sid) };
    }
    assert!(
        status >= 0 || status as u32 == 0x8007_00b7,
        "profile oracle failed: 0x{:08x}",
        status as u32
    );
    let cleanup = unsafe { DeleteAppContainerProfile(name.as_ptr()) };
    assert!(
        cleanup >= 0,
        "owned fixture profile cleanup failed: 0x{:08x}",
        cleanup as u32
    );
    status as u32 == 0x8007_00b7
}

#[test]
fn constructing_a_sandbox_does_not_register_a_persistent_profile() {
    let workspace = tempfile::tempdir().unwrap();
    let sandbox = crate::NativeSandbox::new(workspace.path()).unwrap();
    let registered = registered_profile_remains(&sandbox.platform.profile.name);
    drop(sandbox);
    assert!(
        !registered,
        "constructing a sandbox registered persistent AppContainer state"
    );
}

#[tokio::test]
async fn completing_a_command_leaves_no_persistent_profile() {
    let workspace = tempfile::tempdir().unwrap();
    let sandbox = crate::NativeSandbox::new(workspace.path()).unwrap();
    let name = sandbox.platform.profile.name.clone();
    let output = sandbox
        .exec_command("[Console]::Out.Write('profile-complete')")
        .await
        .unwrap();
    assert_eq!(output.exit_code, 0, "{output:?}");
    assert_eq!(output.stdout, "profile-complete");
    drop(sandbox);
    assert!(
        !registered_profile_remains(&name),
        "an AppContainer profile survived the completed command"
    );
}

#[tokio::test]
async fn recovery_before_profile_creation_clears_its_intent_idempotently() {
    let workspace = tempfile::tempdir().unwrap();
    let directory = WorkspaceDirectory::capture(workspace.path()).unwrap();
    let lease = directory.acquire().await.unwrap();
    let profile = AppContainerProfile::create().unwrap();
    let journal = profile_journal(&lease);
    journal
        .write(
            &serde_json::to_vec(&serde_json::json!({
                "version": 1,
                "workspace": lease.journal_name,
                "name": profile.name,
                "sid": profile.sid,
            }))
            .unwrap(),
        )
        .unwrap();
    AppContainerProfile::recover(&lease).unwrap();
    AppContainerProfile::recover(&lease).unwrap();
    assert!(journal.read().unwrap().is_none());
    assert!(!registered_profile_remains(&profile.name));
}

#[tokio::test]
async fn registration_does_not_overwrite_pending_recovery_or_create_a_profile() {
    let workspace = tempfile::tempdir().unwrap();
    let directory = WorkspaceDirectory::capture(workspace.path()).unwrap();
    let lease = directory.acquire().await.unwrap();
    let profile = AppContainerProfile::create().unwrap();
    let journal = profile_journal(&lease);
    journal.write(b"pending recovery").unwrap();
    let error = profile
        .register(&lease)
        .err()
        .expect("pending recovery must block registration");
    let retained = journal.read().unwrap();
    journal.clear().unwrap();
    assert!(error.to_string().contains("profile recovery is incomplete"));
    assert_eq!(retained.unwrap(), b"pending recovery");
    assert!(!registered_profile_remains(&profile.name));
}

#[tokio::test]
async fn invalid_profile_identity_blocks_start_and_preserves_recovery_state() {
    for field in ["version", "workspace", "name", "sid"] {
        let workspace = tempfile::tempdir().unwrap();
        let directory = WorkspaceDirectory::capture(workspace.path()).unwrap();
        let lease = directory.acquire().await.unwrap();
        let profile = AppContainerProfile::create().unwrap();
        let other = AppContainerProfile::create().unwrap();
        let mut registered = profile.register(&lease).unwrap();
        let journal = profile_journal(&lease);
        let mut intent: serde_json::Value =
            serde_json::from_slice(&journal.read().unwrap().unwrap()).unwrap();
        intent[field] = match field {
            "version" => 2.into(),
            "workspace" => "unrelated-workspace".into(),
            "name" => "unrelated-profile".into(),
            "sid" => serde_json::to_value(&other.sid).unwrap(),
            _ => unreachable!(),
        };
        let bytes = serde_json::to_vec(&intent).unwrap();
        journal.write(&bytes).unwrap();
        drop(lease);
        let sandbox = crate::NativeSandbox::new(workspace.path()).unwrap();
        let result = sandbox
            .exec_command("[IO.File]::WriteAllText('profile-invalid-started', 'unsafe')")
            .await;
        let retained = journal.read().unwrap();
        let untouched = registered_profile_remains(&profile.name);
        registered.remove().unwrap();
        assert!(format!("{:#}", result.unwrap_err()).contains("invalid identity or workspace"));
        assert!(!workspace.path().join("profile-invalid-started").exists());
        assert_eq!(retained.unwrap(), bytes);
        assert!(
            untouched,
            "invalid recovery removed the owned fixture profile: {field}"
        );
    }
}

#[tokio::test]
async fn restarting_after_host_death_leaves_no_persistent_profile() {
    const CHILD: &str = "A3S_SANDBOX_TEST_PROFILE_CRASH_CHILD";
    if let Some(root) = std::env::var_os(CHILD) {
        let root = PathBuf::from(root);
        let workspace = root.join("workspace");
        let sandbox = crate::NativeSandbox::new(&workspace).unwrap();
        std::fs::write(
            root.join("host-profile-name"),
            &sandbox.platform.profile.name,
        )
        .unwrap();
        let ready = workspace
            .join("ready")
            .to_string_lossy()
            .replace('\'', "''");
        sandbox
            .exec_command(format!(
                "[IO.File]::WriteAllText('{ready}', 'running'); Start-Sleep -Seconds 120"
            ))
            .await
            .unwrap();
        panic!("the fixture host must be killed during the real command");
    }

    let root = tempfile::tempdir().unwrap();
    let workspace = root.path().join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    let mut child = tokio::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "platform::windows::profile_lifetime_tests::restarting_after_host_death_leaves_no_persistent_profile", "--nocapture"])
        .env(CHILD, root.path())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::inherit())
        .kill_on_drop(true)
        .spawn().unwrap();
    tokio::time::timeout(Duration::from_secs(60), async {
        while !workspace.join("ready").exists() {
            assert!(
                child.try_wait().unwrap().is_none(),
                "fixture host exited before its command ran"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the real command must start before the host is killed");
    let name = std::fs::read_to_string(root.path().join("host-profile-name")).unwrap();
    child.start_kill().unwrap();
    let status = tokio::time::timeout(Duration::from_secs(5), child.wait())
        .await
        .unwrap()
        .unwrap();
    assert!(!status.success());

    let replacement = crate::NativeSandbox::new(&workspace).unwrap();
    let replacement_name = replacement.platform.profile.name.clone();
    let output = tokio::time::timeout(
        Duration::from_secs(30),
        replacement.exec_command("[Console]::Out.Write('profile-restarted')"),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(output.exit_code, 0, "{output:?}");
    assert_eq!(output.stdout, "profile-restarted");
    drop(replacement);
    let abandoned = registered_profile_remains(&name);
    let completed = registered_profile_remains(&replacement_name);
    assert!(
        !abandoned,
        "the terminated host's AppContainer profile survived restart"
    );
    assert!(!completed, "the recovery host left an AppContainer profile");
}
