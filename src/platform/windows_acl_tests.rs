#![cfg(test)]

use super::*;
use windows_sys::Win32::Security::Authorization::{
    GetEffectiveRightsFromAclW, SetNamedSecurityInfoW, TRUSTEE_W,
};
use windows_sys::Win32::Storage::FileSystem::FILE_WRITE_DATA;

fn write_rights(path: &Path, sid: &SidBuffer) -> u32 {
    file_rights(path, sid) & FILE_WRITE_DATA
}

fn file_rights(path: &Path, sid: &SidBuffer) -> u32 {
    let wide = wide_null(path.as_os_str());
    let (acl, _descriptor) = query_path_dacl(path, &wide).unwrap();
    assert!(!acl.is_null());
    let trustee = TRUSTEE_W {
        TrusteeForm: TRUSTEE_IS_SID,
        TrusteeType: TRUSTEE_IS_UNKNOWN,
        ptstrName: sid.as_ptr().cast(),
        ..Default::default()
    };
    let mut rights = 0;
    assert_eq!(
        unsafe { GetEffectiveRightsFromAclW(acl, &trustee, &mut rights) },
        0
    );
    rights
}

fn lease(sid: &SidBuffer) -> ExecutionAcls {
    ExecutionAcls {
        sid: sid.clone(),
        paths: Vec::new(),
        modified: HashSet::new(),
        journal: None,
        pending: None,
    }
}

#[test]
fn independent_sandboxes_do_not_share_an_appcontainer_identity() {
    let first = AppContainerProfile::create().unwrap();
    let second = AppContainerProfile::create().unwrap();
    assert_ne!(
        first.sid.words, second.sid.words,
        "independent sandboxes share filesystem authority"
    );
}

#[test]
fn releasing_one_acl_lease_preserves_another_live_lease() {
    let directory = tempfile::tempdir().unwrap();
    let target = directory.path().join("shared-acl-target");
    std::fs::write(&target, b"fixture").unwrap();
    let wide = wide_null(target.as_os_str());
    let (original, _descriptor) = query_path_dacl(&target, &wide).unwrap();
    let first = AppContainerProfile::create().unwrap();
    let second = AppContainerProfile::create().unwrap();
    let mut left = lease(&first.sid);
    let mut right = lease(&second.sid);
    left.modify(&target, FILE_GENERIC_WRITE, GRANT_ACCESS)
        .unwrap();
    left.restrict(&target, FILE_GENERIC_READ).unwrap();
    right
        .modify(&target, FILE_GENERIC_WRITE, GRANT_ACCESS)
        .unwrap();
    left.restore().unwrap();
    let second_while_live = write_rights(&target, &second.sid);
    right.restore().unwrap();
    let first_after_release = write_rights(&target, &first.sid);
    let second_after_release = write_rights(&target, &second.sid);
    set_dacl_on_object(&target, &wide, original, DACL_SECURITY_INFORMATION).unwrap();

    assert_ne!(
        second_while_live, 0,
        "restoring one lease revoked another live lease"
    );
    assert_eq!(
        first_after_release, 0,
        "a released lease was reintroduced by a stale snapshot"
    );
    assert_eq!(second_after_release, 0);
}

fn acl_state(path: &Path) -> (bool, Vec<Vec<u8>>) {
    use windows_sys::Win32::Security::{
        GetAce, GetSecurityDescriptorControl, ACE_HEADER, SE_DACL_PROTECTED,
    };
    let wide = wide_null(path.as_os_str());
    let (acl, descriptor) = query_path_dacl(path, &wide).unwrap();
    assert!(!acl.is_null());
    let mut control = 0;
    let mut revision = 0;
    assert_ne!(
        unsafe { GetSecurityDescriptorControl(descriptor.0, &mut control, &mut revision) },
        0
    );
    let mut entries = Vec::new();
    for index in 0..u32::from(unsafe { (*acl).AceCount }) {
        let mut entry = null_mut();
        assert_ne!(unsafe { GetAce(acl, index, &mut entry) }, 0);
        let length = usize::from(unsafe { (*entry.cast::<ACE_HEADER>()).AceSize });
        entries.push(unsafe { std::slice::from_raw_parts(entry.cast::<u8>(), length) }.to_vec());
    }
    entries.sort();
    (control & SE_DACL_PROTECTED != 0, entries)
}

#[tokio::test]
async fn restarting_after_host_death_restores_workspace_authorization() {
    const CHILD: &str = "A3S_SANDBOX_TEST_ACL_CRASH_CHILD";
    if let Some(workspace) = std::env::var_os(CHILD) {
        let workspace = PathBuf::from(workspace);
        let ready = workspace
            .join("ready")
            .to_string_lossy()
            .replace('\'', "''");
        let sandbox = crate::NativeSandbox::new(&workspace).unwrap();
        sandbox
            .exec_command(format!(
                "[IO.File]::WriteAllText('{ready}', 'running'); Start-Sleep -Seconds 120"
            ))
            .await
            .unwrap();
        panic!("the fixture host must be terminated while its command is running");
    }

    let workspace = tempfile::tempdir().unwrap();
    let control = workspace.path().join(".git");
    let policy = control.join("config");
    std::fs::create_dir(&control).unwrap();
    std::fs::write(&policy, b"host-policy").unwrap();
    let paths = [workspace.path(), control.as_path(), policy.as_path()];
    let original = paths.map(acl_state);
    let mut owner = tokio::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "platform::windows_security::acl_tests::restarting_after_host_death_restores_workspace_authorization",
            "--nocapture",
        ])
        .env(CHILD, workspace.path())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(60), async {
        while !workspace.path().join("ready").exists() {
            assert!(owner.try_wait().unwrap().is_none(), "fixture host exited");
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the real sandbox command must run before host termination");
    assert_ne!(
        acl_state(workspace.path()),
        original[0],
        "the fixture must observe active temporary authorization"
    );
    owner.start_kill().unwrap();
    let status = tokio::time::timeout(std::time::Duration::from_secs(5), owner.wait())
        .await
        .unwrap()
        .unwrap();
    assert!(!status.success());

    let replacement = crate::NativeSandbox::new(workspace.path()).unwrap();
    let output = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        replacement.exec_command("[Console]::Out.Write('recovered')"),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(output.exit_code, 0, "{output:?}");
    assert_eq!(output.stdout, "recovered");
    for (path, expected) in paths.into_iter().zip(original) {
        assert_eq!(
            acl_state(path),
            expected,
            "restarting left stale workspace authorization on {}",
            path.display()
        );
    }
    assert_eq!(std::fs::read(&policy).unwrap(), b"host-policy");
}

#[test]
fn cleanup_preserves_host_acl_entries_and_inheritance() {
    for already_protected in [false, true] {
        let workspace = tempfile::tempdir().unwrap();
        let control = workspace.path().join("control");
        let leaf = control.join("policy");
        std::fs::create_dir(&control).unwrap();
        std::fs::write(&leaf, b"host-policy").unwrap();
        if already_protected {
            let wide = wide_null(control.as_os_str());
            let (acl, _descriptor) = query_path_dacl(&control, &wide).unwrap();
            assert_eq!(
                unsafe {
                    SetNamedSecurityInfoW(
                        wide.as_ptr(),
                        SE_FILE_OBJECT,
                        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                        null_mut(),
                        null_mut(),
                        acl,
                        null(),
                    )
                },
                0
            );
        }
        let paths = [workspace.path(), control.as_path(), leaf.as_path()];
        let original = paths.map(acl_state);
        let profile = AppContainerProfile::create().unwrap();
        let mut permissions = lease(&profile.sid);
        permissions
            .modify(
                workspace.path(),
                FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE,
                GRANT_ACCESS,
            )
            .unwrap();
        permissions
            .restrict(&control, FILE_GENERIC_READ | FILE_GENERIC_EXECUTE)
            .unwrap();
        permissions.restore().unwrap();
        for (path, expected) in paths.into_iter().zip(original) {
            assert_eq!(
                acl_state(path),
                expected,
                "host ACL changed permanently for {}",
                path.display()
            );
        }
    }
}

#[test]
fn cleanup_preserves_acl_edits_made_while_a_directory_is_protected() {
    let workspace = tempfile::tempdir().unwrap();
    let control = workspace.path().join("control");
    std::fs::create_dir(&control).unwrap();
    let sandbox = AppContainerProfile::create().unwrap();
    let other = AppContainerProfile::create().unwrap();
    let mut permissions = lease(&sandbox.sid);
    permissions
        .modify(workspace.path(), FILE_GENERIC_WRITE, GRANT_ACCESS)
        .unwrap();
    permissions.restrict(&control, FILE_GENERIC_READ).unwrap();
    let mut concurrent = lease(&other.sid);
    concurrent
        .modify(&control, FILE_GENERIC_WRITE, GRANT_ACCESS)
        .unwrap();

    permissions.restore().unwrap();

    assert_eq!(write_rights(&control, &sandbox.sid), 0);
    assert_ne!(
        write_rights(&control, &other.sid),
        0,
        "cleanup discarded an ACL edit made during execution"
    );
    concurrent.restore().unwrap();
}

#[test]
fn cross_host_acl_mutations_wait_for_the_current_owner() {
    const FIXTURE: &str = "A3S_SANDBOX_ACL_MUTEX_FIXTURE";
    if let Some(directory) = std::env::var_os(FIXTURE) {
        let directory = PathBuf::from(directory);
        let attempt = match lock_acl_mutation(0) {
            Ok(guard) => {
                drop(guard);
                "acquired"
            }
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|error| error.kind() == std::io::ErrorKind::WouldBlock) =>
            {
                "blocked"
            }
            Err(error) => panic!("ACL peer could not attempt the mutex: {error:#}"),
        };
        std::fs::write(directory.join("ready"), attempt).unwrap();
        let _guard = lock_acl_mutation(5_000).unwrap();
        std::fs::write(directory.join("entered"), b"entered").unwrap();
        return;
    }

    struct ChildGuard(std::process::Child);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let directory = tempfile::tempdir().unwrap();
    let guard = lock_acl_mutation(5_000).unwrap();
    let mut child = ChildGuard(std::process::Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("platform::windows_security::acl_tests::cross_host_acl_mutations_wait_for_the_current_owner")
        .env(FIXTURE, directory.path())
        .stdout(std::process::Stdio::null())
        .spawn().unwrap());
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !directory.path().join("ready").exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "ACL peer did not reach its lock attempt"
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    let first_attempt = std::fs::read_to_string(directory.path().join("ready")).unwrap();
    drop(guard);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let status = loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            break status;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "ACL peer did not acquire the released lock"
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
    };
    assert!(status.success());
    assert!(directory.path().join("entered").exists());
    assert_eq!(
        first_attempt, "blocked",
        "another host entered an owned ACL mutation section"
    );
}

#[test]
fn abandoned_acl_mutation_ownership_is_recovered_without_rust_cleanup() {
    const FIXTURE: &str = "A3S_SANDBOX_ACL_ABANDONED_FIXTURE";
    if let Some(directory) = std::env::var_os(FIXTURE) {
        let directory = PathBuf::from(directory);
        let _guard = lock_acl_mutation(5_000).unwrap();
        std::fs::write(directory.join("owned"), b"owned").unwrap();
        std::thread::sleep(std::time::Duration::from_secs(30));
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let guard = lock_acl_mutation(5_000).unwrap();
    let retained_object = guard.handle.try_clone().unwrap();
    drop(guard);
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("platform::windows_security::acl_tests::abandoned_acl_mutation_ownership_is_recovered_without_rust_cleanup")
        .env(FIXTURE, directory.path()).stdout(std::process::Stdio::null()).spawn().unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !directory.path().join("owned").exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    let owned = directory.path().join("owned").exists();
    child.kill().unwrap();
    child.wait().unwrap();
    assert!(
        owned,
        "ACL peer did not own the mutex before forced termination"
    );
    let recovered = lock_acl_mutation(0).expect("abandoned ACL ownership must be recoverable");
    drop(recovered);
    drop(retained_object);
}

#[tokio::test]
async fn appcontainer_cannot_open_the_host_acl_mutation_mutex() {
    let guard = lock_acl_mutation(5_000).unwrap();
    let retained_object = guard.handle.try_clone().unwrap();
    drop(guard);
    let workspace = tempfile::tempdir().unwrap();
    let sandbox = crate::NativeSandbox::new(workspace.path()).unwrap();
    let command = format!(
        "try {{ $mutex = [Threading.Mutex]::OpenExisting('{}') }} catch [UnauthorizedAccessException] {{ [Console]::Out.Write('mutex-denied'); exit 0 }} catch [Threading.WaitHandleCannotBeOpenedException] {{ [Console]::Out.Write('mutex-denied'); exit 0 }}; $mutex.Dispose(); throw 'guest opened host ACL mutex'",
        ACL_MUTATION_MUTEX_NAME,
    );
    let output = sandbox.exec_command(command).await.unwrap();
    assert_eq!(output.exit_code, 0, "{output:?}");
    assert_eq!(output.stdout, "mutex-denied");
    drop(retained_object);
}

#[test]
fn failed_recovery_intent_does_not_change_authorization() {
    let workspace = tempfile::tempdir().unwrap();
    let original = acl_state(workspace.path());
    let profile = AppContainerProfile::create().unwrap();
    let target = open_acl_target(workspace.path()).unwrap();
    let mut protection = None;
    let error = modify_path_acl(
        &target,
        workspace.path(),
        &profile.sid,
        AclChange {
            permissions: FILE_GENERIC_READ,
            access_mode: SET_ACCESS,
            inheritance: SUB_CONTAINERS_AND_OBJECTS_INHERIT,
            protection: DaclProtection::Restrict,
        },
        &mut protection,
        |_| {
            assert_eq!(acl_state(workspace.path()), original);
            bail!("recovery intent storage unavailable")
        },
    )
    .unwrap_err();
    assert!(error
        .to_string()
        .contains("recovery intent storage unavailable"));
    assert_eq!(acl_state(workspace.path()), original);
}

#[tokio::test]
async fn persisted_recovery_refuses_replaced_objects_and_preserves_other_authority() {
    let workspace = tempfile::tempdir().unwrap();
    let directory =
        super::super::windows_workspace::WorkspaceDirectory::capture(workspace.path()).unwrap();
    let owner = directory.acquire().await.unwrap();
    let target = workspace.path().join("target");
    let moved = workspace.path().join("original-target");
    std::fs::write(&target, b"original").unwrap();
    let original = acl_state(&target);
    let profile = AppContainerProfile::create().unwrap();
    let other = AppContainerProfile::create().unwrap();
    let mut permissions = lease(&profile.sid);
    permissions.journal = Some(RecoveryJournal::open(&owner.journal_name).unwrap());
    permissions
        .modify(&target, FILE_GENERIC_WRITE, GRANT_ACCESS)
        .unwrap();
    permissions.restrict(&target, FILE_GENERIC_READ).unwrap();
    let mut concurrent = lease(&other.sid);
    concurrent
        .modify(&target, FILE_GENERIC_WRITE, GRANT_ACCESS)
        .unwrap();
    let journal = permissions.journal.take().unwrap();
    permissions.paths.clear();
    drop(permissions);

    std::fs::rename(&target, &moved).unwrap();
    std::fs::write(&target, b"replacement").unwrap();
    let replacement_acl = acl_state(&target);
    let error = ExecutionAcls::recover(&owner).unwrap_err();
    assert!(format!("{error:#}").contains("target identity changed"));
    assert_eq!(
        acl_state(&target),
        replacement_acl,
        "recovery changed an unrelated replacement"
    );
    assert!(
        journal.read().unwrap().is_some(),
        "failed recovery discarded its obligations"
    );
    assert_eq!(std::fs::read(&target).unwrap(), b"replacement");

    std::fs::remove_file(&target).unwrap();
    std::fs::rename(&moved, &target).unwrap();
    ExecutionAcls::recover(&owner).unwrap();
    assert!(journal.read().unwrap().is_none());
    assert_eq!(write_rights(&target, &profile.sid), 0);
    assert_ne!(
        write_rights(&target, &other.sid),
        0,
        "recovery removed another live authority"
    );
    concurrent.restore().unwrap();
    assert_eq!(acl_state(&target), original);
}

#[tokio::test]
async fn invalid_journal_prevents_command_start_and_is_retained() {
    let workspace = tempfile::tempdir().unwrap();
    let directory =
        super::super::windows_workspace::WorkspaceDirectory::capture(workspace.path()).unwrap();
    let owner = directory.acquire().await.unwrap();
    let journal = RecoveryJournal::open(&owner.journal_name).unwrap();
    journal.write(b"not a recovery record").unwrap();
    drop(owner);
    let sandbox = crate::NativeSandbox::new(workspace.path()).unwrap();
    let result = sandbox
        .exec_command("[IO.File]::WriteAllText('command-started', 'unsafe')")
        .await;
    let retained = journal.read().unwrap();
    journal.clear().unwrap();
    assert!(format!("{:#}", result.unwrap_err())
        .contains("decode Windows authorization recovery journal"));
    assert!(!workspace.path().join("command-started").exists());
    assert_eq!(retained.unwrap(), b"not a recovery record");
}

#[tokio::test]
async fn appcontainer_cannot_write_host_recovery_journal() {
    let workspace = tempfile::tempdir().unwrap();
    let marker = format!("guest-marker-{}", appcontainer_profile_name());
    let journal = RecoveryJournal::open(&marker).unwrap();
    let sandbox = crate::NativeSandbox::new(workspace.path()).unwrap();
    let command = format!(
        "try {{ $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('{}', $true); if ($null -eq $key) {{ throw [Security.SecurityException]::new('inaccessible') }}; $key.SetValue('{marker}', [byte[]](1,2,3), [Microsoft.Win32.RegistryValueKind]::Binary); $key.Dispose() }} catch [Security.SecurityException] {{ [Console]::Out.Write('journal-denied'); exit 0 }} catch [UnauthorizedAccessException] {{ [Console]::Out.Write('journal-denied'); exit 0 }}; throw 'guest wrote host recovery journal'",
        super::super::windows_recovery::RECOVERY_KEY,
    );
    let output = sandbox.exec_command(command).await.unwrap();
    let stored = journal.read().unwrap();
    journal.clear().unwrap();
    assert_eq!(output.exit_code, 0, "{output:?}");
    assert_eq!(output.stdout, "journal-denied");
    assert!(
        stored.is_none(),
        "untrusted guest wrote host recovery intent"
    );
}

#[test]
fn canonical_system_toolchains_do_not_receive_temporary_grants() {
    const CHILD: &str = "A3S_SANDBOX_TEST_SYSTEM_TOOLCHAIN";
    if let Some(root) = std::env::var_os(CHILD) {
        let root = PathBuf::from(root);
        let system = root.join("system").canonicalize().unwrap();
        let binary = system.join("tool.exe");
        let original = [acl_state(&system), acl_state(&binary)];
        let profile = AppContainerProfile::create().unwrap();
        let mut permissions = lease(&profile.sid);
        permissions
            .grant_user_toolchain_binaries(
                std::slice::from_ref(&system),
                &root.join("workspace"),
                &root.join("scratch"),
            )
            .unwrap();
        assert_eq!(
            acl_state(&system),
            original[0],
            "a canonical system root received a grant"
        );
        assert_eq!(
            acl_state(&binary),
            original[1],
            "a system binary received a grant"
        );
        return;
    }
    let root = tempfile::tempdir().unwrap();
    for name in ["system", "workspace", "scratch"] {
        std::fs::create_dir(root.path().join(name)).unwrap();
    }
    std::fs::write(root.path().join("system/tool.exe"), b"fixture").unwrap();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "platform::windows_security::acl_tests::canonical_system_toolchains_do_not_receive_temporary_grants", "--nocapture"])
        .env(CHILD, root.path())
        .env("PROGRAMFILES", root.path().join("system"))
        .status().unwrap();
    assert!(status.success(), "canonical system-tree exclusion failed");
}

#[test]
fn optional_toolchain_aliases_do_not_authorize_targets_or_abort_other_tools() {
    use windows_sys::Win32::Storage::FileSystem::FILE_READ_DATA;
    let root = tempfile::tempdir().unwrap();
    let tools = root.path().join("tools");
    let outside = root.path().join("outside.exe");
    let ordinary = tools.join("ordinary.exe");
    std::fs::create_dir(&tools).unwrap();
    std::fs::write(&outside, b"outside").unwrap();
    std::fs::write(&ordinary, b"ordinary").unwrap();
    std::os::windows::fs::symlink_file(&outside, tools.join("alias.exe")).unwrap();
    let original = acl_state(&outside);
    let profile = AppContainerProfile::create().unwrap();
    let mut permissions = lease(&profile.sid);
    permissions
        .grant_user_toolchain_binaries(
            &[tools],
            &root.path().join("workspace"),
            &root.path().join("scratch"),
        )
        .unwrap();
    assert_ne!(file_rights(&ordinary, &profile.sid) & FILE_READ_DATA, 0);
    assert_eq!(write_rights(&ordinary, &profile.sid), 0);
    assert_eq!(
        acl_state(&outside),
        original,
        "a tool alias authorized its external target"
    );
    permissions.restore().unwrap();
    assert_eq!(file_rights(&ordinary, &profile.sid) & FILE_READ_DATA, 0);
}
