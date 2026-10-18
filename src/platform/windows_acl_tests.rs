#![cfg(test)]

use super::*;
use windows_sys::Win32::Security::Authorization::{GetEffectiveRightsFromAclW, TRUSTEE_W};
use windows_sys::Win32::Storage::FileSystem::FILE_WRITE_DATA;

fn write_rights(path: &Path, sid: &SidBuffer) -> u32 {
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
    rights & FILE_WRITE_DATA
}

fn lease(sid: &SidBuffer) -> ExecutionAcls {
    ExecutionAcls {
        sid: sid.clone(),
        paths: Vec::new(),
        modified: HashSet::new(),
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
