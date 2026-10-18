//! AppContainer identity and temporary Windows filesystem authorization.

use super::windows::{last_windows_error, wide_null, win32_process_path};
use super::windows_recovery::{windows_path, RecoveryJournal};
use super::windows_workspace::{file_identity, FileIdentity, WorkspaceLease};
use crate::policy::EnforcedPolicy;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::ffi::{c_void, OsStr};
use std::fs::{File, OpenOptions};
use std::mem::size_of;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::sync::OnceLock;
use windows_sys::Win32::Foundation::{
    GetLastError, LocalFree, ERROR_ACCESS_DENIED, WAIT_ABANDONED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SetEntriesInAclW,
    SetSecurityInfo, EXPLICIT_ACCESS_W, GRANT_ACCESS, REVOKE_ACCESS, SDDL_REVISION_1, SET_ACCESS,
    SE_FILE_OBJECT, TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN,
};
use windows_sys::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeriveAppContainerSidFromAppContainerName,
};
use windows_sys::Win32::Security::{
    DeleteAce, FreeSid, GetAce, GetLengthSid, GetSecurityDescriptorControl,
    InitializeSecurityDescriptor, IsValidSid, SetKernelObjectSecurity, SetSecurityDescriptorDacl,
    ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, INHERITED_ACE, NO_INHERITANCE,
    PROTECTED_DACL_SECURITY_INFORMATION, PSID, SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR,
    SE_DACL_PROTECTED, SUB_CONTAINERS_AND_OBJECTS_INHERIT, UNPROTECTED_DACL_SECURITY_INFORMATION,
};
use windows_sys::Win32::Storage::FileSystem::{
    DELETE, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_READ_ATTRIBUTES,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE,
};

use windows_sys::Win32::System::Threading::{
    CreateMutexExW, ReleaseMutex, WaitForSingleObject, MUTEX_MODIFY_STATE,
    SYNCHRONIZATION_SYNCHRONIZE,
};

const HRESULT_ALREADY_EXISTS: u32 = 0x8007_00b7;
const READ_CONTROL: u32 = 0x0002_0000;
const WRITE_DAC: u32 = 0x0004_0000;
/// WindowsApps execution aliases and other reparse stubs often return this
/// when CreateFile tries to open them for WRITE_DAC.
const ERROR_CANT_RESOLVE_FILENAME: u32 = 1920;

fn is_skippable_acl_error(code: u32) -> bool {
    code == ERROR_ACCESS_DENIED || code == ERROR_CANT_RESOLVE_FILENAME
}

#[derive(Debug)]
struct AclDenied {
    path: PathBuf,
}

impl std::fmt::Display for AclDenied {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "Windows denied a filesystem ACL change for {}",
            self.path.display()
        )
    }
}

impl std::error::Error for AclDenied {}

fn acl_denied(path: &Path) -> anyhow::Error {
    anyhow::Error::new(AclDenied {
        path: path.to_path_buf(),
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SidBuffer {
    words: Vec<u32>,
}

impl SidBuffer {
    fn from_allocated(sid: PSID) -> Result<Self> {
        if sid.is_null() {
            bail!("Windows returned an empty AppContainer SID");
        }
        let length = unsafe { GetLengthSid(sid) };
        if length == 0 {
            unsafe {
                FreeSid(sid);
            }
            bail!("Windows returned an invalid AppContainer SID");
        }
        let words = usize::try_from(length)
            .context("AppContainer SID length overflowed")?
            .div_ceil(size_of::<u32>());
        let mut buffer = vec![0_u32; words];
        // SID memory is opaque bytes; a u32 backing buffer supplies sufficient
        // alignment for every Win32 SID routine.
        unsafe {
            std::ptr::copy_nonoverlapping(
                sid.cast::<u8>(),
                buffer.as_mut_ptr().cast::<u8>(),
                usize::try_from(length).unwrap_or(0),
            );
            FreeSid(sid);
        }
        Ok(Self { words: buffer })
    }

    pub(super) fn as_ptr(&self) -> PSID {
        self.words.as_ptr().cast_mut().cast::<c_void>()
    }
}

#[derive(Debug)]
pub(super) struct AppContainerProfile {
    pub(super) sid: SidBuffer,
    #[cfg(test)]
    pub(super) name: String,
}

impl AppContainerProfile {
    pub(super) fn create() -> Result<Self> {
        let profile_name = appcontainer_profile_name();
        let name = wide_null(OsStr::new(&profile_name));
        let display = wide_null(OsStr::new("A3S Native Sandbox"));
        let description = wide_null(OsStr::new(
            "Sandbox-scoped AppContainer for fail-closed A3S command execution",
        ));
        let mut sid = null_mut();
        let status = unsafe {
            CreateAppContainerProfile(
                name.as_ptr(),
                display.as_ptr(),
                description.as_ptr(),
                null(),
                0,
                &mut sid,
            )
        };
        if status as u32 == HRESULT_ALREADY_EXISTS {
            sid = null_mut();
            let derived =
                unsafe { DeriveAppContainerSidFromAppContainerName(name.as_ptr(), &mut sid) };
            if derived < 0 {
                bail!(
                    "DeriveAppContainerSidFromAppContainerName failed with HRESULT 0x{:08x}",
                    derived as u32
                );
            }
        } else if status < 0 {
            bail!(
                "CreateAppContainerProfile failed with HRESULT 0x{:08x}",
                status as u32
            );
        }
        Ok(Self {
            sid: SidBuffer::from_allocated(sid)?,
            #[cfg(test)]
            name: profile_name,
        })
    }
}

fn appcontainer_profile_name() -> String {
    static PROCESS_SCOPE: OnceLock<u128> = OnceLock::new();
    static NEXT_PROFILE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let mut hasher = Sha256::new();
    hasher.update(std::process::id().to_le_bytes());
    hasher.update(
        NEXT_PROFILE
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            .to_le_bytes(),
    );
    let process_scope = PROCESS_SCOPE.get_or_init(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos())
    });
    hasher.update(process_scope.to_le_bytes());
    let digest = hasher.finalize();
    let suffix = digest[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("A3S.Sandbox.Execution.{suffix}")
}

pub(super) struct ExecutionAcls {
    sid: SidBuffer,
    paths: Vec<AclRestoration>,
    modified: HashSet<PathBuf>,
    journal: Option<RecoveryJournal>,
    pending: Option<Vec<PlannedAclChange>>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DaclRestoration {
    protected: bool,
    converted_inherited: Vec<Vec<u8>>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AclRestoration {
    #[serde(with = "windows_path")]
    path: PathBuf,
    identity: FileIdentity,
    local_only: bool,
    protection: Option<DaclRestoration>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AclJournalState {
    version: u8,
    sid: SidBuffer,
    paths: Vec<AclRestoration>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DaclProtection {
    Preserve,
    Restrict,
    Restore,
}

struct AclChange {
    permissions: u32,
    access_mode: i32,
    inheritance: u32,
    protection: DaclProtection,
}

struct PlannedAclChange {
    target: File,
    index: usize,
    change: AclChange,
}

fn system_tree_prefixes() -> Vec<PathBuf> {
    let mut prefixes = [
        "WINDIR",
        "PROGRAMFILES",
        "PROGRAMFILES(X86)",
        "PROGRAMW6432",
    ]
    .into_iter()
    .filter_map(std::env::var_os)
    .map(PathBuf::from)
    .filter(|path| path.is_absolute())
    .collect::<Vec<_>>();
    // Store execution aliases are not real binaries; opening them for WRITE_DAC
    // returns ERROR_CANT_RESOLVE_FILENAME and must not fail the sandbox.
    if let Some(local_app_data) = std::env::var_os("LOCALAPPDATA") {
        let windows_apps = PathBuf::from(local_app_data)
            .join("Microsoft")
            .join("WindowsApps");
        if windows_apps.is_absolute() {
            prefixes.push(windows_apps);
        }
    }
    prefixes
        .into_iter()
        .map(|path| path.canonicalize().unwrap_or(path))
        .collect()
}

fn is_toolchain_binary(path: &Path) -> bool {
    if !path.is_file() {
        return false;
    }
    let Some(extension) = path.extension().and_then(|extension| extension.to_str()) else {
        return false;
    };
    matches!(
        extension.to_ascii_lowercase().as_str(),
        "exe" | "dll" | "cmd" | "bat" | "com" | "node"
    )
}

impl ExecutionAcls {
    pub(super) fn recover(lease: &WorkspaceLease) -> Result<()> {
        let journal = RecoveryJournal::open(&lease.journal_name)?;
        let Some(bytes) = journal.read()? else {
            return Ok(());
        };
        let state: AclJournalState = serde_json::from_slice(&bytes)
            .context("decode Windows authorization recovery journal")?;
        let words = &state.sid.words;
        // Validate the backing length before any Win32 routine may inspect the opaque SID.
        if state.version != 1
            || words.len() != 10
            || words[0] != 0x0000_0801
            || unsafe { IsValidSid(state.sid.as_ptr()) } == 0
            || words[1] != 0x0f00_0000
            || words[2] != 2
        {
            bail!("Windows authorization recovery journal has an invalid version or package SID");
        }
        let mut guard = Self {
            sid: state.sid,
            modified: state
                .paths
                .iter()
                .map(|record| record.path.clone())
                .collect(),
            paths: state.paths,
            journal: Some(journal),
            pending: None,
        };
        if guard.paths.is_empty() {
            return guard.persist();
        }
        guard
            .restore()
            .context("recover abandoned Windows authorization")
    }

    pub(super) fn apply(
        policy: &EnforcedPolicy,
        sid: &SidBuffer,
        lease: &WorkspaceLease,
    ) -> Result<Self> {
        let _mutation = lock_acl_mutation(5_000)?;
        let journal = RecoveryJournal::open(&lease.journal_name)?;
        if journal.read()?.is_some() {
            bail!("Windows authorization recovery is incomplete");
        }
        let mut guard = Self {
            sid: sid.clone(),
            paths: Vec::new(),
            modified: HashSet::new(),
            journal: Some(journal),
            pending: Some(Vec::new()),
        };
        guard.grant_ancestor_traversal(&policy.workspace)?;
        guard.grant_ancestor_traversal(&policy.scratch)?;
        // Parent DELETE_CHILD would bypass protected children's own delete permissions.
        guard.modify(
            &policy.workspace,
            FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE,
            GRANT_ACCESS,
        )?;
        guard.modify(
            &policy.scratch,
            FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE,
            GRANT_ACCESS,
        )?;
        // System trees already carry AppContainer grants. User-owned PATH
        // binaries do not; grant those files without propagating ACEs.
        guard.grant_user_toolchain_binaries(
            &policy.allow_read,
            &policy.workspace,
            &policy.scratch,
        )?;
        // Typed policy mounts (Gate 3 RO/RW knowledge trees) are granted
        // explicitly — they sit outside workspace/scratch and otherwise stay
        // invisible to the AppContainer.
        for path in &policy.mount_roots {
            if !path.exists() {
                continue;
            }
            guard.grant_ancestor_traversal(path)?;
            if policy.allow_write.iter().any(|writable| writable == path) {
                guard.modify(
                    path,
                    FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE,
                    GRANT_ACCESS,
                )?;
            } else {
                guard.modify(path, FILE_GENERIC_READ | FILE_GENERIC_EXECUTE, GRANT_ACCESS)?;
            }
        }
        for path in &policy.deny_read {
            if !path.exists()
                || !policy
                    .allow_read
                    .iter()
                    .any(|allowed| path.starts_with(allowed))
            {
                continue;
            }
            guard.restrict(path, 0)?;
        }
        for path in &policy.deny_write {
            if policy.deny_read.iter().any(|denied| denied == path)
                || !path.exists()
                || !policy
                    .allow_write
                    .iter()
                    .any(|allowed| path.starts_with(allowed))
            {
                continue;
            }
            guard.restrict(path, FILE_GENERIC_READ | FILE_GENERIC_EXECUTE)?;
        }
        for path in &policy.write_exceptions {
            if path.exists() {
                guard.modify(
                    path,
                    FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE,
                    GRANT_ACCESS,
                )?;
            }
        }
        guard.persist()?;
        let pending = guard.pending.take().context("Windows ACL plan is absent")?;
        for operation in pending {
            let record = &mut guard.paths[operation.index];
            modify_path_acl(
                &operation.target,
                &record.path,
                &guard.sid,
                operation.change,
                &mut record.protection,
                |_| Ok(()),
            )?;
        }
        Ok(guard)
    }

    fn persist(&self) -> Result<()> {
        write_acl_journal(self.journal.as_ref(), &self.sid, &self.paths)
    }

    fn grant_ancestor_traversal(&mut self, path: &Path) -> Result<()> {
        let ancestors = path
            .ancestors()
            .skip(1)
            .filter(|ancestor| ancestor.parent().is_some())
            .collect::<Vec<_>>();
        for ancestor in ancestors.into_iter().rev() {
            // The caller often cannot rewrite `C:\` or `C:\Users`. Skip only
            // that denial; closer ancestors still receive the package SID.
            if let Err(error) = self.modify_with_inheritance(
                ancestor,
                FILE_TRAVERSE,
                GRANT_ACCESS,
                NO_INHERITANCE,
                false,
            ) {
                if error.downcast_ref::<AclDenied>().is_none() {
                    return Err(error);
                }
            }
        }
        Ok(())
    }

    /// Non-inheritable read/execute for binaries in user-owned PATH directories.
    ///
    /// System directories are skipped: the caller often cannot rewrite them,
    /// and they already allow AppContainer execute. Inheritance is never set,
    /// so this does not walk `node_modules` or the user profile.
    fn grant_user_toolchain_binaries(
        &mut self,
        allow_read: &[PathBuf],
        workspace: &Path,
        scratch: &Path,
    ) -> Result<()> {
        let protected = system_tree_prefixes();
        for root in allow_read {
            if root == workspace || root == scratch || !root.is_dir() {
                continue;
            }
            if protected.iter().any(|prefix| root.starts_with(prefix)) {
                continue;
            }
            self.grant_ancestor_traversal(root)?;
            if let Err(error) = self.modify_with_inheritance(
                root,
                FILE_GENERIC_READ | FILE_GENERIC_EXECUTE,
                GRANT_ACCESS,
                NO_INHERITANCE,
                false,
            ) {
                if error.downcast_ref::<AclDenied>().is_none() {
                    return Err(error);
                }
                continue;
            }
            let Ok(entries) = std::fs::read_dir(root) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if !is_toolchain_binary(&path) {
                    continue;
                }
                if let Err(error) = self.modify_with_inheritance(
                    &path,
                    FILE_GENERIC_READ | FILE_GENERIC_EXECUTE,
                    GRANT_ACCESS,
                    NO_INHERITANCE,
                    false,
                ) {
                    if error.downcast_ref::<AclDenied>().is_none() {
                        return Err(error);
                    }
                }
            }
        }
        Ok(())
    }

    fn modify(&mut self, path: &Path, permissions: u32, access_mode: i32) -> Result<()> {
        let inheritance = if path.is_dir() {
            SUB_CONTAINERS_AND_OBJECTS_INHERIT
        } else {
            NO_INHERITANCE
        };
        self.modify_with_inheritance(path, permissions, access_mode, inheritance, false)
    }

    fn restrict(&mut self, path: &Path, permissions: u32) -> Result<()> {
        let inheritance = if path.is_dir() {
            SUB_CONTAINERS_AND_OBJECTS_INHERIT
        } else {
            NO_INHERITANCE
        };
        let access_mode = if permissions == 0 {
            REVOKE_ACCESS
        } else {
            SET_ACCESS
        };
        self.modify_with_inheritance(path, permissions, access_mode, inheritance, true)
    }

    fn modify_with_inheritance(
        &mut self,
        path: &Path,
        permissions: u32,
        access_mode: i32,
        inheritance: u32,
        protect_dacl: bool,
    ) -> Result<()> {
        let target = open_acl_target(path)?;
        let identity = file_identity(&target)?;
        let local_only = inheritance == NO_INHERITANCE && !protect_dacl;
        let tracked = self.modified.contains(path);
        if !tracked {
            self.modified.insert(path.to_path_buf());
            self.paths.push(AclRestoration {
                path: path.to_path_buf(),
                identity: identity.clone(),
                local_only,
                protection: None,
            });
        }
        let index = self
            .paths
            .iter()
            .position(|record| record.path == path)
            .context("Windows ACL restoration record is absent")?;
        if self.paths[index].identity != identity {
            bail!("Windows ACL target identity changed: {}", path.display());
        }
        self.paths[index].local_only &= local_only;
        let protection = if protect_dacl {
            DaclProtection::Restrict
        } else {
            DaclProtection::Preserve
        };
        let change = AclChange {
            permissions,
            access_mode,
            inheritance,
            protection,
        };
        if let Some(pending) = self.pending.as_mut() {
            if protect_dacl && self.paths[index].protection.is_none() {
                self.paths[index].protection = Some(capture_dacl_restoration(&target, path)?);
            }
            pending.push(PlannedAclChange {
                target,
                index,
                change,
            });
            return Ok(());
        }
        let mut pending = self.paths.clone();
        let original_protection = &mut self.paths[index].protection;
        if let Err(error) = modify_path_acl(
            &target,
            path,
            &self.sid,
            change,
            original_protection,
            |protection| {
                pending[index].protection = protection.clone();
                write_acl_journal(self.journal.as_ref(), &self.sid, &pending)
            },
        ) {
            if !tracked
                && original_protection.is_none()
                && error.downcast_ref::<AclDenied>().is_some()
            {
                self.paths.pop();
                self.modified.remove(path);
            }
            return Err(error);
        }
        Ok(())
    }

    pub(super) fn restore(&mut self) -> Result<()> {
        if self.pending.is_some() || self.paths.is_empty() {
            return Ok(());
        }
        let _mutation = lock_acl_mutation(5_000)?;
        let mut failure = None;
        for index in (0..self.paths.len()).rev() {
            let record = &mut self.paths[index];
            let inheritance = if record.local_only {
                NO_INHERITANCE
            } else {
                SUB_CONTAINERS_AND_OBJECTS_INHERIT
            };
            let restored = (|| {
                let target = open_acl_target(&record.path)?;
                if file_identity(&target)? != record.identity {
                    bail!(
                        "Windows ACL recovery target identity changed: {}",
                        record.path.display()
                    );
                }
                modify_path_acl(
                    &target,
                    &record.path,
                    &self.sid,
                    AclChange {
                        permissions: 0,
                        access_mode: REVOKE_ACCESS,
                        inheritance,
                        protection: DaclProtection::Restore,
                    },
                    &mut record.protection,
                    |_| Ok(()),
                )
            })();
            match restored {
                Ok(()) => {
                    self.modified.remove(&record.path);
                    self.paths.remove(index);
                }
                Err(error) => {
                    if failure.is_none() {
                        failure = Some(error.context(format!(
                            "failed to revoke the sandbox ACL for {}",
                            record.path.display()
                        )));
                    }
                }
            }
        }
        self.persist()?;
        match failure {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

fn write_acl_journal(
    journal: Option<&RecoveryJournal>,
    sid: &SidBuffer,
    paths: &[AclRestoration],
) -> Result<()> {
    if let Some(journal) = journal {
        if paths.is_empty() {
            journal.clear()?;
        } else {
            let state = AclJournalState {
                version: 1,
                sid: sid.clone(),
                paths: paths.to_vec(),
            };
            journal.write(
                &serde_json::to_vec(&state).context("encode Windows ACL recovery journal")?,
            )?;
        }
    }
    Ok(())
}

fn open_acl_target(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .access_mode(READ_CONTROL | WRITE_DAC | FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(win32_process_path(path))
        .map_err(|error| {
            if error
                .raw_os_error()
                .is_some_and(|code| is_skippable_acl_error(code as u32))
            {
                acl_denied(path)
            } else {
                anyhow::Error::from(error)
                    .context(format!("open Windows ACL target {}", path.display()))
            }
        })?;
    if file.metadata()?.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(acl_denied(path));
    }
    Ok(file)
}

impl Drop for ExecutionAcls {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

pub(super) struct LocalAllocation(pub(super) *mut c_void);

impl Drop for LocalAllocation {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}

#[cfg(test)]
fn set_dacl_on_object(
    path: &Path,
    _wide: &[u16],
    acl: *mut ACL,
    security_information: u32,
) -> Result<()> {
    set_dacl_on_handle(&open_acl_target(path)?, path, acl, security_information)
}

fn set_dacl_on_handle(
    file: &File,
    path: &Path,
    acl: *mut ACL,
    security_information: u32,
) -> Result<()> {
    let mut descriptor = SECURITY_DESCRIPTOR::default();
    let descriptor_ptr = &mut descriptor as *mut SECURITY_DESCRIPTOR as *mut c_void;
    if unsafe { InitializeSecurityDescriptor(descriptor_ptr, 1) } == 0 {
        return Err(last_windows_error(
            "initialize a non-propagating ACL update",
        ));
    }
    if unsafe { SetSecurityDescriptorDacl(descriptor_ptr, 1, acl, 0) } == 0 {
        return Err(last_windows_error("attach a non-propagating DACL"));
    }
    // Ancestor traversal grants must not propagate existing inheritable entries.
    if unsafe {
        SetKernelObjectSecurity(file.as_raw_handle(), security_information, descriptor_ptr)
    } == 0
    {
        let code = unsafe { GetLastError() };
        if is_skippable_acl_error(code) {
            return Err(acl_denied(path));
        }
        bail!(
            "SetKernelObjectSecurity failed for {} with error {code}",
            path.display()
        );
    }
    Ok(())
}

const ACL_MUTATION_MUTEX_NAME: &str = r"Global\A3S.Sandbox.AclMutation.v1";

struct AclMutationGuard {
    handle: OwnedHandle,
    // Windows mutex ownership belongs to the acquiring OS thread.
    _thread_bound: std::marker::PhantomData<*mut ()>,
}

impl Drop for AclMutationGuard {
    fn drop(&mut self) {
        unsafe {
            ReleaseMutex(self.handle.as_raw_handle());
        }
    }
}

fn lock_acl_mutation(timeout_ms: u32) -> Result<AclMutationGuard> {
    let handle = open_host_mutex(ACL_MUTATION_MUTEX_NAME)?;
    match unsafe { WaitForSingleObject(handle.as_raw_handle(), timeout_ms) } {
        WAIT_OBJECT_0 | WAIT_ABANDONED => Ok(AclMutationGuard {
            handle,
            _thread_bound: std::marker::PhantomData,
        }),
        WAIT_TIMEOUT => Err(anyhow::Error::from(std::io::Error::from(
            std::io::ErrorKind::WouldBlock,
        ))
        .context("timed out waiting for host-global ACL mutation ownership")),
        _ => Err(last_windows_error("acquire host-global ACL mutation mutex")),
    }
}

pub(super) fn open_host_mutex(name: &str) -> Result<OwnedHandle> {
    let sddl = wide_null(OsStr::new(
        "D:P(D;;GA;;;S-1-15-2-1)(D;;GA;;;S-1-15-2-2)(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x00100001;;;AU)",
    ));
    let mut descriptor = null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            null_mut(),
        )
    } == 0
    {
        return Err(last_windows_error(
            "create host coordination security descriptor",
        ));
    }
    let _descriptor = LocalAllocation(descriptor);
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    let name = wide_null(OsStr::new(name));
    let raw = unsafe {
        CreateMutexExW(
            &attributes,
            name.as_ptr(),
            0,
            SYNCHRONIZATION_SYNCHRONIZE | MUTEX_MODIFY_STATE,
        )
    };
    if raw.is_null() {
        return Err(last_windows_error("open host-global coordination mutex"));
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
}

fn capture_dacl_restoration(target: &File, path: &Path) -> Result<DaclRestoration> {
    let (acl, descriptor) = query_handle_dacl(target, path)?;
    let mut control = 0;
    let mut revision = 0;
    if unsafe { GetSecurityDescriptorControl(descriptor.0, &mut control, &mut revision) } == 0 {
        return Err(last_windows_error(
            "inspect original Windows DACL protection",
        ));
    }
    let protected = control & SE_DACL_PROTECTED != 0;
    let mut converted_inherited = Vec::new();
    if !protected && !acl.is_null() {
        for index in 0..u32::from(unsafe { (*acl).AceCount }) {
            let mut entry = null_mut();
            if unsafe { GetAce(acl, index, &mut entry) } == 0 {
                return Err(last_windows_error("inspect an inherited Windows ACE"));
            }
            let header = unsafe { &*entry.cast::<ACE_HEADER>() };
            if header.AceFlags & INHERITED_ACE as u8 != 0 {
                let mut bytes = unsafe {
                    std::slice::from_raw_parts(entry.cast::<u8>(), usize::from(header.AceSize))
                }
                .to_vec();
                bytes[1] &= !(INHERITED_ACE as u8);
                converted_inherited.push(bytes);
            }
        }
    }
    Ok(DaclRestoration {
        protected,
        converted_inherited,
    })
}

fn modify_path_acl(
    target: &File,
    path: &Path,
    sid: &SidBuffer,
    change: AclChange,
    original_protection: &mut Option<DaclRestoration>,
    mut before_change: impl FnMut(&Option<DaclRestoration>) -> Result<()>,
) -> Result<()> {
    let AclChange {
        permissions,
        access_mode,
        inheritance,
        protection,
    } = change;
    let _mutation = lock_acl_mutation(5_000)?;
    let (mut old_acl, mut descriptor) = query_handle_dacl(target, path)?;
    let mut control = 0;
    let mut revision = 0;
    if protection != DaclProtection::Preserve
        && unsafe { GetSecurityDescriptorControl(descriptor.0, &mut control, &mut revision) } == 0
    {
        return Err(last_windows_error("inspect Windows DACL inheritance state"));
    }

    if protection == DaclProtection::Restrict && original_protection.is_none() {
        *original_protection = Some(capture_dacl_restoration(target, path)?);
    }
    if protection != DaclProtection::Restore {
        before_change(original_protection)?;
    }
    if protection == DaclProtection::Restrict {
        // AppContainer restrictions must replace inherited grants, rather than rely on package-SID denies.
        let status = unsafe {
            SetSecurityInfo(
                target.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                old_acl,
                null(),
            )
        };
        if status != 0 {
            bail!(
                "protecting the Windows DACL for {} failed with error {status}",
                path.display()
            );
        }
        drop(descriptor);
        (old_acl, descriptor) = query_handle_dacl(target, path)?;
    }

    let mut access = EXPLICIT_ACCESS_W {
        grfAccessPermissions: permissions,
        grfAccessMode: access_mode,
        grfInheritance: inheritance,
        Trustee: Default::default(),
    };
    access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    access.Trustee.TrusteeType = TRUSTEE_IS_UNKNOWN;
    access.Trustee.ptstrName = sid.as_ptr().cast::<u16>();

    let mut new_acl: *mut ACL = null_mut();
    let status = unsafe { SetEntriesInAclW(1, &access, old_acl, &mut new_acl) };
    if status != 0 {
        bail!(
            "SetEntriesInAclW failed for {} with error {}",
            path.display(),
            status
        );
    }
    let _new_acl = LocalAllocation(new_acl.cast::<c_void>());
    if protection == DaclProtection::Restore && control & SE_DACL_PROTECTED != 0 {
        if let Some(original) = original_protection.as_ref() {
            // Protection converts inherited ACEs to explicit ones; unprotecting alone duplicates them.
            for converted in &original.converted_inherited {
                for index in 0..u32::from(unsafe { (*new_acl).AceCount }) {
                    let mut entry = null_mut();
                    if unsafe { GetAce(new_acl, index, &mut entry) } == 0 {
                        return Err(last_windows_error("inspect a converted Windows ACE"));
                    }
                    let header = unsafe { &*entry.cast::<ACE_HEADER>() };
                    let bytes = unsafe {
                        std::slice::from_raw_parts(entry.cast::<u8>(), usize::from(header.AceSize))
                    };
                    if bytes == converted {
                        if unsafe { DeleteAce(new_acl, index) } == 0 {
                            return Err(last_windows_error("remove a converted Windows ACE"));
                        }
                        break;
                    }
                }
            }
        }
    }
    let protection_flags = match (
        protection,
        original_protection.as_ref().map(|state| state.protected),
    ) {
        (DaclProtection::Restrict, _) | (DaclProtection::Restore, Some(true)) => {
            PROTECTED_DACL_SECURITY_INFORMATION
        }
        (DaclProtection::Restore, Some(false)) => UNPROTECTED_DACL_SECURITY_INFORMATION,
        _ => 0,
    };
    if inheritance == NO_INHERITANCE && protection_flags == 0 {
        return set_dacl_on_handle(target, path, new_acl, DACL_SECURITY_INFORMATION);
    }
    let status = unsafe {
        SetSecurityInfo(
            target.as_raw_handle(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | protection_flags,
            null_mut(),
            null_mut(),
            new_acl,
            null(),
        )
    };
    if status != 0 {
        bail!(
            "SetSecurityInfo failed for {} with error {}",
            path.display(),
            status
        );
    }
    drop(descriptor);
    Ok(())
}

#[cfg(test)]
fn query_path_dacl(path: &Path, _wide: &[u16]) -> Result<(*mut ACL, LocalAllocation)> {
    let target = OpenOptions::new()
        .read(true)
        .access_mode(READ_CONTROL | FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(win32_process_path(path))?;
    query_handle_dacl(&target, path)
}

fn query_handle_dacl(target: &File, path: &Path) -> Result<(*mut ACL, LocalAllocation)> {
    let mut acl: *mut ACL = null_mut();
    let mut descriptor = null_mut();
    let status = unsafe {
        GetSecurityInfo(
            target.as_raw_handle(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            &mut acl,
            null_mut(),
            &mut descriptor,
        )
    };
    if is_skippable_acl_error(status) {
        return Err(acl_denied(path));
    }
    if status != 0 {
        bail!(
            "GetSecurityInfo failed for {} with error {}",
            path.display(),
            status
        );
    }
    if descriptor.is_null() {
        bail!(
            "Windows returned an empty security descriptor for {}",
            path.display()
        );
    }
    Ok((acl, LocalAllocation(descriptor)))
}

/// Create a connected AppContainer mediation pipe pair.
///
/// AppContainer guests on GHA cannot `CreateFile`/`NamedPipeClientStream.Connect`
/// against a host-created pipe even with package SID + `AC` + Low IL DACLs
/// (persistent `ERROR_ACCESS_DENIED`). The fail-closed bridge therefore:
/// 1. Creates the server pipe under the host's default SD,
/// 2. Opens the client end in the host (succeeds under the creator SD),
/// 3. Marks the client handle inheritable and locks the pipe name down to the
///    AppContainer SID + Low IL so subsequent name opens stay denied,
/// 4. Passes the connected client handle into the guest via the handle list.
///
/// Capability claim still requires the live AppContainer guest tunnel proof.
pub(super) fn create_appcontainer_mediation_pipe(
    pipe_name: &str,
    sid: &SidBuffer,
) -> Result<(OwnedHandle, OwnedHandle)> {
    use windows_sys::Win32::Foundation::{
        SetHandleInformation, GENERIC_READ, GENERIC_WRITE, HANDLE_FLAG_INHERIT,
        INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_OVERLAPPED, OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
    };
    use windows_sys::Win32::System::Pipes::{
        CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE,
        PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
    };

    if !pipe_name.starts_with(r"\\.\pipe\") {
        bail!("AppContainer named pipe requires a \\\\.\\pipe\\... path");
    }

    let wide = wide_null(OsStr::new(pipe_name));
    // Create under the host default SD so the same-process client open succeeds.
    let server = unsafe {
        CreateNamedPipeW(
            wide.as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            PIPE_UNLIMITED_INSTANCES,
            64 * 1024,
            64 * 1024,
            0,
            null(),
        )
    };
    if server.is_null() || server == INVALID_HANDLE_VALUE {
        bail!(
            "CreateNamedPipeW failed for {pipe_name}: {}",
            std::io::Error::last_os_error()
        );
    }
    let server = unsafe { OwnedHandle::from_raw_handle(server) };

    let client = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED,
            null_mut(),
        )
    };
    if client.is_null() || client == INVALID_HANDLE_VALUE {
        bail!(
            "host CreateFileW for mediation pipe client failed: {}",
            std::io::Error::last_os_error()
        );
    }
    let client = unsafe { OwnedHandle::from_raw_handle(client) };
    let ok = unsafe {
        SetHandleInformation(
            client.as_raw_handle(),
            HANDLE_FLAG_INHERIT,
            HANDLE_FLAG_INHERIT,
        )
    };
    if ok == 0 {
        bail!(
            "SetHandleInformation(INHERIT) failed for mediation pipe client: {}",
            std::io::Error::last_os_error()
        );
    }

    // Best-effort name lockdown. SetKernelObjectSecurity(LABEL) is denied on
    // some GHA images without SeRelabelPrivilege; the guest path does not
    // name-open — it inherits `client`. Default creator SD already denies
    // unrelated callers.
    let _ = lock_down_appcontainer_pipe_handle(server.as_raw_handle(), sid);
    Ok((server, client))
}

/// Create a duplex overlapped named pipe whose DACL grants AppContainer clients.
///
/// Prefer [`create_appcontainer_mediation_pipe`] for the live guest bridge; this
/// helper remains for accept-loop factories and host-deny unit coverage.
#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn create_appcontainer_named_pipe(
    pipe_name: &str,
    sid: &SidBuffer,
) -> Result<OwnedHandle> {
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_OVERLAPPED, PIPE_ACCESS_DUPLEX};
    use windows_sys::Win32::System::Pipes::{
        CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE,
        PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
    };

    if !pipe_name.starts_with(r"\\.\pipe\") {
        bail!("AppContainer named pipe requires a \\\\.\\pipe\\... path");
    }

    let descriptor = appcontainer_pipe_security_descriptor(sid)?;
    let _descriptor_guard = LocalAllocation(descriptor);
    let attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>())
            .context("SECURITY_ATTRIBUTES size overflowed")?,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    let wide = wide_null(OsStr::new(pipe_name));
    let handle = unsafe {
        CreateNamedPipeW(
            wide.as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            PIPE_UNLIMITED_INSTANCES,
            64 * 1024,
            64 * 1024,
            0,
            &attributes,
        )
    };
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        bail!(
            "CreateNamedPipeW failed for {pipe_name}: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}

fn appcontainer_pipe_security_descriptor(sid: &SidBuffer) -> Result<*mut c_void> {
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    };

    let mut sid_string: *mut u16 = null_mut();
    let ok = unsafe { ConvertSidToStringSidW(sid.as_ptr(), &mut sid_string) };
    if ok == 0 || sid_string.is_null() {
        bail!(
            "ConvertSidToStringSidW failed: {}",
            std::io::Error::last_os_error()
        );
    }
    let sid_text = unsafe {
        let mut len = 0usize;
        while *sid_string.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(sid_string, len))
    };
    unsafe {
        LocalFree(sid_string.cast());
    }

    // Package SID + All Application Packages + Low mandatory label.
    let sddl = format!("D:(A;;GA;;;{sid_text})(A;;GA;;;AC)S:(ML;;NW;;;LW)");
    let mut descriptor: *mut c_void = null_mut();
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide_null(OsStr::new(&sddl)).as_ptr(),
            1, // SDDL_REVISION_1
            &mut descriptor,
            null_mut(),
        )
    };
    if ok == 0 || descriptor.is_null() {
        bail!(
            "ConvertStringSecurityDescriptorToSecurityDescriptorW failed: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(descriptor)
}

fn lock_down_appcontainer_pipe_handle(handle: *mut c_void, sid: &SidBuffer) -> Result<()> {
    use windows_sys::Win32::Security::{
        SetKernelObjectSecurity, DACL_SECURITY_INFORMATION, LABEL_SECURITY_INFORMATION,
    };

    let descriptor = appcontainer_pipe_security_descriptor(sid)?;
    let _guard = LocalAllocation(descriptor);
    let ok = unsafe {
        SetKernelObjectSecurity(
            handle,
            DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION,
            descriptor,
        )
    };
    if ok == 0 {
        bail!(
            "SetKernelObjectSecurity failed locking mediation pipe: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::windows::io::AsRawHandle;

    #[test]
    fn appcontainer_named_pipe_dacl_denies_host_client_open() {
        use windows_sys::Win32::Foundation::{
            GetLastError, GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE,
        };
        use windows_sys::Win32::Storage::FileSystem::{CreateFileW, OPEN_EXISTING};

        let profile = AppContainerProfile::create().expect("AppContainer profile");
        let pipe_name = format!(r"\\.\pipe\a3s-sandbox-acl-{}", std::process::id());
        let server = create_appcontainer_named_pipe(&pipe_name, &profile.sid)
            .expect("create ACL'd named pipe");
        assert!(!server.as_raw_handle().is_null());

        // Host process is not the AppContainer SID, so a fresh client open must fail.
        let wide = wide_null(OsStr::new(&pipe_name));
        let client = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                null(),
                OPEN_EXISTING,
                0,
                null_mut(),
            )
        };
        assert!(
            client == INVALID_HANDLE_VALUE,
            "host client open should be denied by AppContainer-only DACL"
        );
        let err = unsafe { GetLastError() };
        assert_eq!(err, 5, "expected ERROR_ACCESS_DENIED (5), got {err}");
        drop(server);
    }
}

#[cfg(test)]
#[path = "windows_acl_tests.rs"]
mod acl_tests;
