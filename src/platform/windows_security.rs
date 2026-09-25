//! AppContainer identity and temporary Windows filesystem authorization.

use super::windows::{last_windows_error, wide_null, win32_process_path};
use crate::policy::EnforcedPolicy;
use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::ffi::{c_void, OsStr};
use std::mem::size_of;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::sync::OnceLock;
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, ERROR_ACCESS_DENIED, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::Authorization::{
    GetNamedSecurityInfoW, SetEntriesInAclW, SetNamedSecurityInfoW, EXPLICIT_ACCESS_W,
    GRANT_ACCESS, REVOKE_ACCESS, SET_ACCESS, SE_FILE_OBJECT, TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN,
};
use windows_sys::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeriveAppContainerSidFromAppContainerName,
};
use windows_sys::Win32::Security::{
    FreeSid, GetLengthSid, GetSecurityDescriptorControl, InitializeSecurityDescriptor,
    SetKernelObjectSecurity, SetSecurityDescriptorDacl, ACL, DACL_SECURITY_INFORMATION,
    NO_INHERITANCE, PROTECTED_DACL_SECURITY_INFORMATION, PSID, SECURITY_DESCRIPTOR,
    SE_DACL_PROTECTED, SUB_CONTAINERS_AND_OBJECTS_INHERIT, UNPROTECTED_DACL_SECURITY_INFORMATION,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, DELETE, FILE_DELETE_CHILD, FILE_FLAG_BACKUP_SEMANTICS, FILE_GENERIC_EXECUTE,
    FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    FILE_TRAVERSE, OPEN_EXISTING,
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

#[derive(Debug, Clone)]
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
}

impl AppContainerProfile {
    pub(super) fn create() -> Result<Self> {
        let name = appcontainer_profile_name();
        let name = wide_null(OsStr::new(&name));
        let display = wide_null(OsStr::new("A3S Native Sandbox"));
        let description = wide_null(OsStr::new(
            "Process-scoped AppContainer for fail-closed A3S command execution",
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
        })
    }
}

pub(super) fn appcontainer_profile_name() -> String {
    static PROCESS_SCOPE: OnceLock<u128> = OnceLock::new();
    let mut hasher = Sha256::new();
    hasher.update(std::process::id().to_le_bytes());
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

pub(super) struct ExecutionAcls<'a> {
    sid: &'a SidBuffer,
    paths: Vec<(PathBuf, DaclSnapshot, bool)>,
    modified: HashSet<PathBuf>,
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

impl<'a> ExecutionAcls<'a> {
    pub(super) fn apply(policy: &EnforcedPolicy, sid: &'a SidBuffer) -> Result<Self> {
        let mut guard = Self {
            sid,
            paths: Vec::new(),
            modified: HashSet::new(),
        };
        guard.grant_ancestor_traversal(&policy.workspace)?;
        guard.grant_ancestor_traversal(&policy.scratch)?;
        guard.modify(
            &policy.workspace,
            FILE_GENERIC_READ
                | FILE_GENERIC_WRITE
                | FILE_GENERIC_EXECUTE
                | DELETE
                | FILE_DELETE_CHILD,
            GRANT_ACCESS,
        )?;
        guard.modify(
            &policy.scratch,
            FILE_GENERIC_READ
                | FILE_GENERIC_WRITE
                | FILE_GENERIC_EXECUTE
                | DELETE
                | FILE_DELETE_CHILD,
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
                    FILE_GENERIC_READ
                        | FILE_GENERIC_WRITE
                        | FILE_GENERIC_EXECUTE
                        | DELETE
                        | FILE_DELETE_CHILD,
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
        Ok(guard)
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
        let local_only = inheritance == NO_INHERITANCE && !protect_dacl;
        let tracked = self.modified.contains(path);
        if !tracked {
            let snapshot = capture_path_dacl(path)?;
            self.modified.insert(path.to_path_buf());
            self.paths.push((path.to_path_buf(), snapshot, local_only));
        }
        if let Err(error) = modify_path_acl(
            path,
            self.sid,
            permissions,
            access_mode,
            inheritance,
            protect_dacl,
        ) {
            if !tracked {
                self.paths.pop();
                self.modified.remove(path);
            }
            return Err(error);
        }
        Ok(())
    }

    pub(super) fn restore(&mut self) -> Result<()> {
        let mut failure = None;
        for (path, snapshot, local_only) in self.paths.drain(..).rev() {
            let restored = if local_only {
                restore_path_dacl_locally(&path, &snapshot)
            } else {
                restore_path_dacl(&path, &snapshot)
            };
            if let Err(error) = restored {
                if failure.is_none() {
                    failure = Some(
                        error.context(format!("failed to restore the ACL for {}", path.display())),
                    );
                }
            }
            self.modified.remove(&path);
        }
        match failure {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

impl Drop for ExecutionAcls<'_> {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

struct LocalAllocation(*mut c_void);

impl Drop for LocalAllocation {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}

struct DaclSnapshot {
    words: Option<Vec<u32>>,
    protected: bool,
}

fn capture_path_dacl(path: &Path) -> Result<DaclSnapshot> {
    let security_path = win32_process_path(path);
    let wide = wide_null(security_path.as_os_str());
    let mut acl: *mut ACL = null_mut();
    let mut descriptor = null_mut();
    let status = unsafe {
        GetNamedSecurityInfoW(
            wide.as_ptr(),
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
            "GetNamedSecurityInfoW failed for {} with error {}",
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
    let _descriptor = LocalAllocation(descriptor);
    let mut control = 0_u16;
    let mut revision = 0_u32;
    if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0 {
        return Err(last_windows_error("inspect Windows DACL inheritance state"));
    }
    let protected = control & SE_DACL_PROTECTED != 0;
    if acl.is_null() {
        return Ok(DaclSnapshot {
            words: None,
            protected,
        });
    }
    let bytes = usize::from(unsafe { (*acl).AclSize });
    if bytes < size_of::<ACL>() {
        bail!("Windows returned an invalid DACL for {}", path.display());
    }
    let mut words = vec![0_u32; bytes.div_ceil(size_of::<u32>())];
    unsafe {
        std::ptr::copy_nonoverlapping(acl.cast::<u8>(), words.as_mut_ptr().cast::<u8>(), bytes);
    }
    Ok(DaclSnapshot {
        words: Some(words),
        protected,
    })
}

fn restore_path_dacl(path: &Path, snapshot: &DaclSnapshot) -> Result<()> {
    let security_path = win32_process_path(path);
    let wide = wide_null(security_path.as_os_str());
    let acl = snapshot
        .words
        .as_ref()
        .map_or(null_mut(), |words| words.as_ptr().cast_mut().cast::<ACL>());
    let inheritance = if snapshot.protected {
        PROTECTED_DACL_SECURITY_INFORMATION
    } else {
        UNPROTECTED_DACL_SECURITY_INFORMATION
    };
    let status = unsafe {
        SetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | inheritance,
            null_mut(),
            null_mut(),
            acl,
            null(),
        )
    };
    if status != 0 {
        bail!(
            "SetNamedSecurityInfoW failed while restoring {} with error {}",
            path.display(),
            status
        );
    }
    Ok(())
}

fn restore_path_dacl_locally(path: &Path, snapshot: &DaclSnapshot) -> Result<()> {
    let security_path = win32_process_path(path);
    let wide = wide_null(security_path.as_os_str());
    let acl = snapshot
        .words
        .as_ref()
        .map_or(null_mut(), |words| words.as_ptr().cast_mut().cast::<ACL>());
    let inheritance = if snapshot.protected {
        PROTECTED_DACL_SECURITY_INFORMATION
    } else {
        UNPROTECTED_DACL_SECURITY_INFORMATION
    };
    set_dacl_on_object(path, &wide, acl, DACL_SECURITY_INFORMATION | inheritance)
}

fn set_dacl_on_object(
    path: &Path,
    wide: &[u16],
    acl: *mut ACL,
    security_information: u32,
) -> Result<()> {
    let raw = unsafe {
        CreateFileW(
            wide.as_ptr(),
            READ_CONTROL | WRITE_DAC,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        let code = unsafe { GetLastError() };
        if is_skippable_acl_error(code) {
            return Err(acl_denied(path));
        }
        bail!(
            "opening {} to update its DACL failed with Windows error {code}",
            path.display()
        );
    }
    let mut descriptor = SECURITY_DESCRIPTOR::default();
    let descriptor_ptr = &mut descriptor as *mut SECURITY_DESCRIPTOR as *mut c_void;
    let initialized = unsafe { InitializeSecurityDescriptor(descriptor_ptr, 1) };
    if initialized == 0 {
        unsafe {
            CloseHandle(raw);
        }
        return Err(last_windows_error(
            "initialize a security descriptor for a non-propagating ACL update",
        ));
    }
    let dacl_set = unsafe { SetSecurityDescriptorDacl(descriptor_ptr, 1, acl, 0) };
    if dacl_set == 0 {
        unsafe {
            CloseHandle(raw);
        }
        return Err(last_windows_error(
            "attach a DACL for a non-propagating ACL update",
        ));
    }
    // SetNamedSecurityInfo and SetSecurityInfo both propagate inheritable
    // ACEs that were already on the directory. SetKernelObjectSecurity updates
    // only this object, which is required for ancestor traverse grants.
    let updated = unsafe { SetKernelObjectSecurity(raw, security_information, descriptor_ptr) };
    let code = if updated == 0 {
        unsafe { GetLastError() }
    } else {
        0
    };
    unsafe {
        CloseHandle(raw);
    }
    if is_skippable_acl_error(code) {
        return Err(acl_denied(path));
    }
    if code != 0 {
        bail!(
            "SetKernelObjectSecurity failed for {} with error {code}",
            path.display()
        );
    }
    Ok(())
}

fn modify_path_acl(
    path: &Path,
    sid: &SidBuffer,
    permissions: u32,
    access_mode: i32,
    inheritance: u32,
    protect_dacl: bool,
) -> Result<()> {
    let security_path = win32_process_path(path);
    let wide = wide_null(security_path.as_os_str());
    let (mut old_acl, mut descriptor) = query_path_dacl(path, &wide)?;

    if protect_dacl {
        // Inherited ACEs cannot be replaced while the DACL still participates
        // in automatic inheritance. Protecting the current DACL first turns
        // those ACEs into explicit entries; the following SET_ACCESS or
        // REVOKE_ACCESS operation can then replace every package-SID entry with
        // the bounded mask.
        let status = unsafe {
            SetNamedSecurityInfoW(
                wide.as_ptr(),
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
                "SetNamedSecurityInfoW failed while protecting {} with error {}",
                path.display(),
                status
            );
        }
        drop(descriptor);
        (old_acl, descriptor) = query_path_dacl(path, &wide)?;
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
    let security_information = if protect_dacl {
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION
    } else {
        DACL_SECURITY_INFORMATION
    };
    // SetNamedSecurityInfo rewrites the merged DACL and then walks every
    // descendant of an inheritable ACE already on that directory. A traverse
    // grant on an ancestor must not walk the user profile.
    if inheritance == NO_INHERITANCE && !protect_dacl {
        return set_dacl_on_object(path, &wide, new_acl, security_information);
    }
    let status = unsafe {
        SetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            security_information,
            null_mut(),
            null_mut(),
            new_acl,
            null(),
        )
    };
    if is_skippable_acl_error(status) {
        return Err(acl_denied(path));
    }
    if status != 0 {
        bail!(
            "SetNamedSecurityInfoW failed for {} with error {}",
            path.display(),
            status
        );
    }
    drop(descriptor);
    Ok(())
}

fn query_path_dacl(path: &Path, wide: &[u16]) -> Result<(*mut ACL, LocalAllocation)> {
    let mut acl: *mut ACL = null_mut();
    let mut descriptor = null_mut();
    let status = unsafe {
        GetNamedSecurityInfoW(
            wide.as_ptr(),
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
            "GetNamedSecurityInfoW failed for {} with error {}",
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

    #[test]
    fn windows_apps_execution_aliases_are_not_acl_targets() {
        let Some(local_app_data) = std::env::var_os("LOCALAPPDATA") else {
            return;
        };
        let windows_apps = PathBuf::from(local_app_data)
            .join("Microsoft")
            .join("WindowsApps");
        assert!(
            system_tree_prefixes()
                .iter()
                .any(|prefix| prefix == &windows_apps),
            "WindowsApps must be skipped; alias stubs return ERROR_CANT_RESOLVE_FILENAME"
        );
        assert!(is_skippable_acl_error(ERROR_ACCESS_DENIED));
        assert!(is_skippable_acl_error(ERROR_CANT_RESOLVE_FILENAME));
        assert!(!is_skippable_acl_error(32));
    }
}
