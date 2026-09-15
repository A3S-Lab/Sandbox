//! AppContainer identity and temporary Windows filesystem authorization.

use super::windows::{last_windows_error, wide_null, win32_process_path};
use crate::policy::EnforcedPolicy;
use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::ffi::{c_void, OsStr};
use std::mem::size_of;
use std::os::windows::io::{FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::sync::OnceLock;
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Authorization::{
    GetNamedSecurityInfoW, SetEntriesInAclW, SetNamedSecurityInfoW, EXPLICIT_ACCESS_W,
    GRANT_ACCESS, REVOKE_ACCESS, SET_ACCESS, SE_FILE_OBJECT, TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN,
};
use windows_sys::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeriveAppContainerSidFromAppContainerName,
};
use windows_sys::Win32::Security::{
    FreeSid, GetLengthSid, GetSecurityDescriptorControl, ACL, DACL_SECURITY_INFORMATION,
    NO_INHERITANCE, PROTECTED_DACL_SECURITY_INFORMATION, PSID, SE_DACL_PROTECTED,
    SUB_CONTAINERS_AND_OBJECTS_INHERIT, UNPROTECTED_DACL_SECURITY_INFORMATION,
};
use windows_sys::Win32::Storage::FileSystem::{
    DELETE, FILE_DELETE_CHILD, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
    FILE_TRAVERSE,
};

const HRESULT_ALREADY_EXISTS: u32 = 0x8007_00b7;

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
    paths: Vec<(PathBuf, DaclSnapshot)>,
    modified: HashSet<PathBuf>,
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
        // Do not recursively mutate arbitrary PATH or toolchain roots. Windows
        // propagates inheritable ACEs through those host trees, which is both
        // expensive and too broad. System/package tools retain their existing
        // AppContainer grants; workspace-local tools are covered above.
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
            self.modify_with_inheritance(
                ancestor,
                FILE_TRAVERSE,
                GRANT_ACCESS,
                NO_INHERITANCE,
                false,
            )?;
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
        if !self.modified.contains(path) {
            let snapshot = capture_path_dacl(path)?;
            self.modified.insert(path.to_path_buf());
            self.paths.push((path.to_path_buf(), snapshot));
        }
        modify_path_acl(
            path,
            self.sid,
            permissions,
            access_mode,
            inheritance,
            protect_dacl,
        )?;
        Ok(())
    }

    pub(super) fn restore(&mut self) -> Result<()> {
        let mut failure = None;
        for (path, snapshot) in self.paths.drain(..).rev() {
            if let Err(error) = restore_path_dacl(&path, &snapshot) {
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

/// Create a duplex overlapped named pipe whose DACL grants only `sid`.
///
/// The host keeps the server handle from creation; AppContainer clients may
/// open the pipe name. Other callers should receive `ERROR_ACCESS_DENIED`.
///
/// Used by the Windows execute path to create every named-pipe instance with
/// the same AppContainer-only DACL. Capability claim still requires live guest
/// tunnel proof.
pub(super) fn create_appcontainer_named_pipe(
    pipe_name: &str,
    sid: &SidBuffer,
) -> Result<OwnedHandle> {
    use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};
    use windows_sys::Win32::Security::{
        InitializeSecurityDescriptor, SetSecurityDescriptorDacl, SECURITY_ATTRIBUTES,
        SECURITY_DESCRIPTOR,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_OVERLAPPED, PIPE_ACCESS_DUPLEX, SYNCHRONIZE,
    };
    use windows_sys::Win32::System::Pipes::{
        CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE,
        PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
    };
    use windows_sys::Win32::System::SystemServices::SECURITY_DESCRIPTOR_REVISION;

    if !pipe_name.starts_with(r"\\.\pipe\") {
        bail!("AppContainer named pipe requires a \\\\.\\pipe\\... path");
    }

    let mut access = EXPLICIT_ACCESS_W {
        grfAccessPermissions: GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE,
        grfAccessMode: GRANT_ACCESS,
        grfInheritance: NO_INHERITANCE,
        Trustee: Default::default(),
    };
    access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    access.Trustee.TrusteeType = TRUSTEE_IS_UNKNOWN;
    access.Trustee.ptstrName = sid.as_ptr().cast::<u16>();

    let mut acl: *mut ACL = null_mut();
    let status = unsafe { SetEntriesInAclW(1, &access, null_mut(), &mut acl) };
    if status != 0 {
        bail!("SetEntriesInAclW failed while building named pipe DACL: {status}");
    }
    let _acl_guard = LocalAllocation(acl.cast::<c_void>());

    let mut descriptor: SECURITY_DESCRIPTOR = unsafe { std::mem::zeroed() };
    let ok = unsafe {
        InitializeSecurityDescriptor(
            (&raw mut descriptor).cast::<c_void>(),
            SECURITY_DESCRIPTOR_REVISION,
        )
    };
    if ok == 0 {
        bail!(
            "InitializeSecurityDescriptor failed: {}",
            std::io::Error::last_os_error()
        );
    }
    let ok =
        unsafe { SetSecurityDescriptorDacl((&raw mut descriptor).cast::<c_void>(), 1, acl, 0) };
    if ok == 0 {
        bail!(
            "SetSecurityDescriptorDacl failed: {}",
            std::io::Error::last_os_error()
        );
    }

    let attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>())
            .context("SECURITY_ATTRIBUTES size overflowed")?,
        lpSecurityDescriptor: (&raw mut descriptor).cast::<c_void>(),
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
    if handle.is_null() || handle == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
        bail!(
            "CreateNamedPipeW failed for {pipe_name}: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
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
