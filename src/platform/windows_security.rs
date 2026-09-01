//! AppContainer identity and temporary Windows filesystem authorization.

use super::windows::{last_windows_error, wide_null, win32_process_path};
use crate::policy::SandboxPolicy;
use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::ffi::{c_void, OsStr};
use std::mem::size_of;
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

#[derive(Debug)]
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
    pub(super) fn apply(policy: &SandboxPolicy, sid: &'a SidBuffer) -> Result<Self> {
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
