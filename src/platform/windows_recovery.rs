//! Host-only, write-ahead storage for Windows authorization recovery.

use super::windows::{last_windows_error, wide_null};
use super::windows_security::LocalAllocation;
use anyhow::{bail, Context, Result};
use std::ffi::OsStr;
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::ERROR_FILE_NOT_FOUND;
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
    SE_REGISTRY_KEY,
};
use windows_sys::Win32::Security::{
    GetSecurityDescriptorControl, GetSecurityDescriptorDacl, ACL, DACL_SECURITY_INFORMATION,
    SECURITY_ATTRIBUTES, SE_DACL_PROTECTED,
};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegDeleteValueW, RegFlushKey, RegQueryValueExW, RegSetValueExW,
    HKEY, HKEY_CURRENT_USER, KEY_QUERY_VALUE, KEY_SET_VALUE, KEY_WOW64_64KEY, REG_BINARY,
    REG_OPTION_NON_VOLATILE,
};

pub(super) const RECOVERY_KEY: &str = r"Software\A3S\Sandbox\Recovery.v1";
const MAX_JOURNAL_BYTES: usize = 4 * 1024 * 1024;
const READ_CONTROL: u32 = 0x0002_0000;

struct RegistryKey(isize);

impl Drop for RegistryKey {
    fn drop(&mut self) {
        unsafe { RegCloseKey(self.0 as HKEY) };
    }
}

pub(super) struct RecoveryJournal {
    key: RegistryKey,
    name: Vec<u16>,
}

impl RecoveryJournal {
    pub(super) fn open(name: &str) -> Result<Self> {
        let sddl = wide_null(OsStr::new(
            "D:P(D;;KA;;;AC)(D;;KA;;;S-1-15-2-2)(A;;KA;;;SY)(A;;KA;;;BA)(A;;KA;;;OW)",
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
                "create recovery journal security descriptor",
            ));
        }
        let _descriptor = LocalAllocation(descriptor);
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        };
        let path = wide_null(OsStr::new(RECOVERY_KEY));
        let mut raw = null_mut();
        check(
            unsafe {
                RegCreateKeyExW(
                    HKEY_CURRENT_USER,
                    path.as_ptr(),
                    0,
                    null(),
                    REG_OPTION_NON_VOLATILE,
                    KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_WOW64_64KEY | READ_CONTROL,
                    &attributes,
                    &mut raw,
                    null_mut(),
                )
            },
            "open recovery journal",
        )?;
        let key = RegistryKey(raw as isize);
        verify_security(raw, descriptor)?;
        Ok(Self {
            key,
            name: wide_null(OsStr::new(name)),
        })
    }

    pub(super) fn read(&self) -> Result<Option<Vec<u8>>> {
        let mut kind = 0;
        let mut length = 0;
        let status = unsafe {
            RegQueryValueExW(
                self.key.0 as HKEY,
                self.name.as_ptr(),
                null(),
                &mut kind,
                null_mut(),
                &mut length,
            )
        };
        if status == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        check(status, "inspect recovery journal")?;
        if kind != REG_BINARY || length as usize > MAX_JOURNAL_BYTES {
            bail!("Windows recovery journal has an invalid type or size");
        }
        let mut bytes = vec![0; length as usize];
        check(
            unsafe {
                RegQueryValueExW(
                    self.key.0 as HKEY,
                    self.name.as_ptr(),
                    null(),
                    &mut kind,
                    bytes.as_mut_ptr(),
                    &mut length,
                )
            },
            "read recovery journal",
        )?;
        if kind != REG_BINARY || length as usize != bytes.len() {
            bail!("Windows recovery journal changed while reading");
        }
        Ok(Some(bytes))
    }

    pub(super) fn write(&self, bytes: &[u8]) -> Result<()> {
        if bytes.len() > MAX_JOURNAL_BYTES {
            bail!("Windows recovery journal exceeds its size limit");
        }
        check(
            unsafe {
                RegSetValueExW(
                    self.key.0 as HKEY,
                    self.name.as_ptr(),
                    0,
                    REG_BINARY,
                    bytes.as_ptr(),
                    bytes.len() as u32,
                )
            },
            "write recovery journal",
        )?;
        // The ACL must not become durable before its recovery intent does.
        check(
            unsafe { RegFlushKey(self.key.0 as HKEY) },
            "flush recovery journal",
        )
    }

    pub(super) fn clear(&self) -> Result<()> {
        let status = unsafe { RegDeleteValueW(self.key.0 as HKEY, self.name.as_ptr()) };
        if status != ERROR_FILE_NOT_FOUND {
            check(status, "clear recovery journal")?;
        }
        check(
            unsafe { RegFlushKey(self.key.0 as HKEY) },
            "flush recovery completion",
        )
    }
}

fn verify_security(key: HKEY, expected: *mut std::ffi::c_void) -> Result<()> {
    let mut actual_acl = null_mut();
    let mut actual = null_mut();
    check(
        unsafe {
            GetSecurityInfo(
                key,
                SE_REGISTRY_KEY,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                &mut actual_acl,
                null_mut(),
                &mut actual,
            )
        },
        "inspect recovery journal security",
    )?;
    let _actual = LocalAllocation(actual);
    let mut expected_acl = null_mut();
    let mut present = 0;
    let mut defaulted = 0;
    let mut control = 0;
    let mut revision = 0;
    if unsafe {
        GetSecurityDescriptorDacl(expected, &mut present, &mut expected_acl, &mut defaulted)
    } == 0
        || unsafe { GetSecurityDescriptorControl(actual, &mut control, &mut revision) } == 0
    {
        return Err(last_windows_error("inspect recovery journal DACL"));
    }
    if control & SE_DACL_PROTECTED == 0
        || actual_acl.is_null()
        || expected_acl.is_null()
        || acl_bytes(actual_acl) != acl_bytes(expected_acl)
    {
        bail!("Windows recovery journal security differs from the host-only contract");
    }
    Ok(())
}

fn acl_bytes(acl: *const ACL) -> Vec<u8> {
    unsafe { std::slice::from_raw_parts(acl.cast(), usize::from((*acl).AclSize)) }.to_vec()
}

fn check(status: u32, operation: &str) -> Result<()> {
    if status != 0 {
        return Err(std::io::Error::from_raw_os_error(status as i32)).context(operation.to_owned());
    }
    Ok(())
}

pub(super) mod windows_path {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::ffi::OsString;
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use std::path::{Path, PathBuf};

    pub(crate) fn serialize<S: Serializer>(path: &Path, serializer: S) -> Result<S::Ok, S::Error> {
        path.as_os_str()
            .encode_wide()
            .collect::<Vec<_>>()
            .serialize(serializer)
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<PathBuf, D::Error> {
        let path = Vec::<u16>::deserialize(deserializer)?;
        let decoded = PathBuf::from(OsString::from_wide(&path));
        if path.contains(&0) || !decoded.is_absolute() {
            return Err(serde::de::Error::custom(
                "recovery target must be an absolute Windows path without NUL",
            ));
        }
        Ok(decoded)
    }
}
