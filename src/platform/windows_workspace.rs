//! Physical directory ownership across Windows sandbox hosts.

use anyhow::{bail, Context, Result};
use std::fs::{File, OpenOptions};
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::time::Duration;
use windows_sys::Win32::Foundation::ERROR_SHARING_VIOLATION;
use windows_sys::Win32::Storage::FileSystem::{
    FileIdInfo, GetFileInformationByHandleEx, FILE_ADD_FILE, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_ID_INFO, FILE_READ_ATTRIBUTES,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
};

#[derive(Debug, Eq, PartialEq)]
struct DirectoryIdentity {
    volume: u64,
    file: [u8; 16],
}

#[derive(Debug)]
pub(super) struct WorkspaceDirectory {
    path: PathBuf,
    identity: DirectoryIdentity,
    _identity_pin: File,
}

pub(crate) struct WorkspaceLease {
    _handle: File,
}

impl WorkspaceDirectory {
    pub(super) fn capture(path: &Path) -> Result<Self> {
        let pin = open_directory(
            path,
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        )
        .context("open Windows workspace identity handle")?;
        Ok(Self {
            path: path.to_owned(),
            identity: identity(&pin)?,
            _identity_pin: pin,
        })
    }

    pub(super) async fn acquire(&self) -> Result<WorkspaceLease> {
        loop {
            // Attribute-only access does not participate in share-mode exclusion.
            // shortcut: add-file rights are required; revisit for read-only host root support.
            match open_directory(
                &self.path,
                FILE_ADD_FILE | FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ,
            ) {
                Ok(handle) => {
                    if identity(&handle)? != self.identity {
                        bail!("Windows workspace identity changed before execution");
                    }
                    return Ok(WorkspaceLease { _handle: handle });
                }
                Err(error) if error.raw_os_error() == Some(ERROR_SHARING_VIOLATION as i32) => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Err(error) => {
                    return Err(error).context("acquire Windows workspace directory ownership")
                }
            }
        }
    }
}

fn open_directory(path: &Path, access: u32, sharing: u32) -> std::io::Result<File> {
    OpenOptions::new()
        .read(true)
        .access_mode(access)
        .share_mode(sharing)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

fn identity(file: &File) -> Result<DirectoryIdentity> {
    let metadata = file
        .metadata()
        .context("inspect Windows workspace directory")?;
    if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        bail!("Windows workspace root must be a directory without a reparse point");
    }
    let mut information = FILE_ID_INFO::default();
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileIdInfo,
            (&mut information as *mut FILE_ID_INFO).cast(),
            std::mem::size_of::<FILE_ID_INFO>() as u32,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error())
            .context("read Windows workspace file identity");
    }
    Ok(DirectoryIdentity {
        volume: information.VolumeSerialNumber,
        file: information.FileId.Identifier,
    })
}
