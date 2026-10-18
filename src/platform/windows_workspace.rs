//! Physical directory ownership across Windows sandbox hosts.

use super::windows::last_windows_error;
use super::windows_security::open_host_mutex;
use anyhow::{bail, Context, Result};
use std::fs::{File, OpenOptions};
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::{AsRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::{oneshot, Mutex};
use windows_sys::Win32::Foundation::{WAIT_ABANDONED, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows_sys::Win32::Storage::FileSystem::{
    FileIdInfo, GetFileInformationByHandleEx, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_ID_INFO, FILE_LIST_DIRECTORY,
    FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
};
use windows_sys::Win32::System::Threading::{ReleaseMutex, WaitForSingleObject};

#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FileIdentity {
    volume: u64,
    file: [u8; 16],
}

#[derive(Debug)]
pub(super) struct WorkspaceDirectory {
    path: PathBuf,
    identity: FileIdentity,
    _identity_pin: File,
    local_owner: Arc<Mutex<()>>,
}

pub(crate) struct WorkspaceLease {
    _handle: File,
    _release: oneshot::Sender<()>,
    pub(super) journal_name: String,
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
            identity: file_identity(&pin)?,
            _identity_pin: pin,
            local_owner: Arc::new(Mutex::new(())),
        })
    }

    pub(super) async fn acquire(&self) -> Result<WorkspaceLease> {
        let local_owner = self.local_owner.clone().lock_owned().await;
        let file = self
            .identity
            .file
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let journal_name = format!("{:016x}.{file}", self.identity.volume);
        let name = format!(r"Global\A3S.Sandbox.Workspace.{journal_name}");
        let mutex = open_host_mutex(&name)?;
        let (ready, acquired) = oneshot::channel();
        let (release, released) = oneshot::channel();
        // Keep ownership and release on one OS thread even when the async caller moves.
        // shortcut: one blocking owner per sandbox; global task admission remains S5 work.
        tokio::task::spawn_blocking(move || {
            let _local_owner = local_owner;
            own_until_released(mutex, ready, released);
        });
        acquired
            .await
            .context("Windows workspace ownership worker stopped before acquisition")??;
        // Attribute-only handles do not enforce sharing checks, including delete exclusion.
        let handle = open_directory(
            &self.path,
            FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
        )
        .context("pin Windows workspace root during execution")?;
        if file_identity(&handle)? != self.identity {
            bail!("Windows workspace identity changed before execution");
        }
        Ok(WorkspaceLease {
            _handle: handle,
            _release: release,
            journal_name,
        })
    }
}

struct MutexOwner(OwnedHandle);

impl Drop for MutexOwner {
    fn drop(&mut self) {
        unsafe { ReleaseMutex(self.0.as_raw_handle()) };
    }
}

fn own_until_released(
    handle: OwnedHandle,
    ready: oneshot::Sender<Result<()>>,
    released: oneshot::Receiver<()>,
) {
    loop {
        if ready.is_closed() {
            return;
        }
        match unsafe { WaitForSingleObject(handle.as_raw_handle(), 10) } {
            WAIT_OBJECT_0 | WAIT_ABANDONED => {
                let _owner = MutexOwner(handle);
                if ready.send(Ok(())).is_ok() {
                    let _ = released.blocking_recv();
                }
                return;
            }
            WAIT_TIMEOUT => {}
            _ => {
                let _ = ready.send(Err(last_windows_error(
                    "acquire Windows workspace ownership",
                )));
                return;
            }
        }
    }
}

fn open_directory(path: &Path, access: u32, sharing: u32) -> std::io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .access_mode(access)
        .share_mode(sharing)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(std::io::Error::other(
            "Windows workspace root must be a directory without a reparse point",
        ));
    }
    Ok(file)
}

pub(super) fn file_identity(file: &File) -> Result<FileIdentity> {
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
    Ok(FileIdentity {
        volume: information.VolumeSerialNumber,
        file: information.FileId.Identifier,
    })
}
