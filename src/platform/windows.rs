//! Windows AppContainer and Job Object backend.

use super::windows_shell::{build_powershell_command, encode_powershell_command};
use crate::policy::{requires_directory_placeholder, resolve_executable, SandboxPolicy};
use crate::{CommandOutput, CommandRequest};
use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::ffi::{c_void, OsStr};
use std::fs::{File, OpenOptions};
use std::mem::{size_of, zeroed};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Component, Path, PathBuf, Prefix};
use std::ptr::{null, null_mut};
use std::sync::{Mutex, OnceLock};
use windows_sys::Win32::Foundation::{
    DuplicateHandle, GetLastError, LocalFree, SetHandleInformation, DUPLICATE_SAME_ACCESS,
    ERROR_BROKEN_PIPE, ERROR_NO_DATA, ERROR_PIPE_NOT_CONNECTED, GENERIC_ALL, GENERIC_EXECUTE,
    GENERIC_READ, GENERIC_WRITE, HANDLE, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, WAIT_OBJECT_0,
};
use windows_sys::Win32::Security::Authorization::{
    GetNamedSecurityInfoW, SetEntriesInAclW, SetNamedSecurityInfoW, DENY_ACCESS, EXPLICIT_ACCESS_W,
    GRANT_ACCESS, SE_FILE_OBJECT, TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN,
};
use windows_sys::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeriveAppContainerSidFromAppContainerName,
};
use windows_sys::Win32::Security::{
    FreeSid, GetLengthSid, ACL, DACL_SECURITY_INFORMATION, NO_INHERITANCE, PSID,
    SECURITY_ATTRIBUTES, SECURITY_CAPABILITIES, SUB_CONTAINERS_AND_OBJECTS_INHERIT,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, GetFileInformationByHandle, ReadFile, BY_HANDLE_FILE_INFORMATION, DELETE,
    FILE_ATTRIBUTE_NORMAL, FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
    SetInformationJobObject, TerminateJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_ACTIVE_PROCESS, JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows_sys::Win32::System::Pipes::{CreatePipe, PeekNamedPipe};
use windows_sys::Win32::System::Threading::{
    CreateProcessW, DeleteProcThreadAttributeList, GetCurrentProcess, GetExitCodeProcess,
    InitializeProcThreadAttributeList, ResumeThread, TerminateProcess, UpdateProcThreadAttribute,
    WaitForSingleObject, CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT,
    EXTENDED_STARTUPINFO_PRESENT, INFINITE, LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_INFORMATION,
    PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
    STARTF_USESTDHANDLES, STARTUPINFOEXW,
};

const READ_CHUNK_BYTES: usize = 8 * 1024;
const PIPE_POLL_MS: u64 = 5;
const PIPE_SETTLEMENT_MS: u64 = 500;
const PROCESS_LIMIT: u32 = 256;
const HRESULT_ALREADY_EXISTS: u32 = 0x8007_00b7;
#[derive(Debug)]
pub(crate) struct PlatformSandbox {
    powershell: PathBuf,
    profile: AppContainerProfile,
}

impl PlatformSandbox {
    pub(crate) fn new(workspace: &Path) -> Result<Self> {
        let powershell = resolve_powershell(workspace)?;
        let profile = AppContainerProfile::create()?;
        Ok(Self {
            powershell,
            profile,
        })
    }

    pub(crate) async fn execute(
        &self,
        policy: &SandboxPolicy,
        request: CommandRequest,
    ) -> Result<CommandOutput> {
        // Workspace DACLs are shared host objects. Keep their
        // apply/use/restore lifetime atomic across in-process executions.
        let _execution = execution_gate().lock().await;
        let pins = WorkspacePins::acquire(policy)?;
        let mut acls = ExecutionAcls::apply(policy, &self.profile.sid)?;
        let execution = match policy.child_environment(request.env.as_deref()) {
            Ok(environment) => {
                match spawn_appcontainer_process(
                    &self.powershell,
                    &self.profile.sid,
                    &policy.workspace,
                    &request.command,
                    environment,
                ) {
                    Ok(child) => capture_process(child, request).await,
                    Err(error) => Err(error),
                }
            }
            Err(error) => Err(error),
        };
        let acl_cleanup = acls.restore();
        drop(acls);
        drop(pins);
        finish_execution(execution, acl_cleanup)
    }
}

fn execution_gate() -> &'static tokio::sync::Mutex<()> {
    static GATE: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    GATE.get_or_init(|| tokio::sync::Mutex::new(()))
}

fn finish_execution(
    execution: Result<CommandOutput>,
    acl_cleanup: Result<()>,
) -> Result<CommandOutput> {
    match (execution, acl_cleanup) {
        (Ok(output), Ok(())) => Ok(output),
        (Ok(_), Err(error)) => Err(error),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(cleanup)) => {
            Err(error.context(format!("Windows sandbox cleanup also failed: {cleanup:#}")))
        }
    }
}

fn resolve_powershell(workspace: &Path) -> Result<PathBuf> {
    let program_files = std::env::var_os("ProgramFiles")
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
        .context("Windows Program Files directory is unavailable")?;
    let candidate = program_files.join("PowerShell").join("7").join("pwsh.exe");
    resolve_executable(candidate, workspace)
        .context("PowerShell 7 is required for the Windows native sandbox")
}

#[derive(Debug)]
struct SidBuffer {
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

    fn as_ptr(&self) -> PSID {
        self.words.as_ptr().cast_mut().cast::<c_void>()
    }
}

#[derive(Debug)]
struct AppContainerProfile {
    sid: SidBuffer,
}

impl AppContainerProfile {
    fn create() -> Result<Self> {
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

fn appcontainer_profile_name() -> String {
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

struct ExecutionAcls<'a> {
    sid: &'a SidBuffer,
    paths: Vec<(PathBuf, DaclSnapshot)>,
    modified: HashSet<PathBuf>,
}

impl<'a> ExecutionAcls<'a> {
    fn apply(policy: &SandboxPolicy, sid: &'a SidBuffer) -> Result<Self> {
        let mut guard = Self {
            sid,
            paths: Vec::new(),
            modified: HashSet::new(),
        };
        guard.modify(
            &policy.workspace,
            GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | DELETE,
            GRANT_ACCESS,
        )?;
        guard.modify(
            &policy.scratch,
            GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | DELETE,
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
            guard.modify(path, GENERIC_ALL, DENY_ACCESS)?;
        }
        for path in &policy.deny_write {
            if !path.exists()
                || !policy
                    .allow_write
                    .iter()
                    .any(|allowed| path.starts_with(allowed))
            {
                continue;
            }
            guard.modify(path, GENERIC_WRITE | DELETE, DENY_ACCESS)?;
        }
        Ok(guard)
    }

    fn modify(&mut self, path: &Path, permissions: u32, access_mode: i32) -> Result<()> {
        let inheritance = if path.is_dir() {
            SUB_CONTAINERS_AND_OBJECTS_INHERIT
        } else {
            NO_INHERITANCE
        };
        self.modify_with_inheritance(path, permissions, access_mode, inheritance)
    }

    fn modify_with_inheritance(
        &mut self,
        path: &Path,
        permissions: u32,
        access_mode: i32,
        inheritance: u32,
    ) -> Result<()> {
        let snapshot = if self.modified.contains(path) {
            None
        } else {
            Some(capture_path_dacl(path)?)
        };
        modify_path_acl(path, self.sid, permissions, access_mode, inheritance)?;
        if let Some(snapshot) = snapshot {
            self.modified.insert(path.to_path_buf());
            self.paths.push((path.to_path_buf(), snapshot));
        }
        Ok(())
    }

    fn restore(&mut self) -> Result<()> {
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
}

fn capture_path_dacl(path: &Path) -> Result<DaclSnapshot> {
    let wide = wide_null(path.as_os_str());
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
    let _descriptor = LocalAllocation(descriptor);
    if acl.is_null() {
        return Ok(DaclSnapshot { words: None });
    }
    let bytes = usize::from(unsafe { (*acl).AclSize });
    if bytes < size_of::<ACL>() {
        bail!("Windows returned an invalid DACL for {}", path.display());
    }
    let mut words = vec![0_u32; bytes.div_ceil(size_of::<u32>())];
    unsafe {
        std::ptr::copy_nonoverlapping(acl.cast::<u8>(), words.as_mut_ptr().cast::<u8>(), bytes);
    }
    Ok(DaclSnapshot { words: Some(words) })
}

fn restore_path_dacl(path: &Path, snapshot: &DaclSnapshot) -> Result<()> {
    let wide = wide_null(path.as_os_str());
    let acl = snapshot
        .words
        .as_ref()
        .map_or(null_mut(), |words| words.as_ptr().cast_mut().cast::<ACL>());
    let status = unsafe {
        SetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
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
) -> Result<()> {
    let wide = wide_null(path.as_os_str());
    let mut old_acl: *mut ACL = null_mut();
    let mut descriptor = null_mut();
    let status = unsafe {
        GetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            &mut old_acl,
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
    let _descriptor = LocalAllocation(descriptor);

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
    let status = unsafe {
        SetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
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
    Ok(())
}

struct AttributeList {
    storage: Vec<usize>,
    pointer: LPPROC_THREAD_ATTRIBUTE_LIST,
}

impl AttributeList {
    fn new(attribute_count: u32) -> Result<Self> {
        let mut bytes = 0usize;
        unsafe {
            InitializeProcThreadAttributeList(null_mut(), attribute_count, 0, &mut bytes);
        }
        if bytes == 0 {
            return Err(last_windows_error("size process attribute list"));
        }
        let words = bytes.div_ceil(size_of::<usize>());
        let mut storage = vec![0usize; words];
        let pointer = storage.as_mut_ptr().cast::<c_void>();
        if unsafe { InitializeProcThreadAttributeList(pointer, attribute_count, 0, &mut bytes) }
            == 0
        {
            return Err(last_windows_error("initialize process attribute list"));
        }
        Ok(Self { storage, pointer })
    }

    fn update(&mut self, attribute: usize, value: *const c_void, bytes: usize) -> Result<()> {
        if unsafe {
            UpdateProcThreadAttribute(self.pointer, 0, attribute, value, bytes, null_mut(), null())
        } == 0
        {
            return Err(last_windows_error("update process attribute list"));
        }
        Ok(())
    }
}

impl Drop for AttributeList {
    fn drop(&mut self) {
        let _ = self.storage.len();
        unsafe {
            DeleteProcThreadAttributeList(self.pointer);
        }
    }
}

struct JobGuard {
    handle: OwnedHandle,
}

impl JobGuard {
    fn new() -> Result<Self> {
        let raw = unsafe { CreateJobObjectW(null(), null()) };
        if raw.is_null() {
            return Err(last_windows_error("create native sandbox Job Object"));
        }
        let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
        let mut limits = unsafe { zeroed::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() };
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
            | JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
        limits.BasicLimitInformation.ActiveProcessLimit = PROCESS_LIMIT;
        let size = u32::try_from(size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>())
            .context("Job Object limit structure size overflowed")?;
        if unsafe {
            SetInformationJobObject(
                handle.as_raw_handle(),
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast::<c_void>(),
                size,
            )
        } == 0
        {
            return Err(last_windows_error("configure native sandbox Job Object"));
        }
        Ok(Self { handle })
    }

    fn raw(&self) -> HANDLE {
        self.handle.as_raw_handle()
    }

    fn terminate(&self) {
        unsafe {
            TerminateJobObject(self.raw(), 1);
        }
    }
}

impl Drop for JobGuard {
    fn drop(&mut self) {
        self.terminate();
    }
}

struct WindowsChild {
    process: OwnedHandle,
    job: JobGuard,
    stdout: OwnedHandle,
    stderr: OwnedHandle,
}

fn spawn_appcontainer_process(
    powershell: &Path,
    sid: &SidBuffer,
    workspace: &Path,
    script: &str,
    environment: std::collections::BTreeMap<std::ffi::OsString, std::ffi::OsString>,
) -> Result<WindowsChild> {
    let job = JobGuard::new()?;
    let (stdout_read, stdout_write) = create_pipe()?;
    let (stderr_read, stderr_write) = create_pipe()?;
    let stdin = open_null_input()?;
    let inherited = [
        stdin.as_raw_handle(),
        stdout_write.as_raw_handle(),
        stderr_write.as_raw_handle(),
    ];

    let mut capabilities = SECURITY_CAPABILITIES {
        AppContainerSid: sid.as_ptr(),
        Capabilities: null_mut(),
        CapabilityCount: 0,
        Reserved: 0,
    };
    let mut attributes = AttributeList::new(2)?;
    attributes.update(
        usize::try_from(PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES).unwrap_or(131081),
        (&mut capabilities as *mut SECURITY_CAPABILITIES).cast::<c_void>(),
        size_of::<SECURITY_CAPABILITIES>(),
    )?;
    attributes.update(
        usize::try_from(PROC_THREAD_ATTRIBUTE_HANDLE_LIST).unwrap_or(131074),
        inherited.as_ptr().cast::<c_void>(),
        size_of_val(&inherited),
    )?;

    let wrapped = build_powershell_command(script);
    let encoded = encode_powershell_command(&wrapped);
    let arguments = [
        powershell.as_os_str().to_os_string(),
        "-NoLogo".into(),
        "-NoProfile".into(),
        "-NonInteractive".into(),
        "-ExecutionPolicy".into(),
        "Bypass".into(),
        "-EncodedCommand".into(),
        encoded.into(),
    ];
    let mut command_line = wide_null(OsStr::new(&join_windows_arguments(&arguments)));
    let application = wide_null(powershell.as_os_str());
    let current_directory_path = win32_process_path(workspace);
    let current_directory = wide_null(current_directory_path.as_os_str());
    let environment = environment_block(environment)?;

    let mut startup = STARTUPINFOEXW::default();
    startup.StartupInfo.cb = u32::try_from(size_of::<STARTUPINFOEXW>())
        .context("Windows startup structure size overflowed")?;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = stdin.as_raw_handle();
    startup.StartupInfo.hStdOutput = stdout_write.as_raw_handle();
    startup.StartupInfo.hStdError = stderr_write.as_raw_handle();
    startup.lpAttributeList = attributes.pointer;
    let mut information = unsafe { zeroed::<PROCESS_INFORMATION>() };
    let flags = EXTENDED_STARTUPINFO_PRESENT
        | CREATE_UNICODE_ENVIRONMENT
        | CREATE_SUSPENDED
        | CREATE_NO_WINDOW;
    if unsafe {
        CreateProcessW(
            application.as_ptr(),
            command_line.as_mut_ptr(),
            null(),
            null(),
            1,
            flags,
            environment.as_ptr().cast::<c_void>(),
            current_directory.as_ptr(),
            &startup.StartupInfo,
            &mut information,
        )
    } == 0
    {
        return Err(last_windows_error("create AppContainer PowerShell process"));
    }

    let process = unsafe { OwnedHandle::from_raw_handle(information.hProcess) };
    let thread = unsafe { OwnedHandle::from_raw_handle(information.hThread) };
    if unsafe { AssignProcessToJobObject(job.raw(), process.as_raw_handle()) } == 0 {
        unsafe {
            TerminateProcess(process.as_raw_handle(), 1);
        }
        return Err(last_windows_error(
            "assign AppContainer process to native sandbox Job Object",
        ));
    }
    if unsafe { ResumeThread(thread.as_raw_handle()) } == u32::MAX {
        unsafe {
            TerminateProcess(process.as_raw_handle(), 1);
        }
        return Err(last_windows_error("resume AppContainer process"));
    }
    drop(thread);
    drop(stdin);
    drop(stdout_write);
    drop(stderr_write);
    Ok(WindowsChild {
        process,
        job,
        stdout: stdout_read,
        stderr: stderr_read,
    })
}

fn create_pipe() -> Result<(OwnedHandle, OwnedHandle)> {
    let attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(0),
        lpSecurityDescriptor: null_mut(),
        bInheritHandle: 1,
    };
    let mut read = null_mut();
    let mut write = null_mut();
    if unsafe { CreatePipe(&mut read, &mut write, &attributes, 0) } == 0 {
        return Err(last_windows_error("create AppContainer output pipe"));
    }
    let read = unsafe { OwnedHandle::from_raw_handle(read) };
    let write = unsafe { OwnedHandle::from_raw_handle(write) };
    if unsafe { SetHandleInformation(read.as_raw_handle(), HANDLE_FLAG_INHERIT, 0) } == 0 {
        return Err(last_windows_error(
            "make AppContainer output pipe private to the parent",
        ));
    }
    Ok((read, write))
}

fn open_null_input() -> Result<OwnedHandle> {
    let name = wide_null(OsStr::new("NUL"));
    let attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(0),
        lpSecurityDescriptor: null_mut(),
        bInheritHandle: 1,
    };
    let raw = unsafe {
        CreateFileW(
            name.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            &attributes,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(last_windows_error("open NUL for AppContainer stdin"));
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
}

async fn capture_process(child: WindowsChild, request: CommandRequest) -> Result<CommandOutput> {
    use crate::process::{BoundedCapture, OutputStream};

    let WindowsChild {
        process,
        job,
        stdout,
        stderr,
    } = child;
    let wait_handle = duplicate_handle(&process)?;
    let mut wait = tokio::task::spawn_blocking(move || {
        let result = unsafe { WaitForSingleObject(wait_handle.as_raw_handle(), INFINITE) };
        if result != WAIT_OBJECT_0 {
            return Err(last_windows_error("wait for AppContainer process"));
        }
        Ok::<(), anyhow::Error>(())
    });
    let mut stdout_buffer = vec![0_u8; READ_CHUNK_BYTES];
    let mut stderr_buffer = vec![0_u8; READ_CHUNK_BYTES];
    let mut stdout_done = false;
    let mut stderr_done = false;
    let mut process_done = false;
    let mut timed_out = false;
    let mut capture = BoundedCapture::new();
    let deadline = tokio::time::sleep(tokio::time::Duration::from_millis(request.timeout_ms));
    tokio::pin!(deadline);
    let settlement = tokio::time::sleep(tokio::time::Duration::from_secs(24 * 60 * 60));
    tokio::pin!(settlement);
    let mut settlement_active = false;
    let mut pipe_poll = tokio::time::interval(tokio::time::Duration::from_millis(PIPE_POLL_MS));
    pipe_poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    while !process_done || !stdout_done || !stderr_done {
        tokio::select! {
            _ = pipe_poll.tick(), if !stdout_done || !stderr_done => {
                if !stdout_done {
                    match poll_pipe(&stdout, &mut stdout_buffer)? {
                        PipePoll::Closed => stdout_done = true,
                        PipePoll::Empty => {}
                        PipePoll::Data(count) => {
                        let bytes = &stdout_buffer[..count];
                        capture.push(OutputStream::Stdout, bytes);
                        if let Some(observer) = request.output_observer.as_deref() {
                            observer.on_output_delta(&String::from_utf8_lossy(bytes)).await;
                        }
                    }
                    }
                }
                if !stderr_done {
                    match poll_pipe(&stderr, &mut stderr_buffer)? {
                        PipePoll::Closed => stderr_done = true,
                        PipePoll::Empty => {}
                        PipePoll::Data(count) => {
                        let bytes = &stderr_buffer[..count];
                        capture.push(OutputStream::Stderr, bytes);
                        if let Some(observer) = request.output_observer.as_deref() {
                            observer.on_output_delta(&String::from_utf8_lossy(bytes)).await;
                        }
                    }
                    }
                }
            }
            result = &mut wait, if !process_done => {
                result.context("AppContainer wait task failed")??;
                process_done = true;
                if (!stdout_done || !stderr_done) && !settlement_active {
                    settlement.as_mut().reset(
                        tokio::time::Instant::now()
                            + tokio::time::Duration::from_millis(PIPE_SETTLEMENT_MS),
                    );
                    settlement_active = true;
                }
            }
            _ = &mut deadline, if !timed_out => {
                timed_out = true;
                job.terminate();
                if !settlement_active {
                    settlement.as_mut().reset(
                        tokio::time::Instant::now()
                            + tokio::time::Duration::from_millis(PIPE_SETTLEMENT_MS),
                    );
                    settlement_active = true;
                }
            }
            _ = &mut settlement, if settlement_active => {
                // A broker or descendant can retain a duplicate write handle
                // after the root exits. Bound that drain window and kill the
                // complete job before the temporary ACLs are revoked.
                job.terminate();
                break;
            }
        }
    }

    let summary = capture.summary(timed_out);
    if let Some(observer) = request.output_observer.as_deref() {
        observer.on_output_complete(&summary).await;
    }
    let exit_code = if timed_out {
        -1
    } else {
        let mut code = 0u32;
        if unsafe { GetExitCodeProcess(process.as_raw_handle(), &mut code) } == 0 {
            return Err(last_windows_error("read AppContainer process exit code"));
        }
        i32::try_from(code).unwrap_or(-1)
    };
    drop(job);
    Ok(CommandOutput {
        stdout: capture.render_stream(OutputStream::Stdout),
        stderr: capture.render_stream(OutputStream::Stderr),
        exit_code,
        timed_out,
    })
}

enum PipePoll {
    Data(usize),
    Empty,
    Closed,
}

fn poll_pipe(handle: &OwnedHandle, buffer: &mut [u8]) -> Result<PipePoll> {
    let mut available = 0u32;
    if unsafe {
        PeekNamedPipe(
            handle.as_raw_handle(),
            null_mut(),
            0,
            null_mut(),
            &mut available,
            null_mut(),
        )
    } == 0
    {
        let code = unsafe { GetLastError() };
        if matches!(
            code,
            ERROR_BROKEN_PIPE | ERROR_NO_DATA | ERROR_PIPE_NOT_CONNECTED
        ) {
            return Ok(PipePoll::Closed);
        }
        bail!("peek AppContainer output pipe failed with Windows error {code}");
    }
    if available == 0 {
        return Ok(PipePoll::Empty);
    }
    let bytes = available
        .min(u32::try_from(buffer.len()).context("AppContainer output buffer size overflowed")?);
    let mut read = 0u32;
    if unsafe {
        ReadFile(
            handle.as_raw_handle(),
            buffer.as_mut_ptr(),
            bytes,
            &mut read,
            null_mut(),
        )
    } == 0
    {
        let code = unsafe { GetLastError() };
        if matches!(
            code,
            ERROR_BROKEN_PIPE | ERROR_NO_DATA | ERROR_PIPE_NOT_CONNECTED
        ) {
            return Ok(PipePoll::Closed);
        }
        bail!("read AppContainer output pipe failed with Windows error {code}");
    }
    Ok(PipePoll::Data(
        usize::try_from(read).context("AppContainer output byte count overflowed")?,
    ))
}

fn duplicate_handle(handle: &OwnedHandle) -> Result<OwnedHandle> {
    let process = unsafe { GetCurrentProcess() };
    let mut duplicate = null_mut();
    if unsafe {
        DuplicateHandle(
            process,
            handle.as_raw_handle(),
            process,
            &mut duplicate,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    } == 0
    {
        return Err(last_windows_error("duplicate AppContainer process handle"));
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(duplicate) })
}

fn environment_block(
    environment: std::collections::BTreeMap<std::ffi::OsString, std::ffi::OsString>,
) -> Result<Vec<u16>> {
    let mut block = Vec::new();
    for (key, value) in environment {
        if key.is_empty() || key.to_string_lossy().contains('=') {
            bail!("invalid Windows environment key: {key:?}");
        }
        block.extend(key.encode_wide());
        block.push('=' as u16);
        block.extend(value.encode_wide());
        block.push(0);
    }
    block.push(0);
    Ok(block)
}

fn join_windows_arguments(arguments: &[std::ffi::OsString]) -> String {
    arguments
        .iter()
        .map(|argument| quote_windows_argument(&argument.to_string_lossy()))
        .collect::<Vec<_>>()
        .join(" ")
}

fn win32_process_path(path: &Path) -> PathBuf {
    let mut components = path.components();
    let Some(Component::Prefix(prefix)) = components.next() else {
        return path.to_path_buf();
    };
    let mut normalized = match prefix.kind() {
        Prefix::VerbatimDisk(drive) => PathBuf::from(format!("{}:\\", char::from(drive))),
        Prefix::VerbatimUNC(server, share) => {
            let mut path = PathBuf::from(r"\\");
            path.push(server);
            path.push(share);
            path
        }
        _ => return path.to_path_buf(),
    };
    for component in components {
        if !matches!(component, Component::RootDir) {
            normalized.push(component.as_os_str());
        }
    }
    normalized
}

fn quote_windows_argument(argument: &str) -> String {
    if !argument.is_empty()
        && !argument
            .chars()
            .any(|character| character.is_whitespace() || character == '"')
    {
        return argument.to_string();
    }
    let mut quoted = String::from("\"");
    let mut backslashes = 0usize;
    for character in argument.chars() {
        if character == '\\' {
            backslashes += 1;
        } else if character == '"' {
            quoted.push_str(&"\\".repeat(backslashes * 2 + 1));
            quoted.push('"');
            backslashes = 0;
        } else {
            quoted.push_str(&"\\".repeat(backslashes));
            backslashes = 0;
            quoted.push(character);
        }
    }
    quoted.push_str(&"\\".repeat(backslashes * 2));
    quoted.push('"');
    quoted
}

fn wide_null(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(std::iter::once(0)).collect()
}

fn last_windows_error(operation: &str) -> anyhow::Error {
    let code = unsafe { GetLastError() };
    anyhow::anyhow!("{operation} failed with Windows error {code}")
}

#[derive(Debug)]
struct PinRecord {
    references: usize,
    volume: u32,
    index: u64,
    directory: bool,
}

fn pin_registry() -> &'static Mutex<HashMap<PathBuf, PinRecord>> {
    static REGISTRY: OnceLock<Mutex<HashMap<PathBuf, PinRecord>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

struct WorkspacePins {
    paths: Vec<PathBuf>,
}

impl WorkspacePins {
    fn acquire(policy: &SandboxPolicy) -> Result<Self> {
        let mut pins = Self { paths: Vec::new() };
        for path in &policy.deny_write {
            if !path.starts_with(&policy.workspace) {
                continue;
            }
            pins.acquire_path(&policy.workspace, path)?;
        }
        Ok(pins)
    }

    fn acquire_path(&mut self, workspace: &Path, path: &Path) -> Result<()> {
        let mut registry = pin_registry()
            .lock()
            .map_err(|_| anyhow::anyhow!("native sandbox placeholder registry was poisoned"))?;
        if let Some(record) = registry.get_mut(path) {
            record.references = record
                .references
                .checked_add(1)
                .context("native sandbox placeholder reference count overflowed")?;
            self.paths.push(path.to_path_buf());
            return Ok(());
        }
        let parent = path.parent().context("write-denied path has no parent")?;
        if !parent.is_dir() {
            bail!(
                "cannot pin nonexistent write-denied path because its parent is absent: {}",
                path.display()
            );
        }
        let directory = requires_directory_placeholder(workspace, path);
        match create_placeholder(path, directory)? {
            Some((volume, index)) => {
                registry.insert(
                    path.to_path_buf(),
                    PinRecord {
                        references: 1,
                        volume,
                        index,
                        directory,
                    },
                );
                self.paths.push(path.to_path_buf());
                Ok(())
            }
            None => Ok(()),
        }
    }
}

impl Drop for WorkspacePins {
    fn drop(&mut self) {
        let Ok(mut registry) = pin_registry().lock() else {
            return;
        };
        for path in self.paths.drain(..) {
            let Some(record) = registry.get_mut(&path) else {
                continue;
            };
            if record.references > 1 {
                record.references -= 1;
                continue;
            }
            let volume = record.volume;
            let index = record.index;
            let directory = record.directory;
            registry.remove(&path);
            let Ok(file) = open_placeholder(&path, directory) else {
                continue;
            };
            let Ok(metadata) = file.metadata() else {
                continue;
            };
            let Ok(identity) = file_identity(&file) else {
                continue;
            };
            if identity == (volume, index) && directory && metadata.is_dir() {
                drop(file);
                let _ = std::fs::remove_dir(path);
            } else if identity == (volume, index)
                && !directory
                && metadata.is_file()
                && metadata.len() == 0
            {
                drop(file);
                let _ = std::fs::remove_file(path);
            }
        }
    }
}

fn create_placeholder(path: &Path, directory: bool) -> Result<Option<(u32, u64)>> {
    if directory {
        match std::fs::create_dir(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => return Ok(None),
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("failed to pin write-denied directory {}", path.display())
                })
            }
        }
        let identity = open_placeholder(path, true).and_then(|handle| file_identity(&handle));
        return match identity {
            Ok(identity) => Ok(Some(identity)),
            Err(error) => {
                let _ = std::fs::remove_dir(path);
                Err(error)
            }
        };
    }

    match OpenOptions::new().create_new(true).write(true).open(path) {
        Ok(file) => match file_identity(&file) {
            Ok(identity) => Ok(Some(identity)),
            Err(error) => {
                drop(file);
                let _ = std::fs::remove_file(path);
                Err(error)
            }
        },
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(None),
        Err(error) => Err(error)
            .with_context(|| format!("failed to pin write-denied file {}", path.display())),
    }
}

fn open_placeholder(path: &Path, directory: bool) -> Result<File> {
    let wide = wide_null(path.as_os_str());
    let flags = if directory {
        FILE_FLAG_BACKUP_SEMANTICS
    } else {
        FILE_ATTRIBUTE_NORMAL
    };
    let raw = unsafe {
        CreateFileW(
            wide.as_ptr(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null(),
            OPEN_EXISTING,
            flags,
            null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(last_windows_error("open native sandbox placeholder"));
    }
    Ok(File::from(unsafe { OwnedHandle::from_raw_handle(raw) }))
}

fn file_identity(file: &File) -> Result<(u32, u64)> {
    let mut information = unsafe { zeroed::<BY_HANDLE_FILE_INFORMATION>() };
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut information) } == 0 {
        return Err(last_windows_error("inspect native sandbox placeholder"));
    }
    let index =
        (u64::from(information.nFileIndexHigh) << 32) | u64::from(information.nFileIndexLow);
    Ok((information.dwVolumeSerialNumber, index))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_argument_quoting_preserves_spaces_quotes_and_trailing_slashes() {
        assert_eq!(quote_windows_argument("plain"), "plain");
        assert_eq!(quote_windows_argument("two words"), "\"two words\"");
        assert_eq!(quote_windows_argument(""), "\"\"");
        assert_eq!(quote_windows_argument("a\\\"b"), "\"a\\\\\\\"b\"");
        assert_eq!(
            quote_windows_argument("C:\\path with space\\"),
            "\"C:\\path with space\\\\\""
        );
    }

    #[test]
    fn appcontainer_name_is_stable_and_process_scoped() {
        let first = appcontainer_profile_name();
        let same = appcontainer_profile_name();
        assert_eq!(first, same);
        assert!(first.starts_with("A3S.Sandbox.Execution."));
    }

    #[test]
    fn process_paths_drop_verbatim_prefixes() {
        assert_eq!(
            win32_process_path(Path::new(r"\\?\C:\work tree")),
            PathBuf::from(r"C:\work tree")
        );
        assert_eq!(
            win32_process_path(Path::new(r"\\?\UNC\server\share\work")),
            PathBuf::from(r"\\server\share\work")
        );
    }
}
