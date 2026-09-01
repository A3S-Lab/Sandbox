//! Windows AppContainer and Job Object backend.

use super::windows_shell::{build_powershell_command, encode_powershell_command};
use crate::policy::{resolve_executable, SandboxPolicy};
use crate::{CommandOutput, CommandRequest};
use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::ffi::{c_void, OsStr, OsString};
use std::fs::{File, OpenOptions};
use std::mem::{size_of, zeroed};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::sync::{Mutex, OnceLock};
use tokio::io::AsyncReadExt;
use windows_sys::Win32::Foundation::{
    DuplicateHandle, GetLastError, LocalFree, SetHandleInformation, DUPLICATE_SAME_ACCESS,
    ERROR_BROKEN_PIPE, GENERIC_ALL, GENERIC_EXECUTE, GENERIC_READ, GENERIC_WRITE, HANDLE,
    HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, WAIT_OBJECT_0,
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
    CreateFileW, GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION, DELETE,
    FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
    SetInformationJobObject, TerminateJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_ACTIVE_PROCESS, JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
use windows_sys::Win32::System::Threading::{
    CreateProcessW, DeleteProcThreadAttributeList, GetCurrentProcess, GetExitCodeProcess,
    InitializeProcThreadAttributeList, ResumeThread, TerminateProcess, UpdateProcThreadAttribute,
    WaitForSingleObject, CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT,
    EXTENDED_STARTUPINFO_PRESENT, INFINITE, LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_INFORMATION,
    PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
    STARTF_USESTDHANDLES, STARTUPINFOEXW,
};

const APP_CONTAINER_EXISTS_HRESULT: i32 = 0x8007_00b7_u32 as i32;
const READ_CHUNK_BYTES: usize = 8 * 1024;
const PROCESS_LIMIT: u32 = 256;

#[derive(Debug)]
pub(crate) struct PlatformSandbox {
    powershell: PathBuf,
    appcontainer_sid: SidBuffer,
}

impl PlatformSandbox {
    pub(crate) fn new(workspace: &Path) -> Result<Self> {
        let powershell = resolve_powershell(workspace)?;
        let appcontainer_sid = create_or_open_profile(workspace)?;
        grant_path(
            workspace,
            &appcontainer_sid,
            GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | DELETE,
            GRANT_ACCESS,
        )
        .context("failed to grant the AppContainer access to the workspace")?;
        Ok(Self {
            powershell,
            appcontainer_sid,
        })
    }

    pub(crate) async fn execute(
        &self,
        policy: &SandboxPolicy,
        request: CommandRequest,
    ) -> Result<CommandOutput> {
        let _pins = WorkspacePins::acquire(policy)?;
        apply_execution_acls(policy, &self.appcontainer_sid)?;
        let environment = policy.child_environment(request.env.as_deref())?;
        let child = spawn_appcontainer_process(
            &self.powershell,
            &self.appcontainer_sid,
            &policy.workspace,
            &request.command,
            environment,
        )?;
        capture_process(child, request).await
    }
}

fn resolve_powershell(workspace: &Path) -> Result<PathBuf> {
    let mut buffer = vec![0_u16; 32_768];
    let capacity = u32::try_from(buffer.len()).context("Windows system path buffer overflowed")?;
    let length = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), capacity) };
    if length == 0 {
        return Err(last_windows_error("resolve the Windows system directory"));
    }
    let length = usize::try_from(length).context("Windows system directory length overflowed")?;
    if length >= buffer.len() {
        bail!("Windows system directory exceeds the native sandbox path limit");
    }
    let candidate = PathBuf::from(OsString::from_wide(&buffer[..length]))
        .join("WindowsPowerShell")
        .join("v1.0")
        .join("powershell.exe");
    resolve_executable(candidate, workspace)
        .context("trusted Windows PowerShell executable is unavailable")
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

fn create_or_open_profile(workspace: &Path) -> Result<SidBuffer> {
    let name = appcontainer_profile_name(workspace);
    let wide = wide_null(OsStr::new(&name));
    let display = wide_null(OsStr::new("A3S Code Native Sandbox"));
    let description = wide_null(OsStr::new(
        "A3S-owned AppContainer for fail-closed local command execution",
    ));
    let mut sid = null_mut();
    let created = unsafe {
        CreateAppContainerProfile(
            wide.as_ptr(),
            display.as_ptr(),
            description.as_ptr(),
            null(),
            0,
            &mut sid,
        )
    };
    if created >= 0 {
        return SidBuffer::from_allocated(sid);
    }
    if created != APP_CONTAINER_EXISTS_HRESULT {
        bail!(
            "CreateAppContainerProfile failed with HRESULT 0x{:08x}",
            created as u32
        );
    }
    let derived = unsafe { DeriveAppContainerSidFromAppContainerName(wide.as_ptr(), &mut sid) };
    if derived < 0 {
        bail!(
            "DeriveAppContainerSidFromAppContainerName failed with HRESULT 0x{:08x}",
            derived as u32
        );
    }
    SidBuffer::from_allocated(sid)
}

fn appcontainer_profile_name(workspace: &Path) -> String {
    let mut hasher = Sha256::new();
    for word in workspace.as_os_str().encode_wide() {
        hasher.update(word.to_le_bytes());
    }
    let digest = hasher.finalize();
    let suffix = digest[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("A3S.Code.Sandbox.{suffix}")
}

fn apply_execution_acls(policy: &SandboxPolicy, sid: &SidBuffer) -> Result<()> {
    grant_path(
        &policy.scratch,
        sid,
        GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | DELETE,
        GRANT_ACCESS,
    )?;
    for path in &policy.allow_read {
        if path == &policy.workspace || path == &policy.scratch || !path.exists() {
            continue;
        }
        if let Err(error) = grant_path(path, sid, GENERIC_READ | GENERIC_EXECUTE, GRANT_ACCESS) {
            // System and administrator-owned PATH entries commonly reject DACL
            // mutation while already granting AppContainers read/execute
            // access. Failing to add this optional allow can only reduce the
            // child capability; the process itself will fail closed if the
            // existing ACL is insufficient.
            tracing::debug!(
                path = %path.display(),
                %error,
                "native sandbox could not add optional AppContainer read access"
            );
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
        grant_path(path, sid, GENERIC_ALL, DENY_ACCESS)?;
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
        grant_path(path, sid, GENERIC_WRITE | DELETE, DENY_ACCESS)?;
    }
    Ok(())
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

fn grant_path(path: &Path, sid: &SidBuffer, permissions: u32, access_mode: i32) -> Result<()> {
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

    let inheritance = if path.is_dir() {
        SUB_CONTAINERS_AND_OBJECTS_INHERIT
    } else {
        NO_INHERITANCE
    };
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
    let current_directory = wide_null(workspace.as_os_str());
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
    let stdout = File::from(stdout);
    let stderr = File::from(stderr);
    let mut stdout = tokio::fs::File::from_std(stdout);
    let mut stderr = tokio::fs::File::from_std(stderr);
    let mut stdout_buffer = vec![0_u8; READ_CHUNK_BYTES];
    let mut stderr_buffer = vec![0_u8; READ_CHUNK_BYTES];
    let mut stdout_done = false;
    let mut stderr_done = false;
    let mut process_done = false;
    let mut timed_out = false;
    let mut capture = BoundedCapture::new();
    let deadline = tokio::time::sleep(tokio::time::Duration::from_millis(request.timeout_ms));
    tokio::pin!(deadline);

    while !process_done || !stdout_done || !stderr_done {
        tokio::select! {
            read = stdout.read(&mut stdout_buffer), if !stdout_done => {
                match read {
                    Ok(0) => stdout_done = true,
                    Ok(count) => {
                        let bytes = &stdout_buffer[..count];
                        capture.push(OutputStream::Stdout, bytes);
                        if let Some(observer) = request.output_observer.as_deref() {
                            observer.on_output_delta(&String::from_utf8_lossy(bytes)).await;
                        }
                    }
                    Err(error) => {
                        let message = format!("\n[failed to read command stdout: {error}]\n");
                        capture.push(OutputStream::Stderr, message.as_bytes());
                        stdout_done = true;
                    }
                }
            }
            read = stderr.read(&mut stderr_buffer), if !stderr_done => {
                match read {
                    Ok(0) => stderr_done = true,
                    Ok(count) => {
                        let bytes = &stderr_buffer[..count];
                        capture.push(OutputStream::Stderr, bytes);
                        if let Some(observer) = request.output_observer.as_deref() {
                            observer.on_output_delta(&String::from_utf8_lossy(bytes)).await;
                        }
                    }
                    Err(error) => {
                        let code = error.raw_os_error().map(|code| code as u32);
                        if code != Some(ERROR_BROKEN_PIPE) {
                            let message = format!("\n[failed to read command stderr: {error}]\n");
                            capture.push(OutputStream::Stderr, message.as_bytes());
                        }
                        stderr_done = true;
                    }
                }
            }
            result = &mut wait, if !process_done => {
                result.context("AppContainer wait task failed")??;
                process_done = true;
            }
            _ = &mut deadline, if !timed_out => {
                timed_out = true;
                job.terminate();
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
            pins.acquire_path(path)?;
        }
        Ok(pins)
    }

    fn acquire_path(&mut self, path: &Path) -> Result<()> {
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
        match OpenOptions::new().create_new(true).write(true).open(path) {
            Ok(file) => {
                let (volume, index) = file_identity(&file)?;
                registry.insert(
                    path.to_path_buf(),
                    PinRecord {
                        references: 1,
                        volume,
                        index,
                    },
                );
                self.paths.push(path.to_path_buf());
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
            Err(error) => Err(error)
                .with_context(|| format!("failed to pin write-denied path {}", path.display())),
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
            registry.remove(&path);
            let Ok(file) = File::open(&path) else {
                continue;
            };
            let Ok(metadata) = file.metadata() else {
                continue;
            };
            let Ok(identity) = file_identity(&file) else {
                continue;
            };
            if metadata.is_file() && metadata.len() == 0 && identity == (volume, index) {
                drop(file);
                let _ = std::fs::remove_file(path);
            }
        }
    }
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
    fn appcontainer_name_is_stable_and_workspace_scoped() {
        let first = appcontainer_profile_name(Path::new(r"C:\\work\\one"));
        let same = appcontainer_profile_name(Path::new(r"C:\\work\\one"));
        let second = appcontainer_profile_name(Path::new(r"C:\\work\\two"));
        assert_eq!(first, same);
        assert_ne!(first, second);
        assert!(first.starts_with("A3S.Code.Sandbox."));
    }
}
