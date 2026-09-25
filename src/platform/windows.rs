//! Windows AppContainer and Job Object backend.

#[cfg(test)]
use super::windows_security::appcontainer_profile_name;
use super::windows_security::{AppContainerProfile, ExecutionAcls, SidBuffer};
use super::windows_shell::{build_powershell_command, encode_powershell_command};
use crate::policy::{
    requires_directory_placeholder, resolve_executable, EnforcedPolicy, ResolvedResourceBudget,
};
use crate::{CommandOutput, CommandRequest};
use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::ffi::{c_void, OsStr, OsString};
use std::fs::{File, OpenOptions};
use std::mem::{size_of, size_of_val, zeroed};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Component, Path, PathBuf, Prefix};
use std::ptr::{null, null_mut};
use std::sync::{Mutex, OnceLock};
use windows_sys::Win32::Foundation::{
    DuplicateHandle, GetLastError, SetHandleInformation, DUPLICATE_SAME_ACCESS, ERROR_BROKEN_PIPE,
    ERROR_NO_DATA, ERROR_PIPE_NOT_CONNECTED, GENERIC_READ, HANDLE, HANDLE_FLAG_INHERIT,
    INVALID_HANDLE_VALUE, WAIT_OBJECT_0,
};
use windows_sys::Win32::Security::{SECURITY_ATTRIBUTES, SECURITY_CAPABILITIES};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, DefineDosDeviceW, GetFileInformationByHandle, GetLogicalDrives, ReadFile,
    BY_HANDLE_FILE_INFORMATION, DDD_EXACT_MATCH_ON_REMOVE, DDD_NO_BROADCAST_SYSTEM,
    DDD_RAW_TARGET_PATH, DDD_REMOVE_DEFINITION, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
    SetInformationJobObject, TerminateJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_ACTIVE_PROCESS, JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_LIMIT_PROCESS_MEMORY,
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

    /// Factory that recreates the same pipe name with the session AppContainer SID.
    ///
    /// Kept for accept-loop name-open experiments; live guests use
    /// [`Self::create_mediation_pipe`] + handle inheritance.
    #[allow(dead_code)]
    pub(crate) fn mediator_named_pipe_factory(
        &self,
        pipe_name: String,
    ) -> impl FnMut() -> Result<OwnedHandle> + Send + 'static {
        let sid = self.profile.sid.clone();
        move || super::windows_security::create_appcontainer_named_pipe(&pipe_name, &sid)
    }

    /// Create a connected mediation pipe pair for AppContainer handle inheritance.
    pub(crate) fn create_mediation_pipe(
        &self,
        pipe_name: &str,
    ) -> Result<(OwnedHandle, OwnedHandle)> {
        super::windows_security::create_appcontainer_mediation_pipe(pipe_name, &self.profile.sid)
    }

    pub(crate) async fn execute(
        &self,
        policy: &EnforcedPolicy,
        request: CommandRequest,
    ) -> Result<CommandOutput> {
        self.execute_inner(policy, request, None).await
    }

    /// Execute with an inherited, already-connected mediation pipe client handle.
    pub(crate) async fn execute_with_mediator_client(
        &self,
        policy: &EnforcedPolicy,
        request: CommandRequest,
        mediator_client: OwnedHandle,
    ) -> Result<CommandOutput> {
        self.execute_inner(policy, request, Some(mediator_client))
            .await
    }

    async fn execute_inner(
        &self,
        policy: &EnforcedPolicy,
        request: CommandRequest,
        mediator_client: Option<OwnedHandle>,
    ) -> Result<CommandOutput> {
        // Workspace DACLs are restored after each command. Serialize per
        // workspace so apply/use/restore cannot race. Ancestor ACL mutations
        // (Temp/home traverse) are globally serialized so concurrent workspaces
        // cannot corrupt shared parent DACLs.
        let execution_gate = workspace_execution_gate(&policy.workspace);
        let _execution = execution_gate.lock().await;
        let pins = WorkspacePins::acquire(policy)?;
        let budget = ResolvedResourceBudget::resolve(&policy.resources, request.timeout_ms)?;
        budget.validate_for_backend(crate::policy::BackendCapabilities::native_gate2())?;
        let mut acls = {
            let _acl_gate = acl_mutation_gate()
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            ExecutionAcls::apply(policy, &self.profile.sid)?
        };
        let execution = match policy.child_environment(request.env.as_deref()) {
            Ok(mut environment) => {
                if let Some(client) = mediator_client.as_ref() {
                    environment.insert(
                        OsString::from("A3S_SANDBOX_MEDIATOR_PIPE_HANDLE"),
                        OsString::from(format!("{}", client.as_raw_handle() as usize)),
                    );
                }
                match spawn_appcontainer_process(
                    &self.powershell,
                    &self.profile.sid,
                    &policy.workspace,
                    &policy.scratch,
                    &request.command,
                    environment,
                    &budget,
                    mediator_client,
                ) {
                    Ok(child) => capture_process(child, request, &budget).await,
                    Err(error) => Err(error),
                }
            }
            Err(error) => Err(error),
        };
        let acl_cleanup = {
            let _acl_gate = acl_mutation_gate()
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            acls.restore()
        };
        drop(acls);
        drop(pins);
        finish_execution(execution, acl_cleanup)
    }
}

fn workspace_execution_gate(workspace: &Path) -> std::sync::Arc<tokio::sync::Mutex<()>> {
    use std::sync::Arc;
    static GATES: OnceLock<Mutex<HashMap<PathBuf, Arc<tokio::sync::Mutex<()>>>>> = OnceLock::new();
    let gates = GATES.get_or_init(|| Mutex::new(HashMap::new()));
    let key = workspace.to_path_buf();
    let mut map = gates
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    map.entry(key)
        .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
        .clone()
}

fn drive_allocation_gate() -> &'static Mutex<()> {
    static GATE: OnceLock<Mutex<()>> = OnceLock::new();
    GATE.get_or_init(|| Mutex::new(()))
}

fn acl_mutation_gate() -> &'static Mutex<()> {
    static GATE: OnceLock<Mutex<()>> = OnceLock::new();
    GATE.get_or_init(|| Mutex::new(()))
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

pub(crate) fn resolve_powershell(workspace: &Path) -> Result<PathBuf> {
    let program_files = std::env::var_os("ProgramFiles")
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
        .context("Windows Program Files directory is unavailable")?;
    let candidate = program_files.join("PowerShell").join("7").join("pwsh.exe");
    resolve_executable(candidate, workspace)
        .context("PowerShell 7 is required for the Windows native sandbox")
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
    fn new(budget: &ResolvedResourceBudget) -> Result<Self> {
        let raw = unsafe { CreateJobObjectW(null(), null()) };
        if raw.is_null() {
            return Err(last_windows_error("create native sandbox Job Object"));
        }
        let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
        let mut limits = unsafe { zeroed::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() };
        let mut flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
            | JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
        limits.BasicLimitInformation.ActiveProcessLimit =
            budget.max_processes.unwrap_or(PROCESS_LIMIT);
        if let Some(max_memory_bytes) = budget.max_memory_bytes {
            flags |= JOB_OBJECT_LIMIT_PROCESS_MEMORY;
            limits.ProcessMemoryLimit = usize::try_from(max_memory_bytes)
                .context("Windows Job Object process memory limit does not fit into usize")?;
        }
        limits.BasicLimitInformation.LimitFlags = flags;
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
    workspace_drive: WorkspaceDrive,
    /// Keeps the inherited mediation client handle alive for the guest.
    _mediator_client: Option<OwnedHandle>,
    /// Long scripts are launched with `-File` so the command line stays under
    /// the Windows 32767-character limit. Removed after the process exits.
    script_file: ScriptFile,
}

struct WorkspaceDrive {
    name: Vec<u16>,
    target: Vec<u16>,
    root: PathBuf,
    active: bool,
}

impl WorkspaceDrive {
    fn create(workspace: &Path) -> Result<Self> {
        let _drive_gate = drive_allocation_gate()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let workspace = win32_process_path(workspace);
        if !matches!(
            workspace.components().next(),
            Some(Component::Prefix(prefix))
                if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))
        ) {
            bail!(
                "Windows native sandbox requires a workspace on a local drive: {}",
                workspace.display()
            );
        }

        let mut target = OsString::from(r"\??\");
        target.push(workspace.as_os_str());
        let target = wide_null(&target);
        let occupied = unsafe { GetLogicalDrives() };
        let mut last_error = 0;
        for letter in (b'D'..=b'Z').rev() {
            let bit = 1_u32 << u32::from(letter - b'A');
            if occupied & bit != 0 {
                continue;
            }
            let name = wide_null(OsStr::new(&format!("{}:", char::from(letter))));
            let flags = DDD_RAW_TARGET_PATH | DDD_NO_BROADCAST_SYSTEM;
            if unsafe { DefineDosDeviceW(flags, name.as_ptr(), target.as_ptr()) } != 0 {
                return Ok(Self {
                    name,
                    target,
                    root: PathBuf::from(format!("{}:\\", char::from(letter))),
                    active: true,
                });
            }
            last_error = unsafe { GetLastError() };
        }
        bail!("failed to reserve a Windows sandbox drive with error {last_error}")
    }

    fn root(&self) -> &Path {
        &self.root
    }

    fn remove(&mut self) -> Result<()> {
        if !self.active {
            return Ok(());
        }
        let _drive_gate = drive_allocation_gate()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let flags = DDD_REMOVE_DEFINITION
            | DDD_EXACT_MATCH_ON_REMOVE
            | DDD_RAW_TARGET_PATH
            | DDD_NO_BROADCAST_SYSTEM;
        if unsafe { DefineDosDeviceW(flags, self.name.as_ptr(), self.target.as_ptr()) } == 0 {
            return Err(last_windows_error("remove temporary Windows sandbox drive"));
        }
        self.active = false;
        Ok(())
    }
}

impl Drop for WorkspaceDrive {
    fn drop(&mut self) {
        let _ = self.remove();
    }
}

const MAX_POWERSHELL_COMMAND_CHARS: usize = 30_000;

struct ScriptFile(Option<PathBuf>);

impl Drop for ScriptFile {
    fn drop(&mut self) {
        if let Some(path) = self.0.take() {
            let _ = std::fs::remove_file(path);
        }
    }
}

fn powershell_arguments(
    powershell: &Path,
    scratch: &Path,
    wrapped: &str,
) -> Result<(Vec<OsString>, ScriptFile)> {
    let encoded = encode_powershell_command(wrapped);
    let encoded_arguments = powershell_flags(
        powershell,
        vec![OsString::from("-EncodedCommand"), OsString::from(encoded)],
    );
    if join_windows_arguments(&encoded_arguments)
        .encode_utf16()
        .count()
        <= MAX_POWERSHELL_COMMAND_CHARS
    {
        return Ok((encoded_arguments, ScriptFile(None)));
    }

    std::fs::create_dir_all(scratch)
        .with_context(|| format!("create scratch {}", scratch.display()))?;
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or(0);
    let path = scratch.join(format!("a3s-command-{}-{unique}.ps1", std::process::id()));
    // -File does not turn a failed cmdlet into a non-zero process exit.
    // -EncodedCommand does. Keep that kernel signal for deny checks.
    let file_body = format!("trap {{ exit 1 }}\n{wrapped}\nif (-not $?) {{ exit 1 }}\n");
    std::fs::write(&path, file_body.as_bytes())
        .with_context(|| format!("write PowerShell script {}", path.display()))?;
    let file_arguments = powershell_flags(
        powershell,
        vec![OsString::from("-File"), path.as_os_str().to_os_string()],
    );
    Ok((file_arguments, ScriptFile(Some(path))))
}

fn powershell_flags(powershell: &Path, tail: Vec<OsString>) -> Vec<OsString> {
    let mut arguments = vec![
        powershell.as_os_str().to_os_string(),
        OsString::from("-NoLogo"),
        OsString::from("-NoProfile"),
        OsString::from("-NonInteractive"),
        OsString::from("-ExecutionPolicy"),
        OsString::from("Bypass"),
    ];
    arguments.extend(tail);
    arguments
}

#[allow(clippy::too_many_arguments)] // AppContainer spawn needs identity, FS roots, and optional pipe.
fn spawn_appcontainer_process(
    powershell: &Path,
    sid: &SidBuffer,
    workspace: &Path,
    scratch: &Path,
    script: &str,
    environment: std::collections::BTreeMap<std::ffi::OsString, std::ffi::OsString>,
    budget: &ResolvedResourceBudget,
    mediator_client: Option<OwnedHandle>,
) -> Result<WindowsChild> {
    let workspace_drive = WorkspaceDrive::create(workspace)?;
    let job = JobGuard::new(budget)?;
    let (stdout_read, stdout_write) = create_pipe()?;
    let (stderr_read, stderr_write) = create_pipe()?;
    let stdin = open_null_input()?;
    let mut inherited = vec![
        stdin.as_raw_handle(),
        stdout_write.as_raw_handle(),
        stderr_write.as_raw_handle(),
    ];
    if let Some(client) = mediator_client.as_ref() {
        inherited.push(client.as_raw_handle());
    }

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
        size_of_val(inherited.as_slice()),
    )?;

    let workspace_literal = workspace_drive.root().to_string_lossy().replace('\'', "''");
    // Install the compatibility shim before invoking any cmdlet. In an
    // AppContainer, resolving Set-Location can make PowerShell scan its module
    // paths and emit progress records as CLIXML on stderr. The shim disables
    // progress output, but it cannot suppress records produced before it runs.
    let workspace_script =
        format!("Set-Location -LiteralPath '{workspace_literal}' -ErrorAction Stop\n{script}");
    let wrapped = build_powershell_command(&workspace_script);
    let (arguments, script_file) = powershell_arguments(powershell, scratch, &wrapped)?;
    let mut command_line = wide_null(OsStr::new(&join_windows_arguments(&arguments)));
    let application = wide_null(powershell.as_os_str());
    let current_directory = wide_null(workspace_drive.root().as_os_str());
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
        workspace_drive,
        _mediator_client: mediator_client,
        script_file,
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

async fn capture_process(
    child: WindowsChild,
    request: CommandRequest,
    budget: &ResolvedResourceBudget,
) -> Result<CommandOutput> {
    use crate::process::{BoundedCapture, OutputStream};

    let WindowsChild {
        process,
        job,
        stdout,
        stderr,
        mut workspace_drive,
        _mediator_client,
        script_file: _script_file,
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
    let mut capture = BoundedCapture::new(budget.max_output_bytes);
    let deadline = tokio::time::sleep(tokio::time::Duration::from_millis(budget.timeout_ms));
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
    workspace_drive.remove()?;
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

pub(super) fn win32_process_path(path: &Path) -> PathBuf {
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

pub(super) fn wide_null(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(std::iter::once(0)).collect()
}

pub(super) fn last_windows_error(operation: &str) -> anyhow::Error {
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
    fn acquire(policy: &EnforcedPolicy) -> Result<Self> {
        let mut pins = Self { paths: Vec::new() };
        for path in &policy.deny_write {
            if !path.starts_with(&policy.workspace) {
                continue;
            }
            if policy
                .write_exceptions
                .iter()
                .any(|exception| path == exception || path.starts_with(exception))
            {
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

    #[test]
    fn workspace_execution_gates_are_isolated_by_path() {
        let left = workspace_execution_gate(Path::new(r"C:\sandbox-a"));
        let right = workspace_execution_gate(Path::new(r"C:\sandbox-b"));
        let left_again = workspace_execution_gate(Path::new(r"C:\sandbox-a"));
        assert!(!std::sync::Arc::ptr_eq(&left, &right));
        assert!(std::sync::Arc::ptr_eq(&left, &left_again));
    }

    /// Live AppContainer guest proof for the named-pipe CONNECT bridge.
    ///
    /// Runs only on Windows. Green on Windows CI is the evidence behind
    /// `BackendCapabilities::mediated_http` on this platform. Guest opens via
    /// inherited `A3S_SANDBOX_MEDIATOR_PIPE_HANDLE` — name-open remains Access
    /// Denied under AppContainer even with package SID DACLs.
    #[tokio::test]
    async fn windows_appcontainer_named_pipe_connect_allow_deny_and_blocks_raw_egress() {
        use crate::network::ConnectMediator;
        use crate::policy::{BackendCapabilities, EnforcedPolicy, NetworkAllowRule, SandboxPolicy};
        use crate::CommandRequest;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        use tokio::sync::oneshot;

        let workspace = tempfile::tempdir().unwrap();
        let scratch = tempfile::tempdir().unwrap();
        let sandbox = PlatformSandbox::new(workspace.path()).unwrap();

        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let (hit_tx, hit_rx) = oneshot::channel::<()>();
        tokio::spawn(async move {
            let Ok((mut sock, _)) = upstream.accept().await else {
                return;
            };
            let mut buf = [0u8; 4];
            let _ = sock.read_exact(&mut buf).await;
            let _ = sock.write_all(b"pong").await;
            let _ = hit_tx.send(());
        });

        let mut document = SandboxPolicy::a3s_bash_baseline();
        document.features.mediated_network = true;
        document.network.allow.push(NetworkAllowRule {
            host: "127.0.0.1".into(),
            port: Some(upstream_addr.port()),
            path_prefix: None,
        });

        let pipe_name = format!(
            r"\\.\pipe\a3s-sandbox-live-{}-{}",
            std::process::id(),
            upstream_addr.port()
        );
        let (server, client) = sandbox
            .create_mediation_pipe(&pipe_name)
            .expect("connected mediation pipe pair");
        let mediator =
            ConnectMediator::bind_named_pipe_connected(document.clone(), pipe_name.clone(), server)
                .await
                .expect("connected CONNECT named-pipe mediator");

        let mut policy = EnforcedPolicy::compile(
            &SandboxPolicy::a3s_bash_baseline(),
            workspace.path(),
            scratch.path(),
            BackendCapabilities::native_gate2(),
        )
        .unwrap();
        policy.mediator_pipe_name = Some(pipe_name);

        let allow_script = format!(
            r#"
$ErrorActionPreference = 'Stop'
$raw = $env:A3S_SANDBOX_MEDIATOR_PIPE_HANDLE
if ([string]::IsNullOrEmpty($raw)) {{ throw 'missing A3S_SANDBOX_MEDIATOR_PIPE_HANDLE' }}
$safe = New-Object Microsoft.Win32.SafeHandles.SafePipeHandle([IntPtr][int64]$raw, $true)
$client = New-Object System.IO.Pipes.NamedPipeClientStream([System.IO.Pipes.PipeDirection]::InOut, $false, $true, $safe)
$req = [Text.Encoding]::ASCII.GetBytes("CONNECT 127.0.0.1:{port} HTTP/1.1`r`nHost: 127.0.0.1`r`n`r`n")
$client.Write($req, 0, $req.Length)
$hdr = New-Object byte[] 128
$n = $client.Read($hdr, 0, $hdr.Length)
$text = [Text.Encoding]::ASCII.GetString($hdr, 0, $n)
if ($text -notmatch '200') {{ throw "CONNECT allow failed: $text" }}
$ping = [Text.Encoding]::ASCII.GetBytes('ping')
$client.Write($ping, 0, $ping.Length)
$pong = New-Object byte[] 4
[void]$client.Read($pong, 0, 4)
[Console]::Out.Write([Text.Encoding]::ASCII.GetString($pong))
$client.Dispose()
"#,
            port = upstream_addr.port()
        );

        let allow = sandbox
            .execute_with_mediator_client(
                &policy,
                CommandRequest {
                    command: allow_script,
                    timeout_ms: 30_000,
                    output_observer: None,
                    env: None,
                },
                client,
            )
            .await
            .expect("allow execute");
        assert_eq!(
            allow.exit_code, 0,
            "allow stderr={} stdout={}",
            allow.stderr, allow.stdout
        );
        assert!(
            allow.stdout.contains("pong"),
            "allow stdout={}",
            allow.stdout
        );
        hit_rx
            .await
            .expect("allowed CONNECT must reach upstream once");
        mediator.shutdown().await;

        // Denied CONNECT must not reach a fresh upstream.
        let deny_upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let deny_port = deny_upstream.local_addr().unwrap().port();
        let deny_accept = tokio::spawn(async move {
            tokio::time::timeout(
                std::time::Duration::from_millis(400),
                deny_upstream.accept(),
            )
            .await
        });

        let deny_pipe = format!(
            r"\\.\pipe\a3s-sandbox-deny-{}-{}",
            std::process::id(),
            deny_port
        );
        let (deny_server, deny_client) = sandbox
            .create_mediation_pipe(&deny_pipe)
            .expect("deny mediation pipe pair");
        let deny_mediator =
            ConnectMediator::bind_named_pipe_connected(document, deny_pipe.clone(), deny_server)
                .await
                .expect("deny CONNECT mediator");
        policy.mediator_pipe_name = Some(deny_pipe);

        let deny_script = format!(
            r#"
$ErrorActionPreference = 'Stop'
$raw = $env:A3S_SANDBOX_MEDIATOR_PIPE_HANDLE
$safe = New-Object Microsoft.Win32.SafeHandles.SafePipeHandle([IntPtr][int64]$raw, $true)
$client = New-Object System.IO.Pipes.NamedPipeClientStream([System.IO.Pipes.PipeDirection]::InOut, $false, $true, $safe)
$req = [Text.Encoding]::ASCII.GetBytes("CONNECT 127.0.0.1:{port} HTTP/1.1`r`nHost: 127.0.0.1`r`n`r`n")
$client.Write($req, 0, $req.Length)
$hdr = New-Object byte[] 128
$n = $client.Read($hdr, 0, $hdr.Length)
$text = [Text.Encoding]::ASCII.GetString($hdr, 0, $n)
if ($text -match '200') {{ throw 'denied CONNECT unexpectedly succeeded' }}
[Console]::Out.Write('deny-ok')
$client.Dispose()
"#,
            port = deny_port
        );
        let deny = sandbox
            .execute_with_mediator_client(
                &policy,
                CommandRequest {
                    command: deny_script,
                    timeout_ms: 30_000,
                    output_observer: None,
                    env: None,
                },
                deny_client,
            )
            .await
            .expect("deny execute");
        assert_eq!(
            deny.exit_code, 0,
            "deny stderr={} stdout={}",
            deny.stderr, deny.stdout
        );
        assert!(
            deny.stdout.contains("deny-ok"),
            "deny stdout={}",
            deny.stdout
        );
        let deny_hit = deny_accept.await.unwrap();
        match deny_hit {
            Err(_) => {}
            Ok(Err(_)) => {}
            Ok(Ok(_)) => panic!("denied CONNECT must not reach upstream"),
        }
        deny_mediator.shutdown().await;

        // Raw TCP from the AppContainer guest must stay blocked (zero net caps).
        let egress_script = format!(
            r#"
$ErrorActionPreference = 'Stop'
try {{
  $c = New-Object System.Net.Sockets.TcpClient
  $c.Connect('127.0.0.1', {port})
  throw 'raw egress unexpectedly allowed'
}} catch {{
  if ($_.Exception.Message -match 'unexpectedly') {{ throw }}
  [Console]::Out.Write('egress-blocked')
}}
"#,
            port = upstream_addr.port()
        );
        let egress = sandbox
            .execute(
                &policy,
                CommandRequest {
                    command: egress_script,
                    timeout_ms: 30_000,
                    output_observer: None,
                    env: None,
                },
            )
            .await
            .expect("egress execute");
        assert_eq!(
            egress.exit_code, 0,
            "egress stderr={} stdout={}",
            egress.stderr, egress.stdout
        );
        assert!(
            egress.stdout.contains("egress-blocked"),
            "egress stdout={}",
            egress.stdout
        );
    }
}
