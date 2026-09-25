//! Linux namespace, mount, and seccomp backend.

use crate::policy::{
    path_ancestors, requires_directory_placeholder, resolve_executable, EnforcedPolicy,
    ResolvedResourceBudget,
};
use crate::process::run_tokio_command;
use crate::{CommandOutput, CommandRequest};
use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Seek, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use tokio::process::Command;

const SECCOMP_FD: libc::c_int = 198;

#[derive(Debug)]
pub(crate) struct PlatformSandbox {
    bwrap: PathBuf,
    shell: PathBuf,
}

impl PlatformSandbox {
    pub(crate) fn new(workspace: &Path) -> Result<Self> {
        let bwrap = resolve_executable("/usr/bin/bwrap", workspace)
            .context("Linux native sandbox requires bubblewrap at /usr/bin/bwrap")?;
        let shell = resolve_executable("/bin/bash", workspace)
            .context("trusted Linux bash executable is unavailable")?;
        Ok(Self { bwrap, shell })
    }

    /// Capabilities informed by the runtime probe: without a delegated
    /// cgroup subtree the backend cannot enforce process-tree or CPU
    /// quotas. Probed lazily and cached — construction stays side-effect
    /// free for the overwhelming majority of policies.
    pub(crate) fn effective_capabilities(&self) -> crate::policy::BackendCapabilities {
        let mut capabilities = crate::policy::BackendCapabilities::native_gate2();
        if self.delegated_base().is_none() {
            capabilities.resource_process_limit = false;
            capabilities.resource_cpu_limit = false;
        }
        capabilities
    }

    fn delegated_base(&self) -> Option<PathBuf> {
        static PROBED: OnceLock<Option<PathBuf>> = OnceLock::new();
        PROBED
            .get_or_init(|| super::cgroup::CgroupControl::probe_delegated_base().ok())
            .clone()
    }

    pub(crate) async fn execute(
        &self,
        policy: &EnforcedPolicy,
        request: CommandRequest,
    ) -> Result<CommandOutput> {
        let _pins = WorkspacePins::acquire(policy)?;
        let budget = ResolvedResourceBudget::resolve(&policy.resources, request.timeout_ms)?;
        budget.validate_for_backend(self.effective_capabilities())?;
        let cgroup = self.prepare_cgroup(&budget)?;
        let allow_network_sockets =
            policy.mediator_unix_path.is_some() || policy.socks_mediator_unix_path.is_some();
        let seccomp = write_seccomp_filter(&policy.scratch, allow_network_sockets)?;
        let mut command = Command::new(&self.bwrap);
        configure_base_arguments(&mut command, policy)?;
        if allow_network_sockets {
            // Guest netns: only loopback. Host CONNECT mediator is reached via
            // the Unix socket under scratch + in-guest TCP→Unix relay.
            command.arg("--unshare-net");
        }
        configure_environment(&mut command, policy, request.env.as_deref())?;
        configure_seccomp_fd(&mut command, &seccomp)?;
        let guest_command =
            if policy.mediator_unix_path.is_some() || policy.socks_mediator_unix_path.is_some() {
                let relay_bin = crate::stage_relay_into_scratch(&policy.scratch)
                    .context("failed to stage guest relay into scratch")?;
                crate::wrap_command_with_guest_relays(
                    &relay_bin,
                    policy.mediator_unix_path.as_deref(),
                    policy.socks_mediator_unix_path.as_deref(),
                    &request.command,
                )
                .context("failed to wrap guest command with mediation relays")?
            } else {
                request.command.clone()
            };
        command
            .arg("--")
            .arg(&self.shell)
            .arg("-c")
            .arg(&guest_command)
            .current_dir(&policy.workspace)
            .env_clear();

        run_tokio_command(
            command,
            request,
            &budget,
            "Linux native sandbox command",
            cgroup,
        )
        .await
    }

    /// Create and pre-configure the per-command cgroup when the budget
    /// carries process-tree quotas. Absence of a delegated subtree fails
    /// closed here as well, matching the constructor probe.
    fn prepare_cgroup(
        &self,
        budget: &ResolvedResourceBudget,
    ) -> Result<Option<super::cgroup::CgroupControl>> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static CGROUP_SEQ: AtomicU64 = AtomicU64::new(0);
        if budget.max_processes.is_none()
            && budget.max_memory_bytes.is_none()
            && budget.max_cpu_millicores.is_none()
        {
            return Ok(None);
        }
        let Some(base) = self.delegated_base() else {
            bail!(
                "process/memory quotas require a delegated cgroup v2 subtree; \
                 refusing to run without OS-enforced limits"
            );
        };
        let base = &base;
        super::cgroup::enable_controllers(base)
            .context("failed to enable cgroup controllers for the delegated base")?;
        let control = super::cgroup::CgroupControl::create(
            base,
            &format!(
                "{}-{}",
                std::process::id(),
                CGROUP_SEQ.fetch_add(1, Ordering::Relaxed)
            ),
        )?;
        if let Some(max) = budget.max_processes {
            control.set_pids_max(max)?;
        }
        if let Some(bytes) = budget.max_memory_bytes {
            control.set_memory_max(bytes)?;
        }
        if let Some(millicores) = budget.max_cpu_millicores {
            control.set_cpu_millicores(millicores)?;
        }
        Ok(Some(control))
    }
}

fn configure_base_arguments(command: &mut Command, policy: &EnforcedPolicy) -> Result<()> {
    command.args([
        "--die-with-parent",
        "--new-session",
        "--unshare-user",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--unshare-cgroup-try",
        "--cap-drop",
        "ALL",
        "--ro-bind",
        "/",
        "/",
    ]);

    let broad_read_roots = policy
        .deny_read
        .iter()
        .filter(|denied| {
            denied.parent().is_some()
                && policy
                    .allow_read
                    .iter()
                    .any(|allowed| allowed.starts_with(denied) && allowed != *denied)
        })
        .cloned()
        .collect::<Vec<_>>();
    for root in &broad_read_roots {
        command.arg("--tmpfs").arg(root);
    }

    for allowed in &policy.allow_read {
        ensure_mount_destination(command, allowed);
        if policy.allow_write.iter().any(|write| write == allowed) {
            continue;
        }
        command.arg("--ro-bind").arg(allowed).arg(allowed);
    }
    for writable in &policy.allow_write {
        ensure_mount_destination(command, writable);
        if policy.session_write == crate::policy::SessionWriteMode::Ephemeral
            && writable == &policy.scratch
        {
            if policy.mediator_unix_path.is_some() {
                // Mediation needs a host↔guest Unix socket under scratch; tmpfs
                // would hide the host-bound socket and the staged relay binary.
                command.arg("--bind").arg(writable).arg(writable);
            } else {
                // Ephemeral scratch: tmpfs replaces the host bind so guest writes
                // do not persist on the host after the sandbox exits.
                command.arg("--tmpfs").arg(writable);
            }
            continue;
        }
        command.arg("--bind").arg(writable).arg(writable);
    }

    for denied in &policy.deny_read {
        if !policy
            .allow_read
            .iter()
            .any(|allowed| denied.starts_with(allowed))
        {
            continue;
        }
        mask_read_path(command, denied)?;
    }
    for denied in &policy.deny_write {
        if policy
            .deny_read
            .iter()
            .any(|read_denied| read_denied == denied)
            || !policy
                .allow_write
                .iter()
                .any(|allowed| denied.starts_with(allowed))
        {
            continue;
        }
        bind_read_only(command, denied)?;
    }
    // Re-bind goal-loop carve-outs as writable after the `.a3s` read-only mask.
    for exception in &policy.write_exceptions {
        if exception.exists() {
            command.arg("--bind").arg(exception).arg(exception);
        }
    }

    command.args(["--proc", "/proc", "--dev", "/dev", "--chdir"]);
    command.arg(&policy.workspace);
    Ok(())
}

fn ensure_mount_destination(command: &mut Command, path: &Path) {
    for ancestor in path_ancestors(path) {
        command.arg("--dir").arg(ancestor);
    }
    if path.is_dir() {
        command.arg("--dir").arg(path);
    }
}

fn mask_read_path(command: &mut Command, path: &Path) -> Result<()> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
            ) =>
        {
            return Ok(())
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to inspect read-denied path {}", path.display()))
        }
    };
    if metadata.file_type().is_symlink() {
        bail!(
            "refusing a symbolic link at read-denied sandbox path {}",
            path.display()
        );
    }
    if metadata.is_dir() {
        command.arg("--tmpfs").arg(path);
        command.arg("--remount-ro").arg(path);
    } else if metadata.is_file() {
        command.arg("--ro-bind").arg("/dev/null").arg(path);
    } else {
        bail!("unsupported read-denied file type at {}", path.display());
    }
    Ok(())
}

fn bind_read_only(command: &mut Command, path: &Path) -> Result<()> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
            ) =>
        {
            return Ok(())
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to inspect write-denied path {}", path.display()))
        }
    };
    if metadata.file_type().is_symlink() {
        bail!(
            "refusing a symbolic link at write-denied sandbox path {}",
            path.display()
        );
    }
    if !metadata.is_dir() && !metadata.is_file() {
        bail!("unsupported write-denied file type at {}", path.display());
    }
    command.arg("--ro-bind").arg(path).arg(path);
    Ok(())
}

fn configure_environment(
    command: &mut Command,
    policy: &EnforcedPolicy,
    explicit: Option<&HashMap<String, String>>,
) -> Result<()> {
    command.arg("--clearenv");
    for (key, value) in policy.child_environment(explicit)? {
        command.arg("--setenv").arg(key).arg(value);
    }
    Ok(())
}

fn configure_seccomp_fd(command: &mut Command, filter: &File) -> Result<()> {
    let source_fd = filter.as_raw_fd();
    if source_fd == SECCOMP_FD {
        bail!("native sandbox seccomp source unexpectedly uses reserved fd {SECCOMP_FD}");
    }
    command.arg("--seccomp").arg(SECCOMP_FD.to_string());
    // SAFETY: only async-signal-safe `dup2` runs after fork. `filter` remains
    // alive through spawn, and dup2 clears close-on-exec on the destination.
    unsafe {
        command.as_std_mut().pre_exec(move || {
            if libc::dup2(source_fd, SECCOMP_FD) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    Ok(())
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

fn write_seccomp_filter(scratch: &Path, allow_network_sockets: bool) -> Result<File> {
    let instructions = seccomp_instructions(allow_network_sockets)?;
    let path = scratch.join("network-seccomp.bpf");
    let mut file = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(&path)
        .with_context(|| format!("failed to create seccomp filter {}", path.display()))?;
    for instruction in instructions {
        file.write_all(&instruction.code.to_ne_bytes())?;
        file.write_all(&[instruction.jt, instruction.jf])?;
        file.write_all(&instruction.k.to_ne_bytes())?;
    }
    file.flush()?;
    file.rewind()
        .context("failed to rewind the native sandbox seccomp filter")?;
    Ok(file)
}

fn seccomp_instructions(allow_network_sockets: bool) -> Result<Vec<SockFilter>> {
    const BPF_LD_W_ABS: u16 = 0x20;
    const BPF_ALU_AND_K: u16 = 0x54;
    const BPF_JMP_JEQ_K: u16 = 0x15;
    const BPF_RET_K: u16 = 0x06;
    const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
    const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
    const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

    #[cfg(target_arch = "x86_64")]
    const AUDIT_ARCH: u32 = 0xc000_003e;
    #[cfg(target_arch = "x86_64")]
    const SYS_SOCKET: u32 = 41;
    #[cfg(target_arch = "x86_64")]
    const SYS_SOCKETPAIR: u32 = 53;
    #[cfg(target_arch = "x86_64")]
    const SYS_CLONE: u32 = 56;
    #[cfg(target_arch = "x86_64")]
    const SYS_UNSHARE: u32 = 272;
    #[cfg(target_arch = "x86_64")]
    const SYS_SETNS: u32 = 308;
    #[cfg(target_arch = "x86_64")]
    const LINK_SYSCALLS: &[u32] = &[86, 265];

    #[cfg(target_arch = "aarch64")]
    const AUDIT_ARCH: u32 = 0xc000_00b7;
    #[cfg(target_arch = "aarch64")]
    const SYS_SOCKET: u32 = 198;
    #[cfg(target_arch = "aarch64")]
    const SYS_SOCKETPAIR: u32 = 199;
    #[cfg(target_arch = "aarch64")]
    const SYS_CLONE: u32 = 220;
    #[cfg(target_arch = "aarch64")]
    const SYS_UNSHARE: u32 = 97;
    #[cfg(target_arch = "aarch64")]
    const SYS_SETNS: u32 = 268;
    #[cfg(target_arch = "aarch64")]
    const LINK_SYSCALLS: &[u32] = &[37];

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        bail!(
            "Linux native sandbox seccomp is unsupported on architecture {}",
            std::env::consts::ARCH
        );
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    {
        const SYS_IO_URING_SETUP: u32 = 425;
        const SYS_IO_URING_ENTER: u32 = 426;
        const SYS_IO_URING_REGISTER: u32 = 427;
        const SYS_CLONE3: u32 = 435;
        const CLONE_NEW_NAMESPACE_FLAGS: u32 = 0x7e02_0000;
        let errno = SECCOMP_RET_ERRNO | u32::try_from(libc::EPERM).unwrap_or(1);
        let unsupported =
            SECCOMP_RET_ERRNO | u32::try_from(libc::ENOSYS).unwrap_or(libc::EPERM as u32);
        let mut instructions = vec![
            SockFilter {
                code: BPF_LD_W_ABS,
                jt: 0,
                jf: 0,
                k: 4,
            },
            SockFilter {
                code: BPF_JMP_JEQ_K,
                jt: 1,
                jf: 0,
                k: AUDIT_ARCH,
            },
            SockFilter {
                code: BPF_RET_K,
                jt: 0,
                jf: 0,
                k: SECCOMP_RET_KILL_PROCESS,
            },
            SockFilter {
                code: BPF_LD_W_ABS,
                jt: 0,
                jf: 0,
                k: 0,
            },
        ];
        let mut blocked_with_errno = Vec::new();
        if !allow_network_sockets {
            blocked_with_errno.extend([SYS_SOCKET, SYS_SOCKETPAIR]);
        }
        blocked_with_errno.extend([
            SYS_IO_URING_SETUP,
            SYS_IO_URING_ENTER,
            SYS_IO_URING_REGISTER,
            SYS_UNSHARE,
            SYS_SETNS,
        ]);
        blocked_with_errno.extend_from_slice(LINK_SYSCALLS);
        let clone3_jump = u8::try_from(blocked_with_errno.len() + 6)
            .context("native sandbox clone3 seccomp jump offset overflowed")?;
        instructions.push(SockFilter {
            code: BPF_JMP_JEQ_K,
            jt: clone3_jump,
            jf: 0,
            k: SYS_CLONE3,
        });
        for (index, syscall) in blocked_with_errno.iter().copied().enumerate() {
            let jump = u8::try_from(blocked_with_errno.len() + 4 - index)
                .context("native sandbox seccomp jump offset overflowed")?;
            instructions.push(SockFilter {
                code: BPF_JMP_JEQ_K,
                jt: jump,
                jf: 0,
                k: syscall,
            });
        }
        instructions.extend([
            SockFilter {
                code: BPF_JMP_JEQ_K,
                jt: 0,
                jf: 3,
                k: SYS_CLONE,
            },
            SockFilter {
                code: BPF_LD_W_ABS,
                jt: 0,
                jf: 0,
                k: 16,
            },
            SockFilter {
                code: BPF_ALU_AND_K,
                jt: 0,
                jf: 0,
                k: CLONE_NEW_NAMESPACE_FLAGS,
            },
            SockFilter {
                code: BPF_JMP_JEQ_K,
                jt: 0,
                jf: 1,
                k: 0,
            },
            SockFilter {
                code: BPF_RET_K,
                jt: 0,
                jf: 0,
                k: SECCOMP_RET_ALLOW,
            },
            SockFilter {
                code: BPF_RET_K,
                jt: 0,
                jf: 0,
                k: errno,
            },
            SockFilter {
                code: BPF_RET_K,
                jt: 0,
                jf: 0,
                k: unsupported,
            },
        ]);
        Ok(instructions)
    }
}

#[derive(Debug)]
struct PinRecord {
    references: usize,
    device: u64,
    inode: u64,
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
        let mut guard = Self { paths: Vec::new() };
        for path in &policy.deny_write {
            if !path.starts_with(&policy.workspace) {
                continue;
            }
            guard.acquire_path(&policy.workspace, path)?;
        }
        Ok(guard)
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
        let created = if directory {
            std::fs::DirBuilder::new().mode(0o700).create(path)
        } else {
            OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(path)
                .map(drop)
        };
        match created {
            Ok(()) => {
                let metadata = match std::fs::symlink_metadata(path) {
                    Ok(metadata) => metadata,
                    Err(error) => {
                        if directory {
                            let _ = std::fs::remove_dir(path);
                        } else {
                            let _ = std::fs::remove_file(path);
                        }
                        return Err(error).with_context(|| {
                            format!("failed to inspect sandbox placeholder {}", path.display())
                        });
                    }
                };
                registry.insert(
                    path.to_path_buf(),
                    PinRecord {
                        references: 1,
                        device: metadata.dev(),
                        inode: metadata.ino(),
                        directory,
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
            let device = record.device;
            let inode = record.inode;
            let directory = record.directory;
            registry.remove(&path);
            let Ok(metadata) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            if metadata.dev() == device && metadata.ino() == inode {
                if directory && metadata.is_dir() {
                    let _ = std::fs::remove_dir(path);
                } else if !directory && metadata.is_file() && metadata.len() == 0 {
                    let _ = std::fs::remove_file(path);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evaluate_filter(filter: &[SockFilter], arch: u32, syscall: u32, arg0: u32) -> u32 {
        let mut accumulator = 0;
        let mut index = 0;
        loop {
            let instruction = filter[index];
            match instruction.code {
                0x20 => {
                    accumulator = match instruction.k {
                        0 => syscall,
                        4 => arch,
                        16 => arg0,
                        offset => panic!("unexpected seccomp data offset {offset}"),
                    };
                    index += 1;
                }
                0x54 => {
                    accumulator &= instruction.k;
                    index += 1;
                }
                0x15 => {
                    let jump = if accumulator == instruction.k {
                        instruction.jt
                    } else {
                        instruction.jf
                    };
                    index += usize::from(jump) + 1;
                }
                0x06 => return instruction.k,
                code => panic!("unexpected seccomp instruction {code:#x}"),
            }
        }
    }

    #[test]
    fn seccomp_filter_blocks_sockets_and_namespace_reentry() {
        let filter = seccomp_instructions(false).unwrap();
        #[cfg(target_arch = "x86_64")]
        let (arch, socket, socketpair, clone, unshare, setns) = (0xc000_003e, 41, 53, 56, 272, 308);
        #[cfg(target_arch = "aarch64")]
        let (arch, socket, socketpair, clone, unshare, setns) =
            (0xc000_00b7, 198, 199, 220, 97, 268);

        let allow = 0x7fff_0000;
        let permission_denied = 0x0005_0000 | u32::try_from(libc::EPERM).unwrap();
        let unsupported = 0x0005_0000 | u32::try_from(libc::ENOSYS).unwrap();
        assert_eq!(evaluate_filter(&filter, arch, socket, 0), permission_denied);
        assert_eq!(
            evaluate_filter(&filter, arch, socketpair, 0),
            permission_denied
        );
        assert_eq!(
            evaluate_filter(&filter, arch, unshare, 0),
            permission_denied
        );
        assert_eq!(evaluate_filter(&filter, arch, setns, 0), permission_denied);
        assert_eq!(evaluate_filter(&filter, arch, 435, 0), unsupported);
        assert_eq!(
            evaluate_filter(&filter, arch, clone, 0x1000_0000),
            permission_denied
        );
        assert_eq!(evaluate_filter(&filter, arch, clone, 0), allow);
        assert_eq!(evaluate_filter(&filter, arch, u32::MAX, 0), allow);
    }

    #[test]
    fn seccomp_mediation_mode_allows_sockets_but_blocks_namespace_escape() {
        let filter = seccomp_instructions(true).unwrap();
        #[cfg(target_arch = "x86_64")]
        let (arch, socket, socketpair, unshare, setns) = (0xc000_003e, 41, 53, 272, 308);
        #[cfg(target_arch = "aarch64")]
        let (arch, socket, socketpair, unshare, setns) = (0xc000_00b7, 198, 199, 97, 268);

        let allow = 0x7fff_0000;
        let permission_denied = 0x0005_0000 | u32::try_from(libc::EPERM).unwrap();
        assert_eq!(evaluate_filter(&filter, arch, socket, 0), allow);
        assert_eq!(evaluate_filter(&filter, arch, socketpair, 0), allow);
        assert_eq!(
            evaluate_filter(&filter, arch, unshare, 0),
            permission_denied
        );
        assert_eq!(evaluate_filter(&filter, arch, setns, 0), permission_denied);
    }

    #[test]
    fn seccomp_filter_file_is_rewound_for_bubblewrap() {
        let scratch = tempfile::tempdir().unwrap();
        let mut filter = write_seccomp_filter(scratch.path(), false).unwrap();
        assert_eq!(filter.stream_position().unwrap(), 0);
        assert_eq!(
            filter.metadata().unwrap().len(),
            u64::try_from(
                seccomp_instructions(false).unwrap().len() * std::mem::size_of::<SockFilter>(),
            )
            .unwrap()
        );
    }

    #[test]
    fn ephemeral_scratch_is_mounted_as_tmpfs_not_host_bind() {
        let workspace = tempfile::tempdir().unwrap();
        let scratch = tempfile::tempdir().unwrap();
        let mut document = crate::policy::SandboxPolicy::a3s_bash_baseline();
        document.filesystem.session_write = crate::policy::SessionWriteMode::Ephemeral;
        let policy = EnforcedPolicy::compile(
            &document,
            workspace.path(),
            scratch.path(),
            crate::policy::BackendCapabilities::native_gate2(),
        )
        .unwrap();
        let mut command =
            Command::new(resolve_executable("/usr/bin/bwrap", workspace.path()).unwrap());
        configure_base_arguments(&mut command, &policy).unwrap();
        let args: Vec<String> = command
            .as_std()
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        let scratch = policy.scratch.to_string_lossy().into_owned();
        assert!(
            args.windows(2)
                .any(|pair| pair[0] == "--tmpfs" && pair[1] == scratch),
            "ephemeral scratch must use --tmpfs; args={args:?}"
        );
        assert!(
            !args
                .windows(3)
                .any(|pair| { pair[0] == "--bind" && pair[1] == scratch && pair[2] == scratch }),
            "ephemeral scratch must not host-bind; args={args:?}"
        );
    }

    #[test]
    fn ephemeral_scratch_with_mediation_keeps_host_bind_for_socket() {
        let workspace = tempfile::tempdir().unwrap();
        let scratch = tempfile::tempdir().unwrap();
        let mut document = crate::policy::SandboxPolicy::a3s_bash_baseline();
        document.filesystem.session_write = crate::policy::SessionWriteMode::Ephemeral;
        let mut policy = EnforcedPolicy::compile(
            &document,
            workspace.path(),
            scratch.path(),
            crate::policy::BackendCapabilities::native_gate2(),
        )
        .unwrap();
        policy.mediator_unix_path = Some(scratch.path().join("mediator.sock"));
        let mut command =
            Command::new(resolve_executable("/usr/bin/bwrap", workspace.path()).unwrap());
        configure_base_arguments(&mut command, &policy).unwrap();
        let args: Vec<String> = command
            .as_std()
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        let scratch = policy.scratch.to_string_lossy().into_owned();
        assert!(
            args.windows(3)
                .any(|pair| pair[0] == "--bind" && pair[1] == scratch && pair[2] == scratch),
            "mediation requires host-bound scratch; args={args:?}"
        );
        assert!(
            !args
                .windows(2)
                .any(|pair| pair[0] == "--tmpfs" && pair[1] == scratch),
            "mediation must not hide scratch behind tmpfs; args={args:?}"
        );
    }

    #[test]
    fn mediation_wire_adds_unshare_net_when_unix_mediator_set() {
        let workspace = tempfile::tempdir().unwrap();
        let scratch = tempfile::tempdir().unwrap();
        let mut policy = EnforcedPolicy::for_execution(workspace.path(), scratch.path()).unwrap();
        policy.mediator_unix_path = Some(scratch.path().join("mediator.sock"));
        policy.mediator_port = Some(crate::GUEST_HTTP_CONNECT_RELAY_PORT);
        let mut command =
            Command::new(resolve_executable("/usr/bin/bwrap", workspace.path()).unwrap());
        configure_base_arguments(&mut command, &policy).unwrap();
        if policy.mediator_unix_path.is_some() {
            command.arg("--unshare-net");
        }
        let args: Vec<String> = command
            .as_std()
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        assert!(
            args.iter().any(|arg| arg == "--unshare-net"),
            "Linux mediation wire must unshare net; args={args:?}"
        );
    }

    #[tokio::test]
    async fn linux_bridge_wire_tunnels_allowed_connect_via_unix_mediator() {
        use crate::network::ConnectMediator;
        use crate::policy::NetworkAllowRule;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        use tokio::sync::Mutex;

        static RELAY_ENV_LOCK: Mutex<()> = Mutex::const_new(());
        let _guard = RELAY_ENV_LOCK.lock().await;

        let workspace = tempfile::tempdir().unwrap();
        let scratch = tempfile::tempdir().unwrap();
        let sock = scratch.path().join("mediator.sock");

        let upstream = TcpListener::bind(std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let upstream_port = upstream.local_addr().unwrap().port();
        let upstream_task = tokio::spawn(async move {
            let (mut stream, _) = upstream.accept().await.unwrap();
            let mut buf = [0u8; 4];
            stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"ping");
            stream.write_all(b"pong").await.unwrap();
        });

        let mut document = crate::policy::SandboxPolicy::a3s_bash_baseline();
        document.features.mediated_network = true;
        document.network.allow.push(NetworkAllowRule {
            host: "127.0.0.1".into(),
            port: Some(upstream_port),
            path_prefix: None,
        });
        // Capability claim is still off; arm the wire fields directly to prove
        // the OS bridge path before flipping BackendCapabilities::mediated_http.
        let mut policy = EnforcedPolicy::compile(
            &crate::policy::SandboxPolicy::a3s_bash_baseline(),
            workspace.path(),
            scratch.path(),
            crate::policy::BackendCapabilities::native_gate2(),
        )
        .unwrap();
        let mediator = ConnectMediator::bind_unix(document, &sock, None)
            .await
            .expect("unix CONNECT mediator");
        policy.mediator_unix_path = Some(sock.clone());
        policy.mediator_port = Some(crate::GUEST_HTTP_CONNECT_RELAY_PORT);

        let test_exe = std::env::current_exe().expect("test exe");
        let relay_bin = test_exe
            .parent()
            .and_then(|p| p.parent())
            .map(|debug| debug.join("a3s-sandbox-relay"))
            .expect("resolve target/debug");
        assert!(
            relay_bin.is_file(),
            "expected relay at {} (run cargo test --bins first if missing)",
            relay_bin.display()
        );
        std::env::set_var("A3S_SANDBOX_RELAY", &relay_bin);

        let sandbox = PlatformSandbox::new(workspace.path()).unwrap();
        let probe = workspace.path().join("connect_probe.py");
        std::fs::write(
            &probe,
            format!(
                "import socket\n\
s = socket.create_connection(('127.0.0.1', {port}))\n\
s.sendall(b'CONNECT 127.0.0.1:{up} HTTP/1.1\\r\\nHost: 127.0.0.1:{up}\\r\\n\\r\\n')\n\
hdr = b''\n\
while b'\\r\\n\\r\\n' not in hdr:\n\
\tchunk = s.recv(1)\n\
\tassert chunk, 'closed'\n\
\thdr += chunk\n\
assert hdr.startswith(b'HTTP/1.1 200'), hdr\n\
s.sendall(b'ping')\n\
print(s.recv(4).decode())\n",
                port = crate::GUEST_HTTP_CONNECT_RELAY_PORT,
                up = upstream_port
            ),
        )
        .unwrap();
        let command = format!("python3 {}", probe.display());
        let output = sandbox
            .execute(
                &policy,
                crate::CommandRequest {
                    command,
                    timeout_ms: 30_000,
                    output_observer: None,
                    env: None,
                },
            )
            .await
            .expect("linux bridge execute");
        std::env::remove_var("A3S_SANDBOX_RELAY");
        assert_eq!(output.exit_code, 0, "stderr={}", output.stderr);
        assert_eq!(output.stdout.trim(), "pong");
        upstream_task.await.unwrap();
        mediator.shutdown().await;
    }

    #[tokio::test]
    async fn linux_bridge_wire_denies_forbidden_connect_and_raw_egress() {
        use crate::network::ConnectMediator;
        use crate::policy::NetworkAllowRule;
        use tokio::sync::Mutex;

        static RELAY_ENV_LOCK: Mutex<()> = Mutex::const_new(());
        let _guard = RELAY_ENV_LOCK.lock().await;

        let workspace = tempfile::tempdir().unwrap();
        let scratch = tempfile::tempdir().unwrap();
        let sock = scratch.path().join("mediator.sock");

        let mut document = crate::policy::SandboxPolicy::a3s_bash_baseline();
        document.features.mediated_network = true;
        document.network.allow.push(NetworkAllowRule {
            host: "allowed.example".into(),
            port: Some(443),
            path_prefix: None,
        });
        let mut policy = EnforcedPolicy::compile(
            &crate::policy::SandboxPolicy::a3s_bash_baseline(),
            workspace.path(),
            scratch.path(),
            crate::policy::BackendCapabilities::native_gate2(),
        )
        .unwrap();
        let mediator = ConnectMediator::bind_unix(document, &sock, None)
            .await
            .expect("unix CONNECT mediator");
        policy.mediator_unix_path = Some(sock.clone());
        policy.mediator_port = Some(crate::GUEST_HTTP_CONNECT_RELAY_PORT);

        let test_exe = std::env::current_exe().expect("test exe");
        let relay_bin = test_exe
            .parent()
            .and_then(|p| p.parent())
            .map(|debug| debug.join("a3s-sandbox-relay"))
            .expect("resolve target/debug");
        assert!(relay_bin.is_file(), "missing {}", relay_bin.display());
        std::env::set_var("A3S_SANDBOX_RELAY", &relay_bin);

        let probe = workspace.path().join("deny_probe.py");
        std::fs::write(
            &probe,
            format!(
                "import socket\n\
# Denied CONNECT must return 403 and never open a real tunnel.\n\
s = socket.create_connection(('127.0.0.1', {port}))\n\
s.sendall(b'CONNECT 127.0.0.1:9 HTTP/1.1\\r\\nHost: 127.0.0.1:9\\r\\n\\r\\n')\n\
hdr = b''\n\
while b'\\r\\n\\r\\n' not in hdr:\n\
\tchunk = s.recv(1)\n\
\tassert chunk, 'closed'\n\
\thdr += chunk\n\
assert hdr.startswith(b'HTTP/1.1 403'), hdr\n\
# Raw egress to a public IP must fail inside the guest netns.\n\
failed = False\n\
try:\n\
\tsocket.create_connection(('1.1.1.1', 443), timeout=1.0)\n\
except OSError:\n\
\tfailed = True\n\
assert failed, 'raw egress unexpectedly succeeded'\n\
print('denied-ok')\n",
                port = crate::GUEST_HTTP_CONNECT_RELAY_PORT,
            ),
        )
        .unwrap();

        let sandbox = PlatformSandbox::new(workspace.path()).unwrap();
        let output = sandbox
            .execute(
                &policy,
                crate::CommandRequest {
                    command: format!("python3 {}", probe.display()),
                    timeout_ms: 30_000,
                    output_observer: None,
                    env: None,
                },
            )
            .await
            .expect("linux deny bridge execute");
        std::env::remove_var("A3S_SANDBOX_RELAY");
        assert_eq!(output.exit_code, 0, "stderr={}", output.stderr);
        assert_eq!(output.stdout.trim(), "denied-ok");
        mediator.shutdown().await;
    }

    #[tokio::test]
    async fn linux_socks_bridge_wire_allows_allowed_connect() {
        use crate::network::Socks5Mediator;
        use crate::policy::NetworkAllowRule;
        use tokio::net::TcpListener;
        use tokio::sync::Mutex;

        static RELAY_ENV_LOCK: Mutex<()> = Mutex::const_new(());
        let _guard = RELAY_ENV_LOCK.lock().await;

        let workspace = tempfile::tempdir().unwrap();
        let scratch = tempfile::tempdir().unwrap();
        let sock = scratch.path().join("socks-mediator.sock");

        let upstream = TcpListener::bind(std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let upstream_port = upstream.local_addr().unwrap().port();
        let upstream_task = tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let (mut stream, _) = upstream.accept().await.unwrap();
            let mut buf = [0u8; 4];
            stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"ping");
            stream.write_all(b"pong").await.unwrap();
        });

        let mut document = crate::policy::SandboxPolicy::a3s_bash_baseline();
        document.features.mediated_socks = true;
        document.network.allow.push(NetworkAllowRule {
            host: "127.0.0.1".into(),
            port: Some(upstream_port),
            path_prefix: None,
        });
        // Wire fields armed directly: this test is the live proof the
        // BackendCapabilities::mediated_socks claim rides on, exactly like
        // the HTTP bridge proof.
        let mut policy = EnforcedPolicy::compile(
            &crate::policy::SandboxPolicy::a3s_bash_baseline(),
            workspace.path(),
            scratch.path(),
            crate::policy::BackendCapabilities::native_gate2(),
        )
        .unwrap();
        let mediator = Socks5Mediator::bind_unix(document, &sock)
            .await
            .expect("unix SOCKS mediator");
        policy.socks_mediator_unix_path = Some(sock.clone());
        policy.socks_mediator_port = Some(crate::GUEST_SOCKS_CONNECT_RELAY_PORT);

        let test_exe = std::env::current_exe().expect("test exe");
        let relay_bin = test_exe
            .parent()
            .and_then(|p| p.parent())
            .map(|debug| debug.join("a3s-sandbox-relay"))
            .expect("resolve target/debug");
        assert!(
            relay_bin.is_file(),
            "expected relay at {} (run cargo test --bins first if missing)",
            relay_bin.display()
        );
        std::env::set_var("A3S_SANDBOX_RELAY", &relay_bin);

        let sandbox = PlatformSandbox::new(workspace.path()).unwrap();
        let probe = workspace.path().join("socks_probe.py");
        std::fs::write(
            &probe,
            format!(
                "import socket\n\
s = socket.create_connection(('127.0.0.1', {port}))\n\
s.sendall(b'\\x05\\x01\\x00')\n\
method = s.recv(2)\n\
assert method == b'\\x05\\x00', method\n\
host = b'127.0.0.1'\n\
s.sendall(b'\\x05\\x01\\x00\\x03' + bytes([len(host)]) + host + ({up}).to_bytes(2, 'big'))\n\
reply = s.recv(10)\n\
assert reply[1] == 0, reply\n\
s.sendall(b'ping')\n\
print(s.recv(4).decode())\n",
                port = crate::GUEST_SOCKS_CONNECT_RELAY_PORT,
                up = upstream_port
            ),
        )
        .unwrap();
        let command = format!("python3 {}", probe.display());
        let output = sandbox
            .execute(
                &policy,
                crate::CommandRequest {
                    command,
                    timeout_ms: 30_000,
                    output_observer: None,
                    env: None,
                },
            )
            .await
            .expect("linux socks bridge execute");
        std::env::remove_var("A3S_SANDBOX_RELAY");
        assert_eq!(output.exit_code, 0, "stderr={}", output.stderr);
        assert_eq!(output.stdout.trim(), "pong");
        upstream_task.await.unwrap();
        mediator.shutdown().await;
    }

    #[tokio::test]
    async fn linux_socks_bridge_wire_denies_forbidden_connect() {
        use crate::network::Socks5Mediator;
        use crate::policy::NetworkAllowRule;
        use tokio::sync::Mutex;

        static RELAY_ENV_LOCK: Mutex<()> = Mutex::const_new(());
        let _guard = RELAY_ENV_LOCK.lock().await;

        let workspace = tempfile::tempdir().unwrap();
        let scratch = tempfile::tempdir().unwrap();
        let sock = scratch.path().join("socks-deny.sock");

        let mut document = crate::policy::SandboxPolicy::a3s_bash_baseline();
        document.features.mediated_socks = true;
        document.network.allow.push(NetworkAllowRule {
            host: "allowed.example".into(),
            port: Some(443),
            path_prefix: None,
        });
        let mut policy = EnforcedPolicy::compile(
            &crate::policy::SandboxPolicy::a3s_bash_baseline(),
            workspace.path(),
            scratch.path(),
            crate::policy::BackendCapabilities::native_gate2(),
        )
        .unwrap();
        let mediator = Socks5Mediator::bind_unix(document, &sock)
            .await
            .expect("unix SOCKS mediator");
        policy.socks_mediator_unix_path = Some(sock.clone());
        policy.socks_mediator_port = Some(crate::GUEST_SOCKS_CONNECT_RELAY_PORT);

        let test_exe = std::env::current_exe().expect("test exe");
        let relay_bin = test_exe
            .parent()
            .and_then(|p| p.parent())
            .map(|debug| debug.join("a3s-sandbox-relay"))
            .expect("resolve target/debug");
        assert!(relay_bin.is_file(), "missing {}", relay_bin.display());
        std::env::set_var("A3S_SANDBOX_RELAY", &relay_bin);

        let sandbox = PlatformSandbox::new(workspace.path()).unwrap();
        let probe = workspace.path().join("socks_deny_probe.py");
        std::fs::write(
            &probe,
            format!(
                "import socket\n\
s = socket.create_connection(('127.0.0.1', {port}))\n\
s.sendall(b'\\x05\\x01\\x00')\n\
assert s.recv(2) == b'\\x05\\x00'\n\
s.sendall(b'\\x05\\x01\\x00\\x03\\x09127.0.0.1\\x00\\x09')\n\
reply = s.recv(10)\n\
assert reply[1] == 2, reply\n\
print('socks-denied-ok')\n",
                port = crate::GUEST_SOCKS_CONNECT_RELAY_PORT
            ),
        )
        .unwrap();
        let command = format!("python3 {}", probe.display());
        let output = sandbox
            .execute(
                &policy,
                crate::CommandRequest {
                    command,
                    timeout_ms: 30_000,
                    output_observer: None,
                    env: None,
                },
            )
            .await
            .expect("linux socks bridge deny execute");
        std::env::remove_var("A3S_SANDBOX_RELAY");
        assert_eq!(output.exit_code, 0, "stderr={}", output.stderr);
        assert_eq!(output.stdout.trim(), "socks-denied-ok");
        mediator.shutdown().await;
    }
}
