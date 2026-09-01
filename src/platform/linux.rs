//! Linux namespace, mount, and seccomp backend.

use crate::policy::{
    path_ancestors, requires_directory_placeholder, resolve_executable, SandboxPolicy,
};
use crate::process::run_tokio_command;
use crate::{CommandOutput, CommandRequest};
use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
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

    pub(crate) async fn execute(
        &self,
        policy: &SandboxPolicy,
        request: CommandRequest,
    ) -> Result<CommandOutput> {
        let _pins = WorkspacePins::acquire(policy)?;
        let seccomp = write_seccomp_filter(&policy.scratch)?;
        let mut command = Command::new(&self.bwrap);
        configure_base_arguments(&mut command, policy)?;
        configure_environment(&mut command, policy, request.env.as_deref())?;
        configure_seccomp_fd(&mut command, &seccomp)?;
        command
            .arg("--")
            .arg(&self.shell)
            .arg("-c")
            .arg(&request.command)
            .current_dir(&policy.workspace)
            .env_clear();

        run_tokio_command(command, request, "Linux native sandbox command").await
    }
}

fn configure_base_arguments(command: &mut Command, policy: &SandboxPolicy) -> Result<()> {
    command.args([
        "--die-with-parent",
        "--new-session",
        "--unshare-user",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-net",
        "--unshare-uts",
        "--unshare-cgroup-try",
        "--disable-userns",
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
    policy: &SandboxPolicy,
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

fn write_seccomp_filter(scratch: &Path) -> Result<File> {
    let instructions = seccomp_instructions()?;
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
    Ok(file)
}

fn seccomp_instructions() -> Result<Vec<SockFilter>> {
    const BPF_LD_W_ABS: u16 = 0x20;
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
    const LINK_SYSCALLS: &[u32] = &[86, 265];

    #[cfg(target_arch = "aarch64")]
    const AUDIT_ARCH: u32 = 0xc000_00b7;
    #[cfg(target_arch = "aarch64")]
    const SYS_SOCKET: u32 = 198;
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
        let errno = SECCOMP_RET_ERRNO | u32::try_from(libc::EPERM).unwrap_or(1);
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
        let blocked = [
            &[
                SYS_SOCKET,
                SYS_IO_URING_SETUP,
                SYS_IO_URING_ENTER,
                SYS_IO_URING_REGISTER,
            ][..],
            LINK_SYSCALLS,
        ]
        .concat();
        for (index, syscall) in blocked.iter().copied().enumerate() {
            let jump = u8::try_from(blocked.len() - index)
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
    fn acquire(policy: &SandboxPolicy) -> Result<Self> {
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

    #[test]
    fn seccomp_filter_checks_architecture_and_blocks_socket_families() {
        let filter = seccomp_instructions().unwrap();
        assert!(filter.len() >= 11);
        assert!(filter
            .iter()
            .any(|instruction| instruction.k == 41 || instruction.k == 198));
        assert!(filter
            .iter()
            .any(|instruction| matches!(instruction.k, 37 | 86 | 265)));
        assert!(filter
            .iter()
            .any(|instruction| instruction.k & 0xffff_0000 == 0x0005_0000));
    }

    #[test]
    fn workspace_pins_remove_only_the_sentinel_they_created() {
        let workspace = tempfile::tempdir().unwrap();
        let scratch = tempfile::tempdir().unwrap();
        let policy = SandboxPolicy::for_execution(workspace.path(), scratch.path()).unwrap();
        let protected = workspace.path().join(".git");
        assert!(!protected.exists());
        {
            let _pins = WorkspacePins::acquire(&policy).unwrap();
            assert!(protected.is_dir());
        }
        assert!(!protected.exists());
    }
}
