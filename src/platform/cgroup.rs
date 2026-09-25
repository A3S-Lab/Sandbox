//! Linux cgroup v2 resource enforcement (Gate 11).
//!
//! PIDs and memory quotas need a process-tree scope rlimits cannot express.
//! Where the host delegates a writable cgroup v2 subtree (systemd user
//! delegation, or root), each command runs inside a private cgroup with
//! `pids.max` / `memory.max` applied. Where delegation is unavailable the
//! probe fails closed and quota-bearing policies refuse at construction —
//! never a silent approximation with rlimits.

use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};

/// An exclusive, per-command cgroup under a delegated subtree.
#[derive(Debug)]
pub struct CgroupControl {
    dir: PathBuf,
}

impl CgroupControl {
    /// Probed base directory, if the host delegates a usable subtree.
    pub fn probe_delegated_base() -> Result<PathBuf> {
        let mount = cgroup2_mount_point().context("no writable cgroup v2 mount found")?;
        let uid = unsafe { libc::getuid() };
        let candidates = [
            format!(
                "{}/user.slice/user-{uid}.slice/user@{uid}.service",
                mount.display()
            ),
            mount.display().to_string(),
        ];
        let mut failures = Vec::new();
        for candidate in candidates {
            match probe_base(Path::new(&candidate)) {
                Ok(()) => return Ok(PathBuf::from(candidate)),
                Err(error) => failures.push(format!("{candidate}: {error}")),
            }
        }
        bail!(
            "no delegated cgroup v2 subtree available ({}); process quotas fail closed",
            failures.join("; ")
        )
    }

    /// Create a fresh cgroup for one command under `base`.
    pub fn create(base: &Path, name: &str) -> Result<Self> {
        let dir = base.join(format!("a3s-sandbox-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir)
            .with_context(|| format!("failed to create cgroup {}", dir.display()))?;
        Ok(Self { dir })
    }

    /// Cap the process tree at `max` concurrent tasks (`pids.max`).
    pub fn set_pids_max(&self, max: u32) -> Result<()> {
        write_control(&self.dir, "pids.max", &max.to_string())
    }

    /// Cap resident memory at `bytes` (`memory.max`); swap is pinned to zero
    /// where the kernel exposes it so the quota cannot be bypassed.
    pub fn set_memory_max(&self, bytes: u64) -> Result<()> {
        write_control(&self.dir, "memory.max", &bytes.to_string())?;
        match std::fs::write(self.dir.join("memory.swap.max"), "0") {
            Ok(()) => Ok(()),
            // Kernels or hosts without swap accounting: the memory.max cap
            // above still bounds resident use; refuse only on real errors.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error).context("failed to pin memory.swap.max to zero"),
        }
    }

    /// Move `pid` (and, by inheritance, its whole future tree) into this
    /// cgroup.
    pub fn attach(&self, pid: u32) -> Result<()> {
        write_control(&self.dir, "cgroup.procs", &pid.to_string())
    }

    /// Best-effort removal after the tree exited.
    pub fn cleanup(&self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }

    #[cfg(test)]
    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

impl Drop for CgroupControl {
    fn drop(&mut self) {
        self.cleanup();
    }
}

/// A probed delegated base that passed a real create/remove roundtrip.
#[cfg(test)]
pub struct DelegatedBase {
    base: PathBuf,
}

#[cfg(test)]
impl DelegatedBase {
    pub fn probe() -> Result<Self> {
        let base = CgroupControl::probe_delegated_base()?;
        // Enable the controllers we need top-down before creating children.
        enable_controllers(&base)?;
        Ok(Self { base })
    }

    pub fn create(&self, name: &str) -> Result<CgroupControl> {
        CgroupControl::create(&self.base, name)
    }
}

fn cgroup2_mount_point() -> Result<PathBuf> {
    let mountinfo = std::fs::read_to_string("/proc/self/mountinfo")
        .context("failed to read /proc/self/mountinfo")?;
    for line in mountinfo.lines() {
        // mountinfo: ID parent major:minor root mount-point ... - fstype ...
        if let Some(separator) = line.find(" - ") {
            let tail = &line[separator + 3..];
            if tail.split(' ').next() == Some("cgroup2") {
                let mount_point = line
                    .split(' ')
                    .nth(4)
                    .ok_or_else(|| anyhow::anyhow!("malformed mountinfo line: {line}"))?;
                // Escaped spaces (octal \040) are not expected for the
                // standard cgroup2 mount; refuse rather than misread.
                if mount_point.contains('\\') {
                    bail!("unexpected escaped path in cgroup2 mount: {mount_point}");
                }
                return Ok(PathBuf::from(mount_point));
            }
        }
    }
    bail!("cgroup2 is not mounted")
}

fn probe_base(base: &Path) -> Result<()> {
    if !base.is_dir() {
        bail!("not a directory");
    }
    let probe = base.join(format!("a3s-sandbox-probe-{}", std::process::id()));
    std::fs::create_dir(&probe).with_context(|| format!("cannot create {}", probe.display()))?;
    let _ = std::fs::remove_dir(&probe);
    Ok(())
}

/// Enable `+pids +memory` for children of `base` (top-down delegation rule).
pub(crate) fn enable_controllers(base: &Path) -> Result<()> {
    let subtree = base.join("cgroup.subtree_control");
    let current = std::fs::read_to_string(&subtree).unwrap_or_default();
    let enabled: Vec<&str> = current.split_whitespace().collect();
    let mut wanted = String::new();
    if !enabled.contains(&"pids") {
        wanted.push_str("+pids ");
    }
    if !enabled.contains(&"memory") {
        wanted.push_str("+memory");
    }
    let wanted = wanted.trim();
    if wanted.is_empty() {
        return Ok(());
    }
    std::fs::write(&subtree, wanted)
        .with_context(|| format!("failed to enable controllers in {}", subtree.display()))
}

fn write_control(dir: &Path, file: &str, value: &str) -> Result<()> {
    std::fs::write(dir.join(file), value)
        .with_context(|| format!("failed to write {file}={value} in {}", dir.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cgroup_mount_point_is_cgroup_v2_or_honest_failure() {
        match cgroup2_mount_point() {
            Ok(mount) => assert!(mount.is_dir(), "mount {mount:?} must exist"),
            Err(error) => assert!(
                error.to_string().contains("cgroup2"),
                "failure must explain the cgroup2 situation: {error}"
            ),
        }
    }

    #[test]
    fn delegated_base_probe_roundtrips_or_fails_closed_with_reason() {
        match DelegatedBase::probe() {
            Ok(base) => {
                // A real delegated subtree: create a control cgroup, apply a
                // pids cap, and read it back through the kernel.
                let control = base.create("gate11-probe").expect("create cgroup");
                control.set_pids_max(16).expect("pids.max");
                let read_back =
                    std::fs::read_to_string(control.dir().join("pids.max")).expect("read back");
                assert_eq!(read_back.trim(), "16");
                control.cleanup();
                assert!(!control.dir().exists(), "cleanup must remove the cgroup");
            }
            Err(error) => {
                let message = error.to_string();
                assert!(
                    message.contains("fail closed") || message.contains("cgroup v2"),
                    "unavailability must be explained honestly: {message}"
                );
            }
        }
    }

    #[test]
    fn memory_cap_roundtrips_when_delegated() {
        let Ok(base) = DelegatedBase::probe() else {
            return;
        };
        let control = base.create("gate11-memory").expect("create cgroup");
        control
            .set_memory_max(64 * 1024 * 1024)
            .expect("memory.max");
        let read_back =
            std::fs::read_to_string(control.dir().join("memory.max")).expect("read back");
        assert_eq!(read_back.trim(), (64 * 1024 * 1024).to_string());
        control.cleanup();
    }
}
