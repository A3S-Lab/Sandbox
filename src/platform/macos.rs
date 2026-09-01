//! macOS Seatbelt backend.

use crate::policy::{path_ancestors, resolve_executable, SandboxPolicy};
use crate::process::run_tokio_command;
use crate::{CommandOutput, CommandRequest};
use anyhow::{bail, Context, Result};
use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use tokio::process::Command;

const MAX_SBPL_STRING_BYTES: usize = 1_024;

#[derive(Debug)]
pub(crate) struct PlatformSandbox {
    sandbox_exec: PathBuf,
    env: PathBuf,
    shell: PathBuf,
}

impl PlatformSandbox {
    pub(crate) fn new(workspace: &Path) -> Result<Self> {
        Ok(Self {
            sandbox_exec: resolve_executable("/usr/bin/sandbox-exec", workspace)
                .context("macOS Seatbelt launcher is unavailable")?,
            env: resolve_executable("/usr/bin/env", workspace)
                .context("trusted macOS environment launcher is unavailable")?,
            shell: resolve_executable("/bin/bash", workspace)
                .context("trusted macOS bash executable is unavailable")?,
        })
    }

    pub(crate) async fn execute(
        &self,
        policy: &SandboxPolicy,
        request: CommandRequest,
    ) -> Result<CommandOutput> {
        let profile = compile_profile(policy)?;
        let profile_path = policy.scratch.join("seatbelt.sb");
        tokio::fs::write(&profile_path, profile)
            .await
            .with_context(|| {
                format!(
                    "failed to write Seatbelt profile {}",
                    profile_path.display()
                )
            })?;

        let environment = policy.child_environment(request.env.as_deref())?;
        let mut command = Command::new(&self.sandbox_exec);
        command
            .arg("-f")
            .arg(&profile_path)
            .arg(&self.env)
            .arg("-i");
        for (key, value) in environment {
            command.arg(environment_assignment(&key, &value));
        }
        command
            .arg(&self.shell)
            .arg("-c")
            .arg(&request.command)
            .current_dir(&policy.workspace)
            .env_clear();

        run_tokio_command(command, request, "macOS native sandbox command").await
    }
}

fn environment_assignment(key: &OsStr, value: &OsStr) -> OsString {
    let mut assignment = key.to_os_string();
    assignment.push("=");
    assignment.push(value);
    assignment
}

fn compile_profile(policy: &SandboxPolicy) -> Result<String> {
    let mut lines = vec![
        "(version 1)".to_string(),
        "(deny default)".to_string(),
        "(deny file-link)".to_string(),
        "".to_string(),
        "; Process lifecycle".to_string(),
        "(allow process-exec)".to_string(),
        "(allow process-fork)".to_string(),
        "(allow process-info* (target same-sandbox))".to_string(),
        "(allow signal (target same-sandbox))".to_string(),
        "(allow mach-priv-task-port (target same-sandbox))".to_string(),
        "".to_string(),
        "; Minimal system services required by command-line tools".to_string(),
        "(allow user-preference-read)".to_string(),
        "(allow mach-lookup".to_string(),
        "  (global-name \"com.apple.audio.systemsoundserver\")".to_string(),
        "  (global-name \"com.apple.bsd.dirhelper\")".to_string(),
        "  (global-name \"com.apple.cfprefsd.agent\")".to_string(),
        "  (global-name \"com.apple.distributed_notifications@Uv3\")".to_string(),
        "  (global-name \"com.apple.FontObjectsServer\")".to_string(),
        "  (global-name \"com.apple.fonts\")".to_string(),
        "  (global-name \"com.apple.logd\")".to_string(),
        "  (global-name \"com.apple.lsd.mapdb\")".to_string(),
        "  (global-name \"com.apple.PowerManagement.control\")".to_string(),
        "  (global-name \"com.apple.securityd.xpc\")".to_string(),
        "  (global-name \"com.apple.system.DirectoryService.libinfo_v1\")".to_string(),
        "  (global-name \"com.apple.system.logger\")".to_string(),
        "  (global-name \"com.apple.system.notification_center\")".to_string(),
        "  (global-name \"com.apple.system.opendirectoryd.libinfo\")".to_string(),
        "  (global-name \"com.apple.system.opendirectoryd.membership\")".to_string(),
        ")".to_string(),
        "(allow ipc-posix-shm)".to_string(),
        "(allow ipc-posix-sem)".to_string(),
        "(allow iokit-get-properties)".to_string(),
        "(allow iokit-open".to_string(),
        "  (iokit-registry-entry-class \"IOSurfaceRootUserClient\")".to_string(),
        "  (iokit-registry-entry-class \"RootDomainUserClient\")".to_string(),
        "  (iokit-user-client-class \"IOSurfaceSendRight\")".to_string(),
        ")".to_string(),
        "(allow system-socket (require-all (socket-domain AF_SYSTEM) (socket-protocol 2)))"
            .to_string(),
        "(allow sysctl-read)".to_string(),
        "(allow distributed-notification-post)".to_string(),
        "".to_string(),
        "; Inherited descriptors and safe devices".to_string(),
        "(allow file-read-data file-write-data (subpath \"/dev/fd\"))".to_string(),
        "(allow file-read* file-write-data file-ioctl".to_string(),
        "  (literal \"/dev/null\")".to_string(),
        "  (literal \"/dev/zero\")".to_string(),
        "  (literal \"/dev/random\")".to_string(),
        "  (literal \"/dev/urandom\")".to_string(),
        ")".to_string(),
        "".to_string(),
        "; Network and Unix-domain sockets remain denied by default".to_string(),
        "".to_string(),
        "; Filesystem reads".to_string(),
        "(allow file-read*)".to_string(),
    ];

    push_path_rule(&mut lines, "deny", &["file-read*"], &policy.deny_read)?;
    push_path_rule(&mut lines, "allow", &["file-read*"], &policy.allow_read)?;

    let late_read_denies = policy
        .deny_read
        .iter()
        .filter(|denied| {
            policy
                .allow_read
                .iter()
                .any(|allowed| denied.starts_with(allowed))
        })
        .cloned()
        .collect::<Vec<_>>();
    push_path_rule(&mut lines, "deny", &["file-read*"], &late_read_denies)?;
    if !policy.deny_read.is_empty() {
        lines.push("(allow file-read-metadata (vnode-type DIRECTORY))".to_string());
    }

    lines.push(String::new());
    lines.push("; Filesystem writes".to_string());
    push_path_rule(&mut lines, "allow", &["file-write*"], &policy.allow_write)?;
    push_path_rule(&mut lines, "deny", &["file-write*"], &policy.deny_write)?;

    let mut pinned = BTreeSet::new();
    for path in &policy.deny_write {
        pinned.insert(path.clone());
        pinned.extend(path_ancestors(path));
    }
    push_literal_rule(
        &mut lines,
        "deny",
        &["file-write-unlink", "file-write-create"],
        pinned,
    )?;

    Ok(lines.join("\n"))
}

fn push_path_rule(
    lines: &mut Vec<String>,
    action: &str,
    operations: &[&str],
    paths: &[PathBuf],
) -> Result<()> {
    if paths.is_empty() {
        return Ok(());
    }
    lines.push(format!("({action} {}", operations.join(" ")));
    for path in paths {
        lines.push(format!("  (subpath {})", escaped_path(path)?));
    }
    lines.push(")".to_string());
    Ok(())
}

fn push_literal_rule(
    lines: &mut Vec<String>,
    action: &str,
    operations: &[&str],
    paths: impl IntoIterator<Item = PathBuf>,
) -> Result<()> {
    let paths = paths.into_iter().collect::<Vec<_>>();
    if paths.is_empty() {
        return Ok(());
    }
    lines.push(format!("({action} {}", operations.join(" ")));
    for path in paths {
        lines.push(format!("  (literal {})", escaped_path(&path)?));
    }
    lines.push(")".to_string());
    Ok(())
}

fn escaped_path(path: &Path) -> Result<String> {
    let path = path
        .to_str()
        .with_context(|| format!("Seatbelt path is not UTF-8: {}", path.display()))?;
    if path.contains('\0') {
        bail!("Seatbelt path contains a NUL byte");
    }
    let escaped = serde_json::to_string(path).context("failed to escape Seatbelt path")?;
    if escaped.len() > MAX_SBPL_STRING_BYTES {
        bail!(
            "Seatbelt path exceeds the {MAX_SBPL_STRING_BYTES}-byte profile string limit: {}",
            path
        );
    }
    Ok(escaped)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_denies_network_and_reasserts_workspace_secrets() {
        let workspace = tempfile::tempdir().unwrap();
        let scratch = tempfile::tempdir().unwrap();
        std::fs::write(workspace.path().join(".env"), "secret").unwrap();
        let policy = SandboxPolicy::for_execution(workspace.path(), scratch.path()).unwrap();

        let profile = compile_profile(&policy).unwrap();
        let canonical_workspace = workspace.path().canonicalize().unwrap();

        assert!(!profile.contains("(allow network"));
        assert!(profile.contains("(deny file-link)"));
        let workspace_rule = format!(
            "(subpath {})",
            serde_json::to_string(canonical_workspace.to_str().unwrap()).unwrap()
        );
        let secret_rule = format!(
            "(subpath {})",
            serde_json::to_string(canonical_workspace.join(".env").to_str().unwrap()).unwrap()
        );
        assert!(profile.matches(&workspace_rule).count() >= 2);
        assert!(profile.matches(&secret_rule).count() >= 2);
    }
}
