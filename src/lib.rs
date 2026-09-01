//! Cross-platform native command isolation for A3S.
//!
//! Platform backends are implemented with Seatbelt on macOS, namespaces and
//! seccomp on Linux, and AppContainer plus Job Objects on Windows. Unsupported
//! targets fail closed. The crate does not depend on A3S Code or any product
//! host, so policy and lifecycle semantics remain reusable.

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

mod platform;
mod policy;
mod process;

pub use policy::{
    hard_link_count, hard_link_count_for_open_file, is_protected_workspace_path, sensitive_paths,
    should_skip_workspace_scan_directory, workspace_hardlink_paths, workspace_sensitive_paths,
    PROTECTED_WORKSPACE_DIRECTORIES, PROTECTED_WORKSPACE_FILES,
};

const DEFAULT_TIMEOUT_MS: u64 = 120_000;
const PROBE_TIMEOUT_MS: u64 = 30_000;
const PROBE_MARKER: &str = "a3s-native-sandbox-ready";

/// Maximum stdout and stderr bytes retained for a command.
pub const MAX_OUTPUT_SIZE: usize = 100 * 1024;

/// Native backend selected for the current target.
pub const NATIVE_SANDBOX_BACKEND: &str = if cfg!(target_os = "macos") {
    "macos-seatbelt"
} else if cfg!(target_os = "linux") {
    "linux-namespace-seccomp"
} else if cfg!(windows) {
    "windows-appcontainer"
} else {
    "unsupported"
};

/// Final accounting for bounded command output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutputSummary {
    pub total_bytes: usize,
    pub captured_bytes: usize,
    pub truncated: bool,
    pub timed_out: bool,
}

/// Observer for live command output and final capture accounting.
#[async_trait]
pub trait OutputObserver: Send + Sync {
    async fn on_output_delta(&self, delta: &str);

    async fn on_output_complete(&self, _summary: &OutputSummary) {}
}

/// Complete command execution request.
#[derive(Clone)]
pub struct CommandRequest {
    pub command: String,
    pub timeout_ms: u64,
    pub output_observer: Option<Arc<dyn OutputObserver>>,
    pub env: Option<Arc<HashMap<String, String>>>,
}

impl std::fmt::Debug for CommandRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CommandRequest")
            .field("command", &self.command)
            .field("timeout_ms", &self.timeout_ms)
            .field("output_observer", &self.output_observer.is_some())
            .field("env", &self.env.as_ref().map(|env| env.len()))
            .finish()
    }
}

/// Result of a command executed inside the native boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    pub timed_out: bool,
}

/// A fail-closed native sandbox bound to one canonical workspace.
#[derive(Debug)]
pub struct NativeSandbox {
    workspace: PathBuf,
    platform: platform::PlatformSandbox,
}

impl NativeSandbox {
    /// Resolve a workspace and initialize the current platform boundary.
    pub fn new(workspace: impl Into<PathBuf>) -> Result<Self> {
        let workspace = workspace
            .into()
            .canonicalize()
            .context("failed to canonicalize the native sandbox workspace")?;
        if !workspace.is_dir() {
            bail!(
                "native sandbox workspace is not a directory: {}",
                workspace.display()
            );
        }
        let platform = platform::PlatformSandbox::new(&workspace)?;
        Ok(Self {
            workspace,
            platform,
        })
    }

    pub fn workspace(&self) -> &Path {
        &self.workspace
    }

    pub fn backend(&self) -> &'static str {
        NATIVE_SANDBOX_BACKEND
    }

    /// Prove that the selected operating-system boundary can start a command.
    pub async fn probe(&self) -> Result<()> {
        #[cfg(windows)]
        let command = format!("[Console]::Out.Write('{PROBE_MARKER}')");
        #[cfg(not(windows))]
        let command = format!("printf %s {PROBE_MARKER}");

        let output = self
            .execute(CommandRequest {
                command,
                timeout_ms: PROBE_TIMEOUT_MS,
                output_observer: None,
                env: None,
            })
            .await
            .context("native sandbox capability probe failed")?;
        if output.timed_out {
            bail!("native sandbox capability probe timed out");
        }
        if output.exit_code != 0 || output.stdout != PROBE_MARKER {
            bail!(
                "native sandbox capability probe returned exit code {} with stdout {:?} and stderr {:?}",
                output.exit_code,
                output.stdout,
                output.stderr
            );
        }
        Ok(())
    }

    /// Execute a command with a default two-minute deadline.
    pub async fn exec_command(&self, command: impl Into<String>) -> Result<CommandOutput> {
        self.execute(CommandRequest {
            command: command.into(),
            timeout_ms: DEFAULT_TIMEOUT_MS,
            output_observer: None,
            env: None,
        })
        .await
    }

    /// Execute a command inside the configured native boundary.
    pub async fn execute(&self, request: CommandRequest) -> Result<CommandOutput> {
        if request.timeout_ms == 0 {
            bail!("native sandbox command timeout must be greater than zero");
        }
        if request.command.contains('\0') {
            bail!("native sandbox command contains a NUL byte");
        }
        #[cfg(all(test, windows))]
        eprintln!("[a3s-sandbox-test] build execution policy");
        let scratch = tempfile::Builder::new()
            .prefix("a3s-sandbox-")
            .tempdir()
            .context("failed to create native sandbox scratch directory")?;
        let policy = policy::SandboxPolicy::for_execution(&self.workspace, scratch.path())?;
        #[cfg(all(test, windows))]
        eprintln!("[a3s-sandbox-test] execution policy built");
        self.platform.execute(&policy, request).await
    }
}

#[cfg(test)]
mod tests;
