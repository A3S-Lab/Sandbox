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

mod network;
mod observability;
mod platform;
mod policy;
mod process;

pub use network::{
    default_guest_relay_addr, posix_shell_single_quote, resolve_relay_executable,
    stage_relay_into_scratch, wrap_command_with_guest_relay, ConnectMediator,
    ConnectMediatorHandle, Socks5Mediator, Socks5MediatorHandle, TcpUnixRelay, TcpUnixRelayHandle,
    GUEST_HTTP_CONNECT_RELAY_PORT,
};
pub use observability::{AuditEvent, AuditEventParts, AuditLog, AuditSurface, ReasonCode};
pub use policy::{
    decide_mediated_connect, decide_mediated_http, decide_mediated_socks, decide_network,
    decide_read, decide_write, ensure_policy_not_broader, hard_link_count,
    hard_link_count_for_open_file, is_protected_workspace_path, normalize_policy_path,
    policy_digest, sensitive_paths, should_skip_workspace_scan_directory,
    workspace_credential_hardlink_aliases, workspace_hardlink_paths, workspace_sensitive_paths,
    AccessDecision, BackendCapabilities, FeatureFlags, FilesystemMount, FilesystemRules,
    MediatedHttpRequest, MountMode, NetworkAllowRule, NetworkDefault, NetworkRules, NormalizedPath,
    PathRule, PolicyUpdateOptions, ResolvedResourceBudget, ResourceLimits, SandboxPolicy,
    SessionWriteMode, SocketRules, POLICY_VERSION, PROTECTED_WORKSPACE_DIRECTORIES,
    PROTECTED_WORKSPACE_FILES,
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
    policy: SandboxPolicy,
    platform: platform::PlatformSandbox,
    audit: AuditLog,
    session_id: String,
}

/// Structured capability probe for Gate 6 host negotiation.
///
/// Unavailable surfaces are listed explicitly so nested/container hosts never
/// assume silent degradation. Callers must either drop those policy features or
/// refuse startup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityReport {
    pub backend: &'static str,
    pub capabilities: BackendCapabilities,
    pub policy_digest: String,
    pub unavailable: Vec<&'static str>,
}

impl NativeSandbox {
    /// Resolve a workspace and initialize the current platform boundary with
    /// the A3S Bash baseline policy.
    pub fn new(workspace: impl Into<PathBuf>) -> Result<Self> {
        Self::with_policy(workspace, SandboxPolicy::a3s_bash_baseline())
    }

    /// Resolve a workspace with an explicit typed policy. Unsupported or
    /// unenforceable rules fail closed before any command runs.
    pub fn with_policy(workspace: impl Into<PathBuf>, policy: SandboxPolicy) -> Result<Self> {
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
        policy
            .validate_for_backend(BackendCapabilities::native_gate2())
            .context("sandbox policy is incompatible with this backend")?;
        let platform = platform::PlatformSandbox::new(&workspace)?;
        Ok(Self {
            workspace,
            policy,
            platform,
            audit: AuditLog::with_capacity(1_024),
            session_id: new_session_id(),
        })
    }

    pub fn workspace(&self) -> &Path {
        &self.workspace
    }

    pub fn policy(&self) -> &SandboxPolicy {
        &self.policy
    }

    pub fn policy_digest(&self) -> String {
        policy_digest(&self.policy)
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn audit_log(&self) -> &AuditLog {
        &self.audit
    }

    pub fn backend(&self) -> &'static str {
        NATIVE_SANDBOX_BACKEND
    }

    /// Backend capabilities for the compiled target. Policy must not request more.
    pub fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities::native_gate2()
    }

    /// Reject a caller policy that this backend cannot enforce.
    pub fn ensure_policy_enforceable(&self, policy: &SandboxPolicy) -> Result<()> {
        policy.validate_for_backend(self.capabilities())
    }

    /// Report advertised capabilities and surfaces this host cannot provide.
    pub fn capability_report(&self) -> CapabilityReport {
        let capabilities = self.capabilities();
        let mut unavailable = Vec::new();
        if !capabilities.mediated_http {
            unavailable.push("mediated_http");
        }
        if !capabilities.mediated_socks {
            unavailable.push("mediated_socks");
        }
        if !capabilities.unix_socket_allowlist {
            unavailable.push("unix_socket_allowlist");
        }
        if !capabilities.filesystem_ephemeral_writes {
            unavailable.push("filesystem_ephemeral_writes");
        }
        if !capabilities.resource_memory_limit {
            unavailable.push("resource_memory_limit");
        }
        if !capabilities.resource_process_limit {
            unavailable.push("resource_process_limit");
        }
        CapabilityReport {
            backend: self.backend(),
            capabilities,
            policy_digest: self.policy_digest(),
            unavailable,
        }
    }

    /// Replace the session policy. Broadening fails closed unless opted in.
    ///
    /// Callers must not invoke this concurrently with [`Self::execute`]; each
    /// execute snapshots the policy document at start.
    pub fn replace_policy(
        &mut self,
        policy: SandboxPolicy,
        options: PolicyUpdateOptions,
    ) -> Result<()> {
        policy
            .validate_for_backend(self.capabilities())
            .context("replacement sandbox policy is incompatible with this backend")?;
        if !options.allow_broadening {
            ensure_policy_not_broader(&self.policy, &policy)
                .context("refusing silent policy broadening")?;
        }
        self.policy = policy;
        Ok(())
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
        let scratch = tempfile::Builder::new()
            .prefix("a3s-sandbox-")
            .tempdir()
            .context("failed to create native sandbox scratch directory")?;
        let digest = policy_digest(&self.policy);
        let command_id = new_command_id();
        // Snapshot so concurrent replace_policy cannot race a running command.
        let policy_doc = self.policy.clone();

        let mut http_mediator = None;
        // Platform cfg arms assign different subsets of these fields.
        #[allow(unused_mut)]
        let mut mediator_unix_path = None;
        #[allow(unused_mut)]
        let mut mediator_port = None;
        #[allow(unused_mut)]
        let mut mediator_pipe_name = None;
        if policy_doc.features.mediated_network {
            #[cfg(target_os = "linux")]
            {
                let sock = scratch.path().join("mediator.sock");
                http_mediator = Some(
                    crate::ConnectMediator::bind_unix(policy_doc.clone(), &sock)
                        .await
                        .context("failed to start host Unix CONNECT mediator")?,
                );
                mediator_unix_path = Some(sock);
                mediator_port = Some(crate::GUEST_HTTP_CONNECT_RELAY_PORT);
            }
            #[cfg(target_os = "macos")]
            {
                http_mediator = Some(
                    crate::ConnectMediator::bind(policy_doc.clone())
                        .await
                        .context("failed to start host CONNECT mediator")?,
                );
                mediator_port = http_mediator
                    .as_ref()
                    .map(|handle| handle.listen_addr().port());
            }
            #[cfg(windows)]
            {
                // AppContainer guests have zero network capabilities, so loopback
                // HTTP_PROXY cannot work. Speak CONNECT over an ACL'd named pipe.
                // Capability claim still requires live guest tunnel proof.
                let pipe_name = format!(
                    r"\\.\pipe\a3s-sandbox-{}-{}",
                    std::process::id(),
                    command_id
                );
                let factory = self.platform.mediator_named_pipe_factory(pipe_name.clone());
                http_mediator = Some(
                    crate::ConnectMediator::bind_named_pipe_acl(
                        policy_doc.clone(),
                        pipe_name.clone(),
                        factory,
                    )
                    .await
                    .context("failed to start AppContainer-ACL'd CONNECT named-pipe mediator")?,
                );
                mediator_pipe_name = Some(pipe_name);
            }
            #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
            {
                bail!("mediated_network is unavailable on this platform");
            }
        }
        let mut socks_mediator = None;
        if policy_doc.features.mediated_socks {
            socks_mediator = Some(
                crate::Socks5Mediator::bind(policy_doc.clone())
                    .await
                    .context("failed to start host SOCKS5 mediator")?,
            );
        }
        let socks_mediator_port = socks_mediator
            .as_ref()
            .map(|handle| handle.listen_addr().port());

        let policy = match policy::EnforcedPolicy::compile(
            &policy_doc,
            &self.workspace,
            scratch.path(),
            self.capabilities(),
        ) {
            Ok(mut policy) => {
                policy.mediator_port = mediator_port;
                policy.mediator_unix_path = mediator_unix_path;
                policy.mediator_pipe_name = mediator_pipe_name;
                policy.socks_mediator_port = socks_mediator_port;
                self.audit.record(AuditEvent::from_parts(AuditEventParts {
                    session_id: self.session_id.clone(),
                    command_id: command_id.clone(),
                    policy_digest: digest.clone(),
                    backend: self.backend().into(),
                    surface: AuditSurface::PolicyCompile,
                    decision: AccessDecision::Allow,
                    reason_code: ReasonCode::PolicyAllow,
                    target_redacted: "enforced-policy".into(),
                }));
                self.audit.record(AuditEvent::from_parts(AuditEventParts {
                    session_id: self.session_id.clone(),
                    command_id: command_id.clone(),
                    policy_digest: digest.clone(),
                    backend: self.backend().into(),
                    surface: AuditSurface::Network,
                    decision: AccessDecision::Deny,
                    reason_code: ReasonCode::NetworkDenyAll,
                    target_redacted: if mediator_port.is_some()
                        || socks_mediator_port.is_some()
                        || policy.mediator_pipe_name.is_some()
                    {
                        "<network-except-mediator>".into()
                    } else {
                        "<network>".into()
                    },
                }));
                policy
            }
            Err(error) => {
                self.audit.record(AuditEvent::from_parts(AuditEventParts {
                    session_id: self.session_id.clone(),
                    command_id: command_id.clone(),
                    policy_digest: digest.clone(),
                    backend: self.backend().into(),
                    surface: AuditSurface::PolicyCompile,
                    decision: AccessDecision::Deny,
                    reason_code: ReasonCode::CompileOverlayRejected,
                    target_redacted: "compile-failed".into(),
                }));
                if let Some(handle) = http_mediator {
                    handle.shutdown().await;
                }
                if let Some(handle) = socks_mediator {
                    handle.shutdown().await;
                }
                return Err(error);
            }
        };
        let output = self.platform.execute(&policy, request).await?;
        if let Some(handle) = http_mediator {
            handle.shutdown().await;
        }
        if let Some(handle) = socks_mediator {
            handle.shutdown().await;
        }
        if output.timed_out {
            self.audit.record(AuditEvent::from_parts(AuditEventParts {
                session_id: self.session_id.clone(),
                command_id,
                policy_digest: digest,
                backend: self.backend().into(),
                surface: AuditSurface::Process,
                decision: AccessDecision::Deny,
                reason_code: ReasonCode::Timeout,
                target_redacted: "<process-tree>".into(),
            }));
        }
        Ok(output)
    }
}

fn new_session_id() -> String {
    format!("session-{}", unix_millis())
}

fn new_command_id() -> String {
    format!("command-{}", unix_millis())
}

fn unix_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests;
