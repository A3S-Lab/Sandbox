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
use std::sync::{Arc, RwLock};

mod network;
mod observability;
mod platform;
mod policy;
mod process;

pub use network::{
    default_guest_relay_addr, posix_shell_single_quote, resolve_relay_executable,
    stage_relay_into_scratch, wrap_command_with_guest_relay, wrap_command_with_guest_relays,
    ConnectMediator, ConnectMediatorHandle, Socks5Mediator, Socks5MediatorHandle, TcpUnixRelay,
    TcpUnixRelayHandle, GUEST_HTTP_CONNECT_RELAY_PORT, GUEST_SOCKS_CONNECT_RELAY_PORT,
};
pub use observability::{AuditEvent, AuditEventParts, AuditLog, AuditSurface, ReasonCode};
pub use policy::{
    capability_matrix, capability_matrix_markdown, decide_mediated_connect, decide_mediated_http,
    decide_mediated_socks, decide_network, decide_read, decide_write, ensure_policy_not_broader,
    hard_link_count, hard_link_count_for_open_file, is_protected_workspace_path,
    matching_secret_injections, normalize_policy_path, policy_digest, sensitive_paths,
    should_skip_workspace_scan_directory, workspace_credential_hardlink_aliases,
    workspace_hardlink_paths, workspace_sensitive_paths, AccessDecision, BackendCapabilities,
    FeatureFlags, FilesystemMount, FilesystemRules, MediatedHttpRequest, MountMode,
    NetworkAllowRule, NetworkDefault, NetworkGrant, NetworkRules, NormalizedPath, PathRule,
    PolicyUpdateOptions, ResolvedResourceBudget, ResourceLimits, SandboxPolicy,
    SecretHeaderInjection, SessionWriteMode, SocketRules, POLICY_VERSION,
    PROTECTED_WORKSPACE_DIRECTORIES, PROTECTED_WORKSPACE_FILES,
};

const DEFAULT_TIMEOUT_MS: u64 = 120_000;
const PROBE_TIMEOUT_MS: u64 = 30_000;
const PROBE_MARKER: &str = "a3s-native-sandbox-ready";

/// Maximum stdout and stderr bytes retained for a command.
pub const MAX_OUTPUT_SIZE: usize = 100 * 1024;

/// Prefix of the redacted placeholder a child observes for a host-held secret
/// environment entry. Gate 8 slice 1: real secret bytes never enter the child
/// environment; the host re-injects them only at a mediation point in a later
/// slice.
pub const SECRET_ENV_SENTINEL_PREFIX: &str = "a3s:secret:";

/// Windows host commands use the same PowerShell 7 executable as the
/// AppContainer backend. `powershell.exe` is a different binary and is not
/// part of this contract.
#[cfg(windows)]
pub fn windows_host_powershell(workspace: &Path) -> Result<PathBuf> {
    platform::resolve_powershell(workspace)
}

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
///
/// The policy sits behind a lock so an authorized grant can widen it while
/// the sandbox handle is shared (`Arc<dyn BashSandbox>` hosts). Execution
/// snapshots the policy at start, so a concurrent replacement never affects
/// a running command.
#[derive(Debug)]
pub struct NativeSandbox {
    workspace: PathBuf,
    policy: RwLock<SandboxPolicy>,
    platform: platform::PlatformSandbox,
    capabilities: BackendCapabilities,
    audit: AuditLog,
    session_id: String,
}

fn read_policy(policy: &RwLock<SandboxPolicy>) -> SandboxPolicy {
    policy
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
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
        let platform = platform::PlatformSandbox::new(&workspace)?;
        // Runtime-probed capabilities (Gate 11): without a delegated cgroup
        // subtree a Linux host refuses process-tree quotas at construction.
        let capabilities = platform.effective_capabilities();
        policy
            .validate_for_backend(capabilities)
            .context("sandbox policy is incompatible with this backend")?;
        Ok(Self {
            workspace,
            policy: RwLock::new(policy),
            platform,
            capabilities,
            audit: AuditLog::with_capacity(1_024),
            session_id: new_session_id(),
        })
    }

    pub fn workspace(&self) -> &Path {
        &self.workspace
    }

    /// A snapshot of the active policy document.
    pub fn policy(&self) -> SandboxPolicy {
        read_policy(&self.policy)
    }

    pub fn policy_digest(&self) -> String {
        policy_digest(&read_policy(&self.policy))
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

    /// Capabilities this sandbox instance can enforce, combining the
    /// compiled target with the runtime probe (cgroup delegation, Gate 11).
    pub fn capabilities(&self) -> BackendCapabilities {
        self.capabilities
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
    /// Safe to call while the handle is shared: each execute snapshots the
    /// policy document at start, so a concurrent replacement never affects a
    /// running command.
    pub fn replace_policy(
        &self,
        policy: SandboxPolicy,
        options: PolicyUpdateOptions,
    ) -> Result<()> {
        policy
            .validate_for_backend(self.capabilities())
            .context("replacement sandbox policy is incompatible with this backend")?;
        {
            let mut guard = self
                .policy
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if !options.allow_broadening {
                ensure_policy_not_broader(&guard, &policy)
                    .context("refusing silent policy broadening")?;
            }
            *guard = policy;
        }
        Ok(())
    }

    /// Apply a host-approved network grant: the only sanctioned broadening
    /// path (optimization-roadmap Gate 10).
    ///
    /// `expected_base_digest` must match the current policy digest, pinning
    /// the grant to the exact policy the user approved against. On a deny-all
    /// baseline the grant is also the sanctioned activation of
    /// `mediated_network`, scoped to exactly one origin. Returns the new
    /// policy digest; every application (and every stale-digest refusal) is
    /// auditable.
    pub fn apply_network_grant(
        &self,
        grant: policy::NetworkGrant,
        expected_base_digest: &str,
    ) -> Result<String> {
        let base_digest = self.policy_digest();
        let subject = match grant.port {
            Some(port) => format!("{}:{port}", grant.host),
            None => grant.host.clone(),
        };
        if base_digest != expected_base_digest {
            self.audit.record(AuditEvent::from_parts(AuditEventParts {
                session_id: self.session_id.clone(),
                command_id: format!("grant-{}", unix_millis()),
                policy_digest: base_digest.clone(),
                backend: self.backend().into(),
                surface: AuditSurface::PolicyCompile,
                decision: AccessDecision::Deny,
                reason_code: ReasonCode::PolicyDeny,
                target_redacted: format!("<network-grant:{subject};stale-digest>"),
            }));
            bail!(
                "network grant for {subject} was approved against digest \
                 {expected_base_digest}, but the session policy is now {base_digest}; \
                 re-approve against the current policy"
            );
        }
        let current = read_policy(&self.policy);
        let (widened, changed) = policy::apply_network_grant_to_policy(&current, &grant)?;
        self.replace_policy(
            widened,
            PolicyUpdateOptions {
                allow_broadening: true,
            },
        )
        .context("granted policy must be enforceable on this backend")?;
        let new_digest = self.policy_digest();
        if changed {
            self.audit.record(AuditEvent::from_parts(AuditEventParts {
                session_id: self.session_id.clone(),
                command_id: format!("grant-{}", unix_millis()),
                policy_digest: new_digest.clone(),
                backend: self.backend().into(),
                surface: AuditSurface::Network,
                decision: AccessDecision::Allow,
                reason_code: ReasonCode::GrantApplied,
                target_redacted: format!("<network-grant:{subject}>"),
            }));
        }
        Ok(new_digest)
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
        self.execute_inner(request, new_command_id(), None).await
    }

    /// Execute a command with host-held secret environment entries.
    ///
    /// Secret values never reach the child: each entry is delivered as a
    /// [`SECRET_ENV_SENTINEL_PREFIX`] placeholder and the host re-injects the
    /// real value only at a mediation point. Because a sentinel nothing
    /// re-injects would silently strand the secret, entries refuse to run
    /// unless the policy actually enables the mediated-network boundary.
    /// Malformed names, values, reserved environment names, and collisions
    /// with explicit entries all fail closed before spawn.
    pub async fn execute_with_secrets(
        &self,
        mut request: CommandRequest,
        secrets: Option<Arc<HashMap<String, String>>>,
    ) -> Result<CommandOutput> {
        let command_id = new_command_id();
        let Some(secrets) = secrets.filter(|map| !map.is_empty()) else {
            return self.execute_inner(request, command_id, None).await;
        };
        if !read_policy(&self.policy).features.mediated_network {
            self.audit.record(AuditEvent::from_parts(AuditEventParts {
                session_id: self.session_id.clone(),
                command_id: command_id.clone(),
                policy_digest: self.policy_digest(),
                backend: self.backend().into(),
                surface: AuditSurface::Environment,
                decision: AccessDecision::Deny,
                reason_code: ReasonCode::SecretRequiresMediation,
                target_redacted: "<secret-env>".into(),
            }));
            bail!(
                "secret environment entries require mediated_network; refusing to run \
                 secrets without a mediation boundary"
            );
        }
        for (name, value) in secrets.iter() {
            if name.is_empty() || name.contains('=') || name.contains('\0') || value.contains('\0')
            {
                bail!("invalid secret environment entry: {name:?}");
            }
            if policy::secret_env_name_is_reserved(name) {
                bail!("secret environment entry uses a reserved environment name: {name}");
            }
            if request
                .env
                .as_ref()
                .is_some_and(|env| env.contains_key(name))
            {
                bail!(
                    "secret environment entry {name} collides with an explicit \
                     command environment entry"
                );
            }
        }
        // Gate 8 slice 2: every policy injection must resolve against this
        // request's secrets, and its value must be header-safe. Otherwise the
        // mediator would either strand the rule or split headers upstream.
        for injection in &read_policy(&self.policy).secret_injections {
            let Some(value) = secrets.get(&injection.secret_env) else {
                bail!(
                    "policy secret_injections reference secret {} which was not \
                     provided for this command; refusing to run with a stranded rule",
                    injection.secret_env
                );
            };
            if value.bytes().any(|byte| matches!(byte, b'\r' | b'\n' | 0)) {
                bail!(
                    "invalid secret value for {}: control characters would break \
                     the injected header",
                    injection.secret_env
                );
            }
        }
        let mut merged = request.env.as_deref().cloned().unwrap_or_default();
        for name in secrets.keys() {
            merged.insert(name.clone(), format!("{SECRET_ENV_SENTINEL_PREFIX}{name}"));
        }
        request.env = Some(Arc::new(merged));
        let mut names: Vec<&str> = secrets.keys().map(String::as_str).collect();
        names.sort_unstable();
        self.audit.record(AuditEvent::from_parts(AuditEventParts {
            session_id: self.session_id.clone(),
            command_id: command_id.clone(),
            policy_digest: self.policy_digest(),
            backend: self.backend().into(),
            surface: AuditSurface::Environment,
            decision: AccessDecision::Allow,
            reason_code: ReasonCode::PolicyAllow,
            target_redacted: format!("<secret-env:{}>", names.join(",")),
        }));
        self.execute_inner(request, command_id, Some(secrets)).await
    }

    async fn execute_inner(
        &self,
        request: CommandRequest,
        command_id: String,
        secrets: Option<Arc<HashMap<String, String>>>,
    ) -> Result<CommandOutput> {
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
        let digest = self.policy_digest();
        // Snapshot so a concurrent replace_policy cannot race a running
        // command.
        let policy_doc = read_policy(&self.policy);

        let mut http_mediator = None;
        // Platform cfg arms assign different subsets of these fields.
        #[allow(unused_mut)]
        let mut mediator_unix_path = None;
        #[allow(unused_mut)]
        let mut mediator_port = None;
        #[allow(unused_mut)]
        let mut mediator_pipe_name = None;
        #[cfg(windows)]
        let mut mediator_pipe_client: Option<std::os::windows::io::OwnedHandle> = None;
        if policy_doc.features.mediated_network {
            #[cfg(target_os = "linux")]
            {
                let sock = scratch.path().join("mediator.sock");
                http_mediator = Some(
                    crate::ConnectMediator::bind_unix(policy_doc.clone(), &sock, secrets.clone())
                        .await
                        .context("failed to start host Unix CONNECT mediator")?,
                );
                mediator_unix_path = Some(sock);
                mediator_port = Some(crate::GUEST_HTTP_CONNECT_RELAY_PORT);
            }
            #[cfg(target_os = "macos")]
            {
                http_mediator = Some(
                    crate::ConnectMediator::bind(policy_doc.clone(), secrets.clone())
                        .await
                        .context("failed to start host CONNECT mediator")?,
                );
                mediator_port = http_mediator
                    .as_ref()
                    .map(|handle| handle.listen_addr().port());
            }
            #[cfg(windows)]
            {
                // AppContainer guests cannot name-open host pipes (Access Denied).
                // Create a connected pair and inherit the client handle into the guest.
                let pipe_name = format!(
                    r"\\.\pipe\a3s-sandbox-{}-{}",
                    std::process::id(),
                    command_id
                );
                let (server, client) = self
                    .platform
                    .create_mediation_pipe(&pipe_name)
                    .context("failed to create AppContainer mediation pipe pair")?;
                http_mediator = Some(
                    crate::ConnectMediator::bind_named_pipe_connected(
                        policy_doc.clone(),
                        pipe_name.clone(),
                        server,
                        secrets.clone(),
                    )
                    .await
                    .context("failed to start connected AppContainer CONNECT mediator")?,
                );
                mediator_pipe_name = Some(pipe_name);
                mediator_pipe_client = Some(client);
            }
            #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
            {
                bail!("mediated_network is unavailable on this platform");
            }
        }
        let mut socks_mediator = None;
        // Platform cfg arms assign different subsets of these fields.
        #[allow(unused_mut)]
        let mut socks_mediator_unix_path = None;
        let socks_mediator_port = if policy_doc.features.mediated_socks {
            #[cfg(target_os = "linux")]
            {
                let sock = scratch.path().join("socks-mediator.sock");
                socks_mediator = Some(
                    crate::Socks5Mediator::bind_unix(policy_doc.clone(), &sock)
                        .await
                        .context("failed to start host Unix SOCKS5 mediator")?,
                );
                socks_mediator_unix_path = Some(sock);
                Some(crate::GUEST_SOCKS_CONNECT_RELAY_PORT)
            }
            #[cfg(not(target_os = "linux"))]
            {
                socks_mediator = Some(
                    crate::Socks5Mediator::bind(policy_doc.clone())
                        .await
                        .context("failed to start host SOCKS5 mediator")?,
                );
                socks_mediator
                    .as_ref()
                    .map(|handle| handle.listen_addr().port())
            }
        } else {
            None
        };

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
                policy.socks_mediator_unix_path = socks_mediator_unix_path;
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
        let output = {
            #[cfg(windows)]
            {
                if let Some(client) = mediator_pipe_client {
                    self.platform
                        .execute_with_mediator_client(&policy, request, client)
                        .await?
                } else {
                    self.platform.execute(&policy, request).await?
                }
            }
            #[cfg(not(windows))]
            {
                self.platform.execute(&policy, request).await?
            }
        };
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
