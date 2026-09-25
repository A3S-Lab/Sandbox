//! Typed, versioned sandbox policy document (Gate 1).

use anyhow::{bail, Result};
use std::collections::BTreeSet;

/// Policy schema version carried in every digest.
pub const POLICY_VERSION: u32 = 1;

/// Public, platform-neutral policy document.
///
/// Backends must enforce this document (or a compiled view of it). They must
/// not invent broader permissions when a host feature is missing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxPolicy {
    pub version: u32,
    pub filesystem: FilesystemRules,
    pub network: NetworkRules,
    pub sockets: SocketRules,
    pub resources: ResourceLimits,
    pub features: FeatureFlags,
    /// Gate 8 egress transforms. Decoration only: a request is allowed by the
    /// `network.allow` list alone, and matching injection rules add one secret
    /// header each. TLS interception stays a non-goal, so these apply only to
    /// absolute-form plain-HTTP mediation.
    pub secret_injections: Vec<SecretHeaderInjection>,
}

/// Inject `{header}: {value_prefix}<secret>` into an allowed absolute-form
/// plain-HTTP request whose origin and path match. The secret value lives in
/// the per-request secret map (see `NativeSandbox::execute_with_secrets`),
/// never in this document: only its env-entry name is recorded here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretHeaderInjection {
    pub host: String,
    pub port: Option<u16>,
    pub path_prefix: Option<String>,
    /// HTTP header name to inject, replacing any client-supplied instance.
    pub header: String,
    /// Literal prefix before the secret value (for example `"Bearer "`).
    pub value_prefix: String,
    /// Name of the secret env entry holding the value.
    pub secret_env: String,
}

/// Filesystem allow/deny sets. Deny wins over allow. Write exceptions apply
/// after deny-write (carve-outs under an otherwise denied ancestor).
///
/// Gate 3 mounts are typed roots with explicit modes. Empty `mounts` keeps the
/// Gate 0/1 workspace+scratch baseline. `session_write` defaults to
/// [`SessionWriteMode::Persistent`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FilesystemRules {
    pub allow_read: Vec<PathRule>,
    pub deny_read: Vec<PathRule>,
    pub allow_write: Vec<PathRule>,
    pub deny_write: Vec<PathRule>,
    pub write_exceptions: Vec<PathRule>,
    pub mounts: Vec<FilesystemMount>,
    pub session_write: SessionWriteMode,
}

/// How a typed mount root may be used inside the sandbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MountMode {
    /// Readable knowledge / tool tree; writes must fail closed.
    ReadOnly,
    /// Writable root. Outside workspace/scratch this still fails closed.
    ReadWrite,
    /// Private scratch root (must resolve under the session scratch tree).
    Scratch,
}

/// A Gate 3 filesystem mount root.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct FilesystemMount {
    pub root: PathRule,
    pub mode: MountMode,
}

/// Session write durability. Ephemeral requires an OS overlay/tmpfs (or
/// equivalent); backends that cannot provide it must fail closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SessionWriteMode {
    #[default]
    Persistent,
    Ephemeral,
}

/// A single path rule. Paths are stored in normalized policy form (`/`
/// separators, no `.` / `..` components after normalization).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum PathRule {
    /// Exact path match, or prefix match when the candidate is under this path.
    Exact(String),
    /// Glob match (`*` and `?` only; `**` is rejected at validation time).
    Glob(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkRules {
    pub default: NetworkDefault,
    /// Reserved for Gate 4+. Gate 1 rejects non-empty allow lists unless the
    /// mediated-network feature flag is set—and still rejects them until that
    /// gate ships (fail closed).
    pub allow: Vec<NetworkAllowRule>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkDefault {
    DenyAll,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct NetworkAllowRule {
    pub host: String,
    pub port: Option<u16>,
    /// Optional path prefix for HTTP(S) mediation (`/` normalized). Empty
    /// means any path on the origin.
    pub path_prefix: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SocketRules {
    /// Empty means deny all host Unix-domain sockets (Gate 0 / Gate 1 default).
    pub allow_unix: Vec<PathRule>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceLimits {
    pub timeout_ms: u64,
    pub max_output_bytes: usize,
    pub max_call_depth: Option<u32>,
    pub max_processes: Option<u32>,
    pub max_memory_bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FeatureFlags {
    /// Gate 4. Must stay false until mediated HTTP ships.
    pub mediated_network: bool,
    /// Gate 5. Opt-in SOCKS5 host mediation (requires OS loopback fence).
    pub mediated_socks: bool,
}

impl Default for NetworkRules {
    fn default() -> Self {
        Self {
            default: NetworkDefault::DenyAll,
            allow: Vec::new(),
        }
    }
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            timeout_ms: 120_000,
            max_output_bytes: crate::MAX_OUTPUT_SIZE,
            max_call_depth: None,
            max_processes: None,
            max_memory_bytes: None,
        }
    }
}

impl Default for SandboxPolicy {
    fn default() -> Self {
        Self {
            version: POLICY_VERSION,
            filesystem: FilesystemRules::default(),
            network: NetworkRules::default(),
            sockets: SocketRules::default(),
            resources: ResourceLimits::default(),
            features: FeatureFlags::default(),
            secret_injections: Vec::new(),
        }
    }
}

impl SandboxPolicy {
    /// Strict A3S Bash baseline document: network deny-all, no mediation flags.
    pub fn a3s_bash_baseline() -> Self {
        Self::default()
    }

    /// Reject malformed or prematurely enabled rules. Never silently repair.
    pub fn validate(&self) -> Result<()> {
        if self.version != POLICY_VERSION {
            bail!(
                "unsupported sandbox policy version {}; only {POLICY_VERSION} is accepted",
                self.version
            );
        }

        for rule in self
            .filesystem
            .allow_read
            .iter()
            .chain(self.filesystem.deny_read.iter())
            .chain(self.filesystem.allow_write.iter())
            .chain(self.filesystem.deny_write.iter())
            .chain(self.filesystem.write_exceptions.iter())
            .chain(self.filesystem.mounts.iter().map(|mount| &mount.root))
            .chain(self.sockets.allow_unix.iter())
        {
            validate_path_rule(rule)?;
        }

        for mount in &self.filesystem.mounts {
            if matches!(mount.mode, MountMode::ReadWrite) {
                // Document-level RW mounts outside workspace/scratch are rejected
                // at compile time; still forbid Glob RW mounts here (Exact only).
                if matches!(mount.root, PathRule::Glob(_)) {
                    bail!(
                        "ReadWrite mounts must use Exact paths; globs would broaden \
                         write surface unpredictably"
                    );
                }
            }
        }

        if self.resources.timeout_ms == 0 {
            bail!("resource limit timeout_ms must be greater than zero");
        }
        if self.resources.max_output_bytes == 0 {
            bail!("resource limit max_output_bytes must be greater than zero");
        }

        let mediation_enabled = self.features.mediated_network || self.features.mediated_socks;
        if !self.network.allow.is_empty() && !mediation_enabled {
            bail!(
                "network allow rules require features.mediated_network or \
                 features.mediated_socks; refuse premature allow lists instead of \
                 silently ignoring them"
            );
        }
        if self.features.mediated_network && self.network.allow.is_empty() {
            bail!(
                "features.mediated_network is set but network.allow is empty; refuse a \
                 mediation flag with no allowlist"
            );
        }
        if self.features.mediated_socks && self.network.allow.is_empty() {
            bail!(
                "features.mediated_socks is set but network.allow is empty; refuse a \
                 mediation flag with no allowlist"
            );
        }
        if self.network.default != NetworkDefault::DenyAll {
            bail!("network default must be DenyAll (mediation is allowlist-only)");
        }
        if !self.secret_injections.is_empty() && !self.features.mediated_network {
            bail!(
                "secret_injections require features.mediated_network; refuse secret \
                 egress transforms without a mediation boundary"
            );
        }

        for rule in &self.network.allow {
            if rule.host.is_empty() || rule.host.contains(['/', '\\', ' ']) {
                bail!("invalid network allow host: {:?}", rule.host);
            }
            if let Some(prefix) = &rule.path_prefix {
                if !prefix.starts_with('/') || prefix.contains("..") {
                    bail!(
                        "network allow path_prefix must be an absolute path without '..': {:?}",
                        prefix
                    );
                }
            }
        }

        for injection in &self.secret_injections {
            if injection.host.is_empty() || injection.host.contains(['/', '\\', ' ']) {
                bail!("invalid secret injection host: {:?}", injection.host);
            }
            if injection.header.is_empty() || !injection.header.chars().all(is_http_token_char) {
                bail!(
                    "invalid secret injection header name: {:?}",
                    injection.header
                );
            }
            if injection
                .value_prefix
                .bytes()
                .any(|byte| matches!(byte, b'\r' | b'\n' | 0))
            {
                bail!(
                    "secret injection value_prefix must not contain control characters: {:?}",
                    injection.header
                );
            }
            if injection.secret_env.is_empty()
                || injection.secret_env.contains(['=', '\0'])
                || super::secret_env_name_is_reserved(&injection.secret_env)
            {
                bail!(
                    "invalid secret injection secret_env name: {:?}",
                    injection.secret_env
                );
            }
            if let Some(prefix) = &injection.path_prefix {
                if !prefix.starts_with('/') || prefix.contains("..") {
                    bail!(
                        "secret injection path_prefix must be an absolute path without '..': {:?}",
                        prefix
                    );
                }
            }
        }

        Ok(())
    }

    /// Validate against what the current backend can enforce.
    pub fn validate_for_backend(
        &self,
        capabilities: crate::policy::BackendCapabilities,
    ) -> Result<()> {
        self.validate()?;
        if self.features.mediated_network && !capabilities.mediated_http {
            bail!("policy requests mediated_network but backend cannot enforce it; fail closed");
        }
        if self.features.mediated_socks && !capabilities.mediated_socks {
            bail!("policy requests mediated_socks but backend cannot enforce it; fail closed");
        }
        if !self.sockets.allow_unix.is_empty() && !capabilities.unix_socket_allowlist {
            bail!("unix socket allowlist requested but backend cannot enforce it; fail closed");
        }
        if self.resources.max_memory_bytes.is_some() && !capabilities.resource_memory_limit {
            bail!("memory limit requested but backend cannot enforce it; fail closed");
        }
        if self.resources.max_processes.is_some() && !capabilities.resource_process_limit {
            bail!("process limit requested but backend cannot enforce it; fail closed");
        }
        if self.resources.max_call_depth.is_some() {
            bail!("max_call_depth is not enforceable by the OS process boundary; fail closed");
        }
        if !self.filesystem.mounts.is_empty() && !capabilities.filesystem_readonly_mounts {
            bail!(
                "filesystem mounts requested but backend cannot enforce typed mounts; fail closed"
            );
        }
        if self.filesystem.session_write == SessionWriteMode::Ephemeral
            && !capabilities.filesystem_ephemeral_writes
        {
            bail!(
                "ephemeral session writes requested but backend cannot provide overlay/tmpfs \
                 (or equivalent); fail closed instead of emulating an in-process FS"
            );
        }
        if !capabilities.network_deny_all {
            bail!("backend cannot enforce network deny-all; fail closed");
        }
        Ok(())
    }

    /// Canonicalize rule ordering so digests are stable.
    pub fn canonicalized(&self) -> Self {
        let mut policy = self.clone();
        sort_path_rules(&mut policy.filesystem.allow_read);
        sort_path_rules(&mut policy.filesystem.deny_read);
        sort_path_rules(&mut policy.filesystem.allow_write);
        sort_path_rules(&mut policy.filesystem.deny_write);
        sort_path_rules(&mut policy.filesystem.write_exceptions);
        policy.filesystem.mounts.sort();
        policy.filesystem.mounts.dedup();
        sort_path_rules(&mut policy.sockets.allow_unix);
        policy.network.allow.sort();
        policy.network.allow.dedup();
        policy
    }
}

fn sort_path_rules(rules: &mut Vec<PathRule>) {
    let set: BTreeSet<_> = rules.drain(..).collect();
    rules.extend(set);
}

/// RFC 7230 `tchar`: characters allowed in an HTTP header name.
fn is_http_token_char(char: char) -> bool {
    matches!(
        char,
        '!' | '#' | '$' | '%' | '&' | '\'' | '*' | '+' | '-' | '.' | '^' | '_' | '`' | '|'
            | '~'
            | '0'..='9'
            | 'a'..='z'
            | 'A'..='Z'
    )
}

fn validate_path_rule(rule: &PathRule) -> Result<()> {
    let value = match rule {
        PathRule::Exact(value) | PathRule::Glob(value) => value,
    };
    if value.is_empty() {
        bail!("path rules must not be empty");
    }
    if value.contains('\0') {
        bail!("path rules must not contain NUL");
    }
    if value.split('/').any(|part| part == "." || part == "..") {
        bail!("path rules must be normalized before validation: {value}");
    }
    if matches!(rule, PathRule::Glob(_)) && value.contains("**") {
        bail!("recursive glob '**' is not supported; refuse ambiguous rules");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn baseline_policy_validates() {
        SandboxPolicy::a3s_bash_baseline().validate().unwrap();
    }

    #[test]
    fn rejects_wrong_version() {
        let mut policy = SandboxPolicy::a3s_bash_baseline();
        policy.version = 99;
        let error = policy.validate().unwrap_err().to_string();
        assert!(
            error.contains("unsupported sandbox policy version"),
            "{error}"
        );
    }

    #[test]
    fn rejects_network_allow_without_mediation_flag() {
        let mut policy = SandboxPolicy::a3s_bash_baseline();
        policy.network.allow.push(NetworkAllowRule {
            host: "example.com".into(),
            port: Some(443),
            path_prefix: None,
        });
        let error = policy.validate().unwrap_err().to_string();
        assert!(error.contains("mediated_network"), "{error}");
    }

    #[test]
    fn rejects_mediated_network_flag_without_allowlist() {
        let mut policy = SandboxPolicy::a3s_bash_baseline();
        policy.features.mediated_network = true;
        let error = policy.validate().unwrap_err().to_string();
        assert!(
            error.contains("empty") || error.contains("allowlist"),
            "{error}"
        );
    }

    #[test]
    fn mediated_network_document_validates_shape_but_backend_fails_closed() {
        let mut policy = SandboxPolicy::a3s_bash_baseline();
        policy.features.mediated_network = true;
        policy.network.allow.push(NetworkAllowRule {
            host: "example.com".into(),
            port: Some(443),
            path_prefix: Some("/v1".into()),
        });
        policy.validate().unwrap();
        let result =
            policy.validate_for_backend(crate::policy::BackendCapabilities::native_gate2());
        if cfg!(any(target_os = "macos", target_os = "linux", windows)) {
            result.unwrap();
        } else {
            let error = result.unwrap_err().to_string();
            assert!(
                error.contains("mediated_network") || error.contains("fail closed"),
                "{error}"
            );
        }
    }

    #[test]
    fn rejects_dotdot_in_path_rules() {
        let mut policy = SandboxPolicy::a3s_bash_baseline();
        policy
            .filesystem
            .allow_write
            .push(PathRule::Exact("foo/../bar".into()));
        let error = policy.validate().unwrap_err().to_string();
        assert!(error.contains("normalized"), "{error}");
    }

    #[test]
    fn rejects_recursive_glob() {
        let mut policy = SandboxPolicy::a3s_bash_baseline();
        policy
            .filesystem
            .deny_read
            .push(PathRule::Glob("**/secrets".into()));
        let error = policy.validate().unwrap_err().to_string();
        assert!(error.contains("**"), "{error}");
    }

    #[test]
    fn rejects_zero_timeout() {
        let mut policy = SandboxPolicy::a3s_bash_baseline();
        policy.resources.timeout_ms = 0;
        assert!(policy.validate().is_err());
    }
}
