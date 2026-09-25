//! Versioned sandbox policy: typed model, normalization, decisions, digests.
//!
//! Gate 1: backends compile [`EnforcedPolicy`] only from a validated
//! [`SandboxPolicy`] via [`EnforcedPolicy::compile`]. Platform modules enforce
//! the compiled view; they do not invent broader permissions.

mod capabilities;
mod decide;
mod digest;
mod enforced;
pub(crate) use enforced::secret_env_name_is_reserved;
mod mediate;
mod model;
mod normalize;
pub(crate) mod resources;
mod update;

#[cfg(test)]
mod gate1_integration;
#[cfg(test)]
mod gate3_integration;
#[cfg(test)]
mod gate4_integration;
#[cfg(test)]
mod gate5_integration;
#[cfg(test)]
mod gate5_linux_bridge;
#[cfg(test)]
mod gate5_windows_bridge;
#[cfg(test)]
mod gate6_integration;
#[cfg(test)]
mod gate7_fuzz;
#[cfg(test)]
mod gate7_integration;
#[cfg(test)]
mod gate7_release_invariants;

pub use capabilities::BackendCapabilities;
pub use decide::{decide_network, decide_read, decide_write, AccessDecision};
pub use digest::policy_digest;
pub use mediate::{
    decide_mediated_connect, decide_mediated_http, decide_mediated_socks,
    matching_secret_injections, MediatedHttpRequest,
};
pub use model::{
    FeatureFlags, FilesystemMount, FilesystemRules, MountMode, NetworkAllowRule, NetworkDefault,
    NetworkRules, PathRule, ResourceLimits, SandboxPolicy, SecretHeaderInjection, SessionWriteMode,
    SocketRules, POLICY_VERSION,
};
pub use normalize::{normalize_policy_path, NormalizedPath};
pub use resources::ResolvedResourceBudget;
pub use update::{ensure_policy_not_broader, PolicyUpdateOptions};

pub use enforced::{
    hard_link_count, hard_link_count_for_open_file, is_protected_workspace_path, sensitive_paths,
    should_skip_workspace_scan_directory, workspace_credential_hardlink_aliases,
    workspace_hardlink_paths, workspace_sensitive_paths, PROTECTED_WORKSPACE_DIRECTORIES,
    PROTECTED_WORKSPACE_FILES,
};

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) use enforced::path_ancestors;
#[cfg(any(target_os = "linux", windows))]
pub(crate) use enforced::requires_directory_placeholder;
pub(crate) use enforced::{resolve_executable, EnforcedPolicy};
#[cfg(test)]
mod gate8_integration;
