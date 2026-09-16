//! Gate 6 session policy updates: refuse silent broadening.

use super::model::{SandboxPolicy, SessionWriteMode};
use anyhow::{bail, Result};

/// Options for [`crate::NativeSandbox::replace_policy`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PolicyUpdateOptions {
    /// When false (default), reject updates that enlarge the attack surface.
    pub allow_broadening: bool,
}

/// Return an error if `next` is strictly broader than `current`.
///
/// Narrowing (disabling mediation, removing allow rules, adding denies) is
/// always permitted. Broadening requires [`PolicyUpdateOptions::allow_broadening`].
pub fn ensure_policy_not_broader(current: &SandboxPolicy, next: &SandboxPolicy) -> Result<()> {
    if let Some(reason) = broadening_reason(current, next) {
        bail!("policy update broadens {reason}; set allow_broadening to opt in explicitly");
    }
    Ok(())
}

fn broadening_reason(current: &SandboxPolicy, next: &SandboxPolicy) -> Option<&'static str> {
    if !current.features.mediated_network && next.features.mediated_network {
        return Some("features.mediated_network");
    }
    if !current.features.mediated_socks && next.features.mediated_socks {
        return Some("features.mediated_socks");
    }
    if next
        .network
        .allow
        .iter()
        .any(|rule| !current.network.allow.contains(rule))
    {
        return Some("network.allow");
    }
    if next
        .sockets
        .allow_unix
        .iter()
        .any(|rule| !current.sockets.allow_unix.contains(rule))
    {
        return Some("sockets.allow_unix");
    }
    if next
        .filesystem
        .allow_read
        .iter()
        .any(|rule| !current.filesystem.allow_read.contains(rule))
    {
        return Some("filesystem.allow_read");
    }
    if next
        .filesystem
        .allow_write
        .iter()
        .any(|rule| !current.filesystem.allow_write.contains(rule))
    {
        return Some("filesystem.allow_write");
    }
    if current
        .filesystem
        .deny_read
        .iter()
        .any(|rule| !next.filesystem.deny_read.contains(rule))
    {
        return Some("filesystem.deny_read");
    }
    if current
        .filesystem
        .deny_write
        .iter()
        .any(|rule| !next.filesystem.deny_write.contains(rule))
    {
        return Some("filesystem.deny_write");
    }
    if next
        .filesystem
        .mounts
        .iter()
        .any(|mount| !current.filesystem.mounts.contains(mount))
    {
        return Some("filesystem.mounts");
    }
    if current.filesystem.session_write == SessionWriteMode::Ephemeral
        && next.filesystem.session_write == SessionWriteMode::Persistent
    {
        return Some("filesystem.session_write");
    }
    if next.resources.timeout_ms > current.resources.timeout_ms {
        return Some("resources.timeout_ms");
    }
    if next.resources.max_output_bytes > current.resources.max_output_bytes {
        return Some("resources.max_output_bytes");
    }
    if limit_raised_u32(
        current.resources.max_processes,
        next.resources.max_processes,
    ) {
        return Some("resources.max_processes");
    }
    if limit_raised_u64(
        current.resources.max_memory_bytes,
        next.resources.max_memory_bytes,
    ) {
        return Some("resources.max_memory_bytes");
    }
    if limit_raised_u32(
        current.resources.max_call_depth,
        next.resources.max_call_depth,
    ) {
        return Some("resources.max_call_depth");
    }
    None
}

fn limit_raised_u32(current: Option<u32>, next: Option<u32>) -> bool {
    match (current, next) {
        (None, Some(_)) => true, // unbounded → capped is narrower; wait
        // None means no OS quota requested. Adding a quota is narrowing.
        // Raising an existing quota is broadening. Removing a quota (Some→None) is broadening.
        (Some(_), None) => true,
        (Some(a), Some(b)) => b > a,
        (None, None) => false,
    }
}

fn limit_raised_u64(current: Option<u64>, next: Option<u64>) -> bool {
    match (current, next) {
        (Some(_), None) => true,
        (Some(a), Some(b)) => b > a,
        (None, None) | (None, Some(_)) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{NetworkAllowRule, PathRule};

    #[test]
    fn narrowing_mediation_is_allowed() {
        let mut current = SandboxPolicy::a3s_bash_baseline();
        current.features.mediated_network = true;
        current.network.allow.push(NetworkAllowRule {
            host: "api.example.com".into(),
            port: Some(443),
            path_prefix: None,
        });
        let next = SandboxPolicy::a3s_bash_baseline();
        ensure_policy_not_broader(&current, &next).unwrap();
    }

    #[test]
    fn enabling_socks_is_broadening() {
        let current = SandboxPolicy::a3s_bash_baseline();
        let mut next = SandboxPolicy::a3s_bash_baseline();
        next.features.mediated_socks = true;
        next.network.allow.push(NetworkAllowRule {
            host: "api.example.com".into(),
            port: Some(443),
            path_prefix: None,
        });
        let error = ensure_policy_not_broader(&current, &next)
            .unwrap_err()
            .to_string();
        assert!(error.contains("mediated_socks"), "{error}");
    }

    #[test]
    fn adding_unix_socket_allow_is_broadening() {
        let current = SandboxPolicy::a3s_bash_baseline();
        let mut next = SandboxPolicy::a3s_bash_baseline();
        next.sockets
            .allow_unix
            .push(PathRule::Exact("/tmp/x.sock".into()));
        let error = ensure_policy_not_broader(&current, &next)
            .unwrap_err()
            .to_string();
        assert!(error.contains("sockets.allow_unix"), "{error}");
    }

    #[test]
    fn raising_timeout_is_broadening() {
        let mut current = SandboxPolicy::a3s_bash_baseline();
        current.resources.timeout_ms = 1_000;
        let mut next = current.clone();
        next.resources.timeout_ms = 2_000;
        let error = ensure_policy_not_broader(&current, &next)
            .unwrap_err()
            .to_string();
        assert!(error.contains("timeout_ms"), "{error}");
    }

    #[test]
    fn removing_process_quota_is_broadening() {
        let mut current = SandboxPolicy::a3s_bash_baseline();
        current.resources.max_processes = Some(4);
        let mut next = current.clone();
        next.resources.max_processes = None;
        let error = ensure_policy_not_broader(&current, &next)
            .unwrap_err()
            .to_string();
        assert!(error.contains("max_processes"), "{error}");
    }
}
