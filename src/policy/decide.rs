//! Platform-neutral allow/deny decisions for a [`SandboxPolicy`].

use super::model::{NetworkDefault, PathRule, SandboxPolicy};
use super::normalize::NormalizedPath;

/// Decision returned by the policy engine. Backends may only enforce Allow or
/// Deny; they must not invent a third "best effort allow" state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessDecision {
    Allow,
    Deny,
}

/// Read decision. Deny-read wins over allow-read. Read-only mounts grant
/// read when neither deny nor allow matched earlier. If nothing matches, deny.
pub fn decide_read(policy: &SandboxPolicy, path: &NormalizedPath) -> AccessDecision {
    if matches_any(&policy.filesystem.deny_read, path) {
        return AccessDecision::Deny;
    }
    if matches_any(&policy.filesystem.allow_read, path) {
        return AccessDecision::Allow;
    }
    if policy
        .filesystem
        .mounts
        .iter()
        .any(|mount| rule_matches(&mount.root, path.as_str()))
    {
        return AccessDecision::Allow;
    }
    AccessDecision::Deny
}

/// Write decision. Write exceptions win over deny-write. Deny-write wins over
/// allow-write. Read-only mounts deny writes. ReadWrite/Scratch mounts allow
/// writes. If nothing matches, deny.
pub fn decide_write(policy: &SandboxPolicy, path: &NormalizedPath) -> AccessDecision {
    use super::model::MountMode;
    if matches_any(&policy.filesystem.write_exceptions, path) {
        return AccessDecision::Allow;
    }
    if matches_any(&policy.filesystem.deny_write, path) {
        return AccessDecision::Deny;
    }
    if policy.filesystem.mounts.iter().any(|mount| {
        matches!(mount.mode, MountMode::ReadOnly) && rule_matches(&mount.root, path.as_str())
    }) {
        return AccessDecision::Deny;
    }
    if matches_any(&policy.filesystem.allow_write, path) {
        return AccessDecision::Allow;
    }
    if policy.filesystem.mounts.iter().any(|mount| {
        matches!(mount.mode, MountMode::ReadWrite | MountMode::Scratch)
            && rule_matches(&mount.root, path.as_str())
    }) {
        return AccessDecision::Allow;
    }
    AccessDecision::Deny
}

/// Network decision for Gate 1: always deny unless a future gate adds
/// enforceable allow rules (which [`SandboxPolicy::validate`] currently rejects).
pub fn decide_network(policy: &SandboxPolicy) -> AccessDecision {
    match policy.network.default {
        NetworkDefault::DenyAll => AccessDecision::Deny,
    }
}

fn matches_any(rules: &[PathRule], path: &NormalizedPath) -> bool {
    rules.iter().any(|rule| rule_matches(rule, path.as_str()))
}

fn rule_matches(rule: &PathRule, path: &str) -> bool {
    match rule {
        PathRule::Exact(exact) => path == exact || path.starts_with(&format!("{exact}/")),
        PathRule::Glob(pattern) => glob_match(pattern, path),
    }
}

fn glob_match(pattern: &str, path: &str) -> bool {
    let pattern_parts: Vec<&str> = pattern.split('/').collect();
    let path_parts: Vec<&str> = path.split('/').collect();
    if pattern_parts.len() != path_parts.len() {
        return false;
    }
    pattern_parts
        .iter()
        .zip(path_parts.iter())
        .all(|(pat, part)| wildcard_match(pat, part))
}

fn wildcard_match(pattern: &str, value: &str) -> bool {
    let pattern = pattern.as_bytes();
    let value = value.as_bytes();
    let mut pi = 0;
    let mut vi = 0;
    let mut star = None::<(usize, usize)>;

    while vi < value.len() {
        if pi < pattern.len() && (pattern[pi] == b'?' || pattern[pi] == value[vi]) {
            pi += 1;
            vi += 1;
        } else if pi < pattern.len() && pattern[pi] == b'*' {
            star = Some((pi, vi));
            pi += 1;
        } else if let Some((star_pi, star_vi)) = star {
            pi = star_pi + 1;
            vi = star_vi + 1;
            star = Some((star_pi, vi));
        } else {
            return false;
        }
    }

    while pi < pattern.len() && pattern[pi] == b'*' {
        pi += 1;
    }
    pi == pattern.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::normalize::normalize_policy_path;
    use crate::policy::{FilesystemRules, PathRule, SandboxPolicy};

    fn policy_with_fs(filesystem: FilesystemRules) -> SandboxPolicy {
        SandboxPolicy {
            filesystem,
            ..SandboxPolicy::a3s_bash_baseline()
        }
    }

    #[test]
    fn deny_read_wins_over_allow_read() {
        let policy = policy_with_fs(FilesystemRules {
            allow_read: vec![PathRule::Exact("workspace".into())],
            deny_read: vec![PathRule::Exact("workspace/.env".into())],
            ..FilesystemRules::default()
        });
        let allowed = normalize_policy_path("workspace/src/main.rs").unwrap();
        let denied = normalize_policy_path("workspace/.env").unwrap();
        assert_eq!(decide_read(&policy, &allowed), AccessDecision::Allow);
        assert_eq!(decide_read(&policy, &denied), AccessDecision::Deny);
    }

    #[test]
    fn write_exception_carves_out_denied_ancestor() {
        let policy = policy_with_fs(FilesystemRules {
            allow_write: vec![PathRule::Exact("workspace".into())],
            deny_write: vec![PathRule::Exact("workspace/.a3s".into())],
            write_exceptions: vec![PathRule::Exact("workspace/.a3s/loops".into())],
            ..FilesystemRules::default()
        });
        let loops = normalize_policy_path("workspace/.a3s/loops/goal/STATE.md").unwrap();
        let other = normalize_policy_path("workspace/.a3s/policy.acl").unwrap();
        let src = normalize_policy_path("workspace/src/lib.rs").unwrap();
        assert_eq!(decide_write(&policy, &loops), AccessDecision::Allow);
        assert_eq!(decide_write(&policy, &other), AccessDecision::Deny);
        assert_eq!(decide_write(&policy, &src), AccessDecision::Allow);
    }

    #[test]
    fn unmatched_paths_fail_closed() {
        let policy = SandboxPolicy::a3s_bash_baseline();
        let path = normalize_policy_path("anywhere/file").unwrap();
        assert_eq!(decide_read(&policy, &path), AccessDecision::Deny);
        assert_eq!(decide_write(&policy, &path), AccessDecision::Deny);
    }

    #[test]
    fn network_default_is_deny_all() {
        let policy = SandboxPolicy::a3s_bash_baseline();
        assert_eq!(decide_network(&policy), AccessDecision::Deny);
    }

    #[test]
    fn glob_rules_match_single_segment_wildcards() {
        let policy = policy_with_fs(FilesystemRules {
            deny_read: vec![PathRule::Glob("workspace/.env*".into())],
            allow_read: vec![PathRule::Exact("workspace".into())],
            ..FilesystemRules::default()
        });
        let secret = normalize_policy_path("workspace/.env.local").unwrap();
        let ok = normalize_policy_path("workspace/readme.md").unwrap();
        assert_eq!(decide_read(&policy, &secret), AccessDecision::Deny);
        assert_eq!(decide_read(&policy, &ok), AccessDecision::Allow);
    }

    #[test]
    fn fixture_decisions_are_separator_agnostic() {
        let policy = policy_with_fs(FilesystemRules {
            allow_write: vec![PathRule::Exact("workspace".into())],
            deny_write: vec![PathRule::Exact("workspace/.git".into())],
            ..FilesystemRules::default()
        });
        let unix = normalize_policy_path("workspace/.git/config").unwrap();
        let mixed =
            normalize_policy_path(std::path::Path::new("workspace").join(".git/HEAD")).unwrap();
        assert_eq!(decide_write(&policy, &unix), AccessDecision::Deny);
        assert_eq!(decide_write(&policy, &mixed), AccessDecision::Deny);
    }
}
