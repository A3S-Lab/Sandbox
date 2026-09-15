//! Canonical, redacted policy digests for audit and replay.

use super::model::{NetworkAllowRule, PathRule, SandboxPolicy};
use sha2::{Digest, Sha256};

/// Stable hex digest of a validated policy's canonical form.
///
/// The digest redacts nothing sensitive beyond omitting runtime workspace
/// absolutes: callers should place portable relative rules in digests they
/// intend to compare across hosts. Absolute tool roots that appear in an
/// enforced profile are hashed as provided after canonical sort order.
pub fn policy_digest(policy: &SandboxPolicy) -> String {
    let canonical = policy.canonicalized();
    let payload = canonical_payload(&canonical);
    let hash = Sha256::digest(payload.as_bytes());
    hex_encode(&hash)
}

fn canonical_payload(policy: &SandboxPolicy) -> String {
    let mut out = String::new();
    out.push_str(&format!("version={}\n", policy.version));
    append_path_section(&mut out, "allow_read", &policy.filesystem.allow_read);
    append_path_section(&mut out, "deny_read", &policy.filesystem.deny_read);
    append_path_section(&mut out, "allow_write", &policy.filesystem.allow_write);
    append_path_section(&mut out, "deny_write", &policy.filesystem.deny_write);
    append_path_section(
        &mut out,
        "write_exceptions",
        &policy.filesystem.write_exceptions,
    );
    out.push_str("mounts=[");
    for (index, mount) in policy.filesystem.mounts.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push_str(&format!("{:?}:", mount.mode));
        match &mount.root {
            PathRule::Exact(value) => {
                out.push_str("exact:");
                out.push_str(value);
            }
            PathRule::Glob(value) => {
                out.push_str("glob:");
                out.push_str(value);
            }
        }
    }
    out.push_str("]\n");
    out.push_str(&format!(
        "session_write={:?}\n",
        policy.filesystem.session_write
    ));
    out.push_str(&format!("network.default={:?}\n", policy.network.default));
    append_network_section(&mut out, &policy.network.allow);
    append_path_section(&mut out, "allow_unix", &policy.sockets.allow_unix);
    out.push_str(&format!(
        "resources.timeout_ms={}\nresources.max_output_bytes={}\n",
        policy.resources.timeout_ms, policy.resources.max_output_bytes
    ));
    out.push_str(&format!(
        "resources.max_call_depth={:?}\nresources.max_processes={:?}\nresources.max_memory_bytes={:?}\n",
        policy.resources.max_call_depth,
        policy.resources.max_processes,
        policy.resources.max_memory_bytes
    ));
    out.push_str(&format!(
        "features.mediated_network={}\nfeatures.mediated_socks={}\n",
        policy.features.mediated_network, policy.features.mediated_socks
    ));
    out
}

fn append_path_section(out: &mut String, name: &str, rules: &[PathRule]) {
    out.push_str(name);
    out.push('=');
    if rules.is_empty() {
        out.push_str("[]\n");
        return;
    }
    out.push('[');
    for (index, rule) in rules.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        match rule {
            PathRule::Exact(value) => {
                out.push_str("exact:");
                out.push_str(value);
            }
            PathRule::Glob(value) => {
                out.push_str("glob:");
                out.push_str(value);
            }
        }
    }
    out.push_str("]\n");
}

fn append_network_section(out: &mut String, rules: &[NetworkAllowRule]) {
    out.push_str("network.allow=");
    if rules.is_empty() {
        out.push_str("[]\n");
        return;
    }
    out.push('[');
    for (index, rule) in rules.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push_str(&rule.host);
        out.push(':');
        match rule.port {
            Some(port) => out.push_str(&port.to_string()),
            None => out.push('*'),
        }
        out.push(':');
        match &rule.path_prefix {
            Some(prefix) => out.push_str(prefix),
            None => out.push('*'),
        }
    }
    out.push_str("]\n");
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0xf) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::PathRule;

    #[test]
    fn digest_is_stable_under_rule_reordering() {
        let mut left = SandboxPolicy::a3s_bash_baseline();
        left.filesystem.allow_write = vec![
            PathRule::Exact("workspace".into()),
            PathRule::Exact("scratch".into()),
        ];
        let mut right = SandboxPolicy::a3s_bash_baseline();
        right.filesystem.allow_write = vec![
            PathRule::Exact("scratch".into()),
            PathRule::Exact("workspace".into()),
        ];
        assert_eq!(policy_digest(&left), policy_digest(&right));
    }

    #[test]
    fn digest_changes_when_rules_change() {
        let baseline = SandboxPolicy::a3s_bash_baseline();
        let mut changed = baseline.clone();
        changed
            .filesystem
            .deny_write
            .push(PathRule::Exact("workspace/.git".into()));
        assert_ne!(policy_digest(&baseline), policy_digest(&changed));
    }

    #[test]
    fn baseline_digest_is_hex_sha256_length() {
        let digest = policy_digest(&SandboxPolicy::a3s_bash_baseline());
        assert_eq!(digest.len(), 64);
        assert!(digest.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
