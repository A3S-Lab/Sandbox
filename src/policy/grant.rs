//! Typed policy grants: the only sanctioned broadening path.
//!
//! A grant is a host-approved, subject-scoped policy widening (Gate 10 of the
//! optimization roadmap). The crate cannot verify user intent — that lives in
//! the prompting host — so the contract here is structural: grants are typed
//! objects, application is digest-pinned for lineage, the resulting policy is
//! the minimal widening for exactly the granted subject, and every
//! application is auditable. Everything else still refuses to broaden.

use super::model::{NetworkAllowRule, SandboxPolicy};
use anyhow::{bail, Context, Result};

/// One approved network subject: `host` plus an optional port pin.
///
/// Exact-string semantics only — the existing mediated decisions never alias
/// `localhost` with `127.0.0.1` or hostnames with literal IPs, and a grant
/// cannot widen that.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkGrant {
    pub host: String,
    pub port: Option<u16>,
}

impl NetworkGrant {
    pub fn new(host: impl Into<String>, port: Option<u16>) -> Result<Self> {
        let host = host.into();
        if host.is_empty() || host.contains(['/', '\\', ' ', '*', '?']) {
            bail!("invalid network grant host: {host:?}");
        }
        Ok(Self { host, port })
    }

    fn allow_rule(&self) -> NetworkAllowRule {
        NetworkAllowRule {
            host: self.host.clone(),
            port: self.port,
            path_prefix: None,
        }
    }
}

/// Compute the minimal widening of `policy` for `grant`.
///
/// Returns the new policy plus whether anything changed. On a deny-all
/// baseline this is also the sanctioned activation of `mediated_network`:
/// the default stays deny-all until a grant turns mediation on for exactly
/// one subject.
pub fn apply_network_grant_to_policy(
    policy: &SandboxPolicy,
    grant: &NetworkGrant,
) -> Result<(SandboxPolicy, bool)> {
    if policy
        .network
        .allow
        .iter()
        .any(|rule| rule.host.eq_ignore_ascii_case(&grant.host) && rule.port == grant.port)
    {
        return Ok((policy.clone(), false));
    }
    let mut widened = policy.clone();
    widened.features.mediated_network = true;
    widened.network.allow.push(grant.allow_rule());
    widened.validate().context("granted policy must validate")?;
    Ok((widened, true))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{decide_mediated_connect, AccessDecision};

    fn grant(host: &str, port: Option<u16>) -> NetworkGrant {
        NetworkGrant::new(host, port).unwrap()
    }

    #[test]
    fn apply_to_deny_all_baseline_activates_mediation_for_exactly_that_origin() {
        let policy = SandboxPolicy::a3s_bash_baseline();
        let (widened, changed) =
            apply_network_grant_to_policy(&policy, &grant("api.example.com", Some(443))).unwrap();
        assert!(changed);
        assert!(widened.features.mediated_network);
        assert_eq!(widened.network.allow.len(), 1);
        assert_eq!(widened.network.allow[0].host, "api.example.com");
        assert_eq!(widened.network.allow[0].port, Some(443));
        assert_eq!(widened.network.allow[0].path_prefix, None);
        widened.validate().unwrap();
    }

    #[test]
    fn apply_appends_to_existing_mediated_policy_without_clobbering() {
        let mut policy = SandboxPolicy::a3s_bash_baseline();
        policy.features.mediated_network = true;
        policy.network.allow.push(NetworkAllowRule {
            host: "existing.example.com".into(),
            port: Some(443),
            path_prefix: None,
        });
        let (widened, changed) =
            apply_network_grant_to_policy(&policy, &grant("api.example.com", Some(443))).unwrap();
        assert!(changed);
        assert_eq!(widened.network.allow.len(), 2);
        assert_eq!(widened.network.allow[0].host, "existing.example.com");
    }

    #[test]
    fn apply_is_idempotent_for_identical_subject() {
        let policy = SandboxPolicy::a3s_bash_baseline();
        let (once, changed) =
            apply_network_grant_to_policy(&policy, &grant("api.example.com", Some(443))).unwrap();
        assert!(changed);
        let (twice, changed_again) =
            apply_network_grant_to_policy(&once, &grant("API.example.COM", Some(443))).unwrap();
        assert!(!changed_again, "case-insensitive duplicate must be a no-op");
        assert_eq!(once, twice);
    }

    #[test]
    fn apply_refuses_invalid_or_wildcard_hosts() {
        for host in ["", "a/b", "a b", "a\\b", "*", "api.*.com", "*.example.com"] {
            assert!(
                NetworkGrant::new(host, Some(443)).is_err(),
                "host {host:?} must refuse as a grant subject"
            );
        }
        // A valid host still applies through the same constructor.
        assert!(NetworkGrant::new("api.example.com", Some(443)).is_ok());
    }

    #[test]
    fn grant_cannot_alias_localhost_to_loopback_ip() {
        let policy = SandboxPolicy::a3s_bash_baseline();
        let (widened, _) =
            apply_network_grant_to_policy(&policy, &grant("localhost", Some(8443))).unwrap();
        assert_eq!(
            decide_mediated_connect(&widened, "127.0.0.1", 8443),
            AccessDecision::Deny,
            "a localhost grant must not authorize the literal loopback IP"
        );
    }

    #[test]
    fn port_pinned_grant_widens_only_that_port() {
        let policy = SandboxPolicy::a3s_bash_baseline();
        let (widened, _) =
            apply_network_grant_to_policy(&policy, &grant("api.example.com", Some(443))).unwrap();
        assert_eq!(
            decide_mediated_connect(&widened, "api.example.com", 443),
            AccessDecision::Allow
        );
        assert_eq!(
            decide_mediated_connect(&widened, "api.example.com", 8443),
            AccessDecision::Deny
        );
        assert_eq!(
            decide_mediated_connect(&widened, "other.example.com", 443),
            AccessDecision::Deny
        );
    }
}
