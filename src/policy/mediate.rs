//! Gate 4 HTTP(S) allowlist matching and mediator contracts.
//!
//! The native backend keeps `mediated_http: false` until a host-supervised
//! mediator is fenced by the OS. These helpers define the decision surface
//! that the future mediator must enforce without silent broadening.

use super::model::{NetworkAllowRule, SandboxPolicy};
use super::AccessDecision;

/// Request shape the mediator evaluates. No DNS resolution here—callers pass
/// the authority they intend to contact after policy-normalized hostnames.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediatedHttpRequest {
    pub host: String,
    pub port: u16,
    pub path: String,
}

/// Decide whether a TCP CONNECT tunnel to `host:port` is allowed.
///
/// CONNECT cannot observe HTTPS request paths, so path-prefixed allow rules
/// do not authorize tunnels. Only host/port rules with `path_prefix: None`
/// may allow CONNECT. Everything else fails closed.
pub fn decide_mediated_connect(policy: &SandboxPolicy, host: &str, port: u16) -> AccessDecision {
    if !policy.features.mediated_network {
        return AccessDecision::Deny;
    }
    decide_origin_tunnel(policy, host, port)
}

/// Decide whether a SOCKS5 CONNECT to `host:port` is allowed.
///
/// Same origin allowlist as HTTP CONNECT: path-prefixed rules never authorize
/// opaque TCP tunnels. Requires `features.mediated_socks`.
pub fn decide_mediated_socks(policy: &SandboxPolicy, host: &str, port: u16) -> AccessDecision {
    if !policy.features.mediated_socks {
        return AccessDecision::Deny;
    }
    decide_origin_tunnel(policy, host, port)
}

/// Shared origin allowlist for opaque TCP tunnels (HTTP CONNECT / SOCKS5).
fn decide_origin_tunnel(policy: &SandboxPolicy, host: &str, port: u16) -> AccessDecision {
    if policy.network.allow.is_empty() {
        return AccessDecision::Deny;
    }
    if policy.network.allow.iter().any(|rule| {
        rule.path_prefix.is_none()
            && host_eq(&rule.host, host)
            && rule.port.map(|allowed| allowed == port).unwrap_or(true)
    }) {
        AccessDecision::Allow
    } else {
        AccessDecision::Deny
    }
}

/// Decide whether a mediated HTTP request matches the policy allowlist.
///
/// Deny-all remains the default. Matching requires `features.mediated_network`
/// and at least one allow rule. Path matching is prefix-based; missing
/// `path_prefix` allows any path on that origin.
pub fn decide_mediated_http(
    policy: &SandboxPolicy,
    request: &MediatedHttpRequest,
) -> AccessDecision {
    if !policy.features.mediated_network || policy.network.allow.is_empty() {
        return AccessDecision::Deny;
    }
    if policy
        .network
        .allow
        .iter()
        .any(|rule| rule_matches(rule, request))
    {
        AccessDecision::Allow
    } else {
        AccessDecision::Deny
    }
}

fn rule_matches(rule: &NetworkAllowRule, request: &MediatedHttpRequest) -> bool {
    if !host_eq(&rule.host, &request.host) {
        return false;
    }
    if let Some(port) = rule.port {
        if port != request.port {
            return false;
        }
    }
    match &rule.path_prefix {
        None => true,
        Some(prefix) => request.path == *prefix || request.path.starts_with(&format!("{prefix}/")),
    }
}

fn host_eq(expected: &str, actual: &str) -> bool {
    expected.eq_ignore_ascii_case(actual)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::SandboxPolicy;

    fn mediated_policy(rules: Vec<NetworkAllowRule>) -> SandboxPolicy {
        let mut policy = SandboxPolicy::a3s_bash_baseline();
        policy.features.mediated_network = true;
        policy.network.allow = rules;
        policy
    }

    #[test]
    fn deny_when_mediation_flag_off() {
        let policy = SandboxPolicy::a3s_bash_baseline();
        let decision = decide_mediated_http(
            &policy,
            &MediatedHttpRequest {
                host: "example.com".into(),
                port: 443,
                path: "/".into(),
            },
        );
        assert_eq!(decision, AccessDecision::Deny);
    }

    #[test]
    fn allow_exact_origin_and_path_prefix() {
        let policy = mediated_policy(vec![NetworkAllowRule {
            host: "api.example.com".into(),
            port: Some(443),
            path_prefix: Some("/v1".into()),
        }]);
        assert_eq!(
            decide_mediated_http(
                &policy,
                &MediatedHttpRequest {
                    host: "API.example.com".into(),
                    port: 443,
                    path: "/v1/models".into(),
                }
            ),
            AccessDecision::Allow
        );
        assert_eq!(
            decide_mediated_http(
                &policy,
                &MediatedHttpRequest {
                    host: "api.example.com".into(),
                    port: 443,
                    path: "/v2".into(),
                }
            ),
            AccessDecision::Deny
        );
        assert_eq!(
            decide_mediated_http(
                &policy,
                &MediatedHttpRequest {
                    host: "api.example.com".into(),
                    port: 80,
                    path: "/v1".into(),
                }
            ),
            AccessDecision::Deny
        );
        assert_eq!(
            decide_mediated_http(
                &policy,
                &MediatedHttpRequest {
                    host: "api.example.com".into(),
                    port: 443,
                    path: "/v10".into(),
                }
            ),
            AccessDecision::Deny
        );
    }

    #[test]
    fn missing_path_prefix_allows_any_path_on_origin() {
        let policy = mediated_policy(vec![NetworkAllowRule {
            host: "example.com".into(),
            port: Some(443),
            path_prefix: None,
        }]);
        assert_eq!(
            decide_mediated_http(
                &policy,
                &MediatedHttpRequest {
                    host: "example.com".into(),
                    port: 443,
                    path: "/anything".into(),
                }
            ),
            AccessDecision::Allow
        );
    }

    #[test]
    fn connect_requires_pathless_allow_rule() {
        let path_limited = mediated_policy(vec![NetworkAllowRule {
            host: "api.example.com".into(),
            port: Some(443),
            path_prefix: Some("/v1".into()),
        }]);
        assert_eq!(
            decide_mediated_connect(&path_limited, "api.example.com", 443),
            AccessDecision::Deny
        );

        let origin = mediated_policy(vec![NetworkAllowRule {
            host: "api.example.com".into(),
            port: Some(443),
            path_prefix: None,
        }]);
        assert_eq!(
            decide_mediated_connect(&origin, "api.example.com", 443),
            AccessDecision::Allow
        );
        assert_eq!(
            decide_mediated_connect(&origin, "evil.example.com", 443),
            AccessDecision::Deny
        );
    }

    #[test]
    fn socks_requires_mediated_socks_flag_and_pathless_rule() {
        let mut origin = SandboxPolicy::a3s_bash_baseline();
        origin.features.mediated_network = true;
        origin.network.allow.push(NetworkAllowRule {
            host: "api.example.com".into(),
            port: Some(443),
            path_prefix: None,
        });
        assert_eq!(
            decide_mediated_socks(&origin, "api.example.com", 443),
            AccessDecision::Deny,
            "HTTP mediation alone must not authorize SOCKS"
        );

        origin.features.mediated_socks = true;
        assert_eq!(
            decide_mediated_socks(&origin, "api.example.com", 443),
            AccessDecision::Allow
        );

        let mut path_limited = origin.clone();
        path_limited.network.allow[0].path_prefix = Some("/v1".into());
        assert_eq!(
            decide_mediated_socks(&path_limited, "api.example.com", 443),
            AccessDecision::Deny
        );
    }
}
