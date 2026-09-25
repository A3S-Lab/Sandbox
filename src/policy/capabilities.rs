//! Backend capability declarations. Missing capabilities fail closed.

/// What the compiled backend can actually enforce.
///
/// Policy features that exceed these capabilities must be rejected before
/// launch. Silent degradation is forbidden.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackendCapabilities {
    pub filesystem_path_policy: bool,
    pub filesystem_readonly_mounts: bool,
    pub filesystem_ephemeral_writes: bool,
    pub network_deny_all: bool,
    pub mediated_http: bool,
    pub mediated_socks: bool,
    pub unix_socket_allowlist: bool,
    pub resource_timeout: bool,
    pub resource_output_limit: bool,
    pub resource_memory_limit: bool,
    pub resource_process_limit: bool,
}

impl BackendCapabilities {
    /// Capabilities after Gate 3 typed mounts plus Gate 2 budgets.
    ///
    /// Ephemeral session writes: Linux bwrap `--tmpfs` only.
    /// Mediated HTTP / SOCKS: macOS Seatbelt loopback-to-mediator fence;
    /// Linux netns + host Unix mediators + in-guest TCP→Unix relays (HTTP and
    /// SOCKS5, live wire proofs under `--unshare-net`);
    /// Windows AppContainer inherited named-pipe CONNECT (HTTP).
    /// Windows SOCKS / non-macOS unix-socket allowlists stay fail-closed.
    pub fn native_gate2() -> Self {
        Self {
            filesystem_path_policy: true,
            filesystem_readonly_mounts: true,
            filesystem_ephemeral_writes: cfg!(target_os = "linux"),
            network_deny_all: true,
            mediated_http: cfg!(any(target_os = "macos", target_os = "linux", windows)),
            // SOCKS5: macOS Seatbelt loopback fence; Linux netns + Unix
            // SOCKS mediator + guest TCP relay (same fence family as HTTP).
            mediated_socks: cfg!(any(target_os = "macos", target_os = "linux")),
            unix_socket_allowlist: cfg!(target_os = "macos"),
            resource_timeout: true,
            resource_output_limit: true,
            resource_memory_limit: cfg!(any(windows, target_os = "linux")),
            // Linux claims pids quotas through delegated cgroup v2; the
            // runtime probe at construction fails closed without one.
            resource_process_limit: cfg!(any(windows, target_os = "linux")),
        }
    }

    /// Alias used by compile/execute paths for the current shipped backend.
    pub fn native_gate1() -> Self {
        Self::native_gate2()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::SandboxPolicy;

    #[test]
    fn memory_limit_without_backend_support_fails_closed() {
        let mut policy = SandboxPolicy::a3s_bash_baseline();
        policy.resources.max_memory_bytes = Some(64 * 1024 * 1024);
        let restricted = BackendCapabilities {
            resource_memory_limit: false,
            ..BackendCapabilities::native_gate2()
        };
        let error = policy
            .validate_for_backend(restricted)
            .unwrap_err()
            .to_string();
        assert!(error.contains("memory limit"), "{error}");
    }

    #[test]
    fn gate2_backend_enforces_optional_memory_and_process_limits() {
        let caps = BackendCapabilities::native_gate2();
        assert_eq!(
            caps.resource_memory_limit,
            cfg!(any(windows, target_os = "linux"))
        );
        assert_eq!(
            caps.resource_process_limit,
            cfg!(any(windows, target_os = "linux"))
        );

        let mut policy = SandboxPolicy::a3s_bash_baseline();
        policy.resources.max_memory_bytes = Some(32 * 1024 * 1024);
        if caps.resource_memory_limit {
            policy.validate_for_backend(caps).unwrap();
        } else {
            let error = policy.validate_for_backend(caps).unwrap_err().to_string();
            assert!(error.contains("memory limit"), "{error}");
        }

        policy.resources.max_memory_bytes = None;
        policy.resources.max_processes = Some(16);
        if caps.resource_process_limit {
            policy.validate_for_backend(caps).unwrap();
        } else {
            let error = policy.validate_for_backend(caps).unwrap_err().to_string();
            assert!(error.contains("process limit"), "{error}");
        }
    }

    #[test]
    fn gate5_mediated_socks_capability_matches_platform_fence() {
        let caps = BackendCapabilities::native_gate2();
        assert_eq!(
            caps.mediated_socks,
            cfg!(any(target_os = "macos", target_os = "linux"))
        );
        assert!(caps.network_deny_all);
    }

    #[test]
    fn policy_exceeding_backend_capabilities_fails_closed() {
        let mut policy = SandboxPolicy::a3s_bash_baseline();
        policy.features.mediated_socks = true;
        policy.network.allow.push(crate::policy::NetworkAllowRule {
            host: "api.example.com".into(),
            port: Some(443),
            path_prefix: None,
        });
        let restricted = BackendCapabilities {
            mediated_socks: false,
            ..BackendCapabilities::native_gate2()
        };
        let error = policy
            .validate_for_backend(restricted)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("mediated_socks") || error.contains("fail closed"),
            "{error}"
        );
    }

    #[test]
    fn gate4_mediated_http_capability_matches_platform_fence() {
        let caps = BackendCapabilities::native_gate2();
        assert_eq!(
            caps.mediated_http,
            cfg!(any(target_os = "macos", target_os = "linux", windows))
        );
    }
}
