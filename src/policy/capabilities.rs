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
    pub resource_cpu_limit: bool,
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
            // CPU quotas have exactly one honest locus: cgroup v2 cpu.max.
            resource_cpu_limit: cfg!(target_os = "linux"),
        }
    }

    /// Alias used by compile/execute paths for the current shipped backend.
    pub fn native_gate1() -> Self {
        Self::native_gate2()
    }
}

/// One row of the per-platform claim matrix — the single source of truth
/// rendered by `a3s-sandbox matrix` and asserted against the docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapabilityMatrixRow {
    pub surface: &'static str,
    pub macos: bool,
    pub linux: bool,
    pub windows: bool,
}

/// The claim matrix, compiled from the same constants as
/// [`BackendCapabilities::native_gate2`]. Docs embed the rendered table
/// between sentinels; tests fail when either side drifts.
pub fn capability_matrix() -> Vec<CapabilityMatrixRow> {
    vec![
        CapabilityMatrixRow {
            surface: "filesystem_path_policy",
            macos: true,
            linux: true,
            windows: true,
        },
        CapabilityMatrixRow {
            surface: "filesystem_readonly_mounts",
            macos: true,
            linux: true,
            windows: true,
        },
        CapabilityMatrixRow {
            surface: "filesystem_ephemeral_writes",
            macos: false,
            linux: true,
            windows: false,
        },
        CapabilityMatrixRow {
            surface: "network_deny_all",
            macos: true,
            linux: true,
            windows: true,
        },
        CapabilityMatrixRow {
            surface: "mediated_http",
            macos: true,
            linux: true,
            windows: true,
        },
        CapabilityMatrixRow {
            surface: "mediated_socks",
            macos: true,
            linux: true,
            windows: false,
        },
        CapabilityMatrixRow {
            surface: "unix_socket_allowlist",
            macos: true,
            linux: false,
            windows: false,
        },
        CapabilityMatrixRow {
            surface: "resource_timeout",
            macos: true,
            linux: true,
            windows: true,
        },
        CapabilityMatrixRow {
            surface: "resource_output_limit",
            macos: true,
            linux: true,
            windows: true,
        },
        CapabilityMatrixRow {
            surface: "resource_memory_limit",
            macos: false,
            linux: true,
            windows: true,
        },
        CapabilityMatrixRow {
            surface: "resource_process_limit",
            macos: false,
            linux: true,
            windows: true,
        },
        CapabilityMatrixRow {
            surface: "resource_cpu_limit",
            macos: false,
            linux: true,
            windows: false,
        },
    ]
}

/// Render the matrix as the markdown block the docs embed.
pub fn capability_matrix_markdown() -> String {
    let cell = |claimed: bool| if claimed { "claimed" } else { "fail-closed" };
    let mut out =
        String::from("| Surface | macOS | Linux | Windows |\n| --- | --- | --- | --- |\n");
    for row in capability_matrix() {
        out.push_str(&format!(
            "| {} | {} | {} | {} |\n",
            row.surface,
            cell(row.macos),
            cell(row.linux),
            cell(row.windows)
        ));
    }
    out.push_str(
        "\n`resource_process_limit` on Linux rides a runtime cgroup-delegation probe; \
         construction fails closed without one.\n",
    );
    out
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

    #[test]
    fn gate13_matrix_rows_match_this_platforms_capabilities() {
        let caps = BackendCapabilities::native_gate2();
        let field = |surface: &str| match surface {
            "filesystem_path_policy" => caps.filesystem_path_policy,
            "filesystem_readonly_mounts" => caps.filesystem_readonly_mounts,
            "filesystem_ephemeral_writes" => caps.filesystem_ephemeral_writes,
            "network_deny_all" => caps.network_deny_all,
            "mediated_http" => caps.mediated_http,
            "mediated_socks" => caps.mediated_socks,
            "unix_socket_allowlist" => caps.unix_socket_allowlist,
            "resource_timeout" => caps.resource_timeout,
            "resource_output_limit" => caps.resource_output_limit,
            "resource_memory_limit" => caps.resource_memory_limit,
            "resource_process_limit" => caps.resource_process_limit,
            "resource_cpu_limit" => caps.resource_cpu_limit,
            other => panic!("matrix row {other} has no capability field"),
        };
        for row in capability_matrix() {
            let here = if cfg!(target_os = "macos") {
                row.macos
            } else if cfg!(target_os = "linux") {
                row.linux
            } else {
                row.windows
            };
            assert_eq!(
                here,
                field(row.surface),
                "matrix row {} drifts from native_gate2 on this platform",
                row.surface
            );
        }
    }

    #[test]
    fn gate13_threat_model_embeds_the_generated_capability_matrix() {
        let doc = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/THREAT_MODEL.md"))
            .expect("THREAT_MODEL.md is part of the crate");
        let begin = "<!-- capability-matrix:begin";
        let end = "<!-- capability-matrix:end -->";
        let Some(start) = doc.find(begin) else {
            panic!("THREAT_MODEL.md lost the capability-matrix begin sentinel");
        };
        let Some(stop) = doc[start..].find(end) else {
            panic!("THREAT_MODEL.md lost the capability-matrix end sentinel");
        };
        let content_start = doc[start..]
            .find('\n')
            .map(|offset| start + offset + 1)
            .unwrap_or(start);
        let embedded = doc[content_start..start + stop]
            .trim()
            .replace("\r\n", "\n");
        let generated = capability_matrix_markdown().trim().replace("\r\n", "\n");
        assert_eq!(
            embedded, generated,
            "THREAT_MODEL.md claim matrix drifted from `a3s-sandbox matrix`; \
             regenerate it and commit"
        );
    }
}
