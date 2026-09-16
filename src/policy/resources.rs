//! Resolve and apply policy resource budgets to OS primitives.

use super::model::ResourceLimits;
use super::BackendCapabilities;
use anyhow::{bail, Result};

/// Concrete budget after combining policy ceilings with a command request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedResourceBudget {
    pub timeout_ms: u64,
    pub max_output_bytes: usize,
    pub max_processes: Option<u32>,
    pub max_memory_bytes: Option<u64>,
}

impl ResolvedResourceBudget {
    /// Combine policy resource ceilings with the per-command timeout.
    ///
    /// The effective timeout is `min(request_timeout, policy.timeout_ms)`.
    /// Output capture uses the policy ceiling. Process/memory limits are
    /// optional and must be enforceable by the backend (validated earlier).
    pub fn resolve(policy: &ResourceLimits, request_timeout_ms: u64) -> Result<Self> {
        if request_timeout_ms == 0 {
            bail!("command timeout must be greater than zero");
        }
        if policy.timeout_ms == 0 {
            bail!("policy timeout_ms must be greater than zero");
        }
        if policy.max_output_bytes == 0 {
            bail!("policy max_output_bytes must be greater than zero");
        }
        if let Some(0) = policy.max_processes {
            bail!("policy max_processes must be greater than zero when set");
        }
        if let Some(0) = policy.max_memory_bytes {
            bail!("policy max_memory_bytes must be greater than zero when set");
        }
        if policy.max_call_depth.is_some() {
            bail!(
                "max_call_depth is not enforceable by the OS process boundary; fail closed \
                 instead of silently ignoring it"
            );
        }

        Ok(Self {
            timeout_ms: request_timeout_ms.min(policy.timeout_ms),
            max_output_bytes: policy.max_output_bytes,
            max_processes: policy.max_processes,
            max_memory_bytes: policy.max_memory_bytes,
        })
    }

    /// Confirm the budget only uses limits this backend can enforce.
    pub fn validate_for_backend(self, capabilities: BackendCapabilities) -> Result<()> {
        if !capabilities.resource_timeout {
            bail!("backend cannot enforce command timeouts; fail closed");
        }
        if !capabilities.resource_output_limit {
            bail!("backend cannot enforce output capture limits; fail closed");
        }
        if self.max_processes.is_some() && !capabilities.resource_process_limit {
            bail!("process limit requested but backend cannot enforce it; fail closed");
        }
        if self.max_memory_bytes.is_some() && !capabilities.resource_memory_limit {
            bail!("memory limit requested but backend cannot enforce it; fail closed");
        }
        Ok(())
    }
}

/// Apply Unix rlimits in the child before exec. Limits are inherited by
/// descendants.
///
/// - Linux: `RLIMIT_AS` enforces optional memory ceilings.
/// - Process-count quotas are never applied via `RLIMIT_NPROC` (UID-scoped).
/// - macOS cannot lower address-space rlimits; memory must fail closed earlier
///   via capabilities.
#[cfg(unix)]
pub(crate) fn apply_unix_rlimits(budget: &ResolvedResourceBudget) -> Result<()> {
    if budget.max_processes.is_some() {
        bail!(
            "process limit requested but Unix backends cannot enforce a process-tree \
             quota without cgroup (or equivalent); fail closed"
        );
    }
    if let Some(max_memory_bytes) = budget.max_memory_bytes {
        #[cfg(target_os = "linux")]
        {
            // Cast: musl uses c_int; glibc uses __rlimit_resource_t (u32).
            set_rlimit(libc::RLIMIT_AS as u32, max_memory_bytes)?;
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = max_memory_bytes;
            bail!(
                "memory limit requested but this Unix platform cannot enforce address-space \
                 quotas via rlimit; fail closed"
            );
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn set_rlimit(resource: u32, soft_and_hard: u64) -> Result<()> {
    let limit = libc::rlimit {
        rlim_cur: soft_and_hard as libc::rlim_t,
        rlim_max: soft_and_hard as libc::rlim_t,
    };
    // `as _` accepts both musl (c_int) and glibc (__rlimit_resource_t).
    let rc = unsafe { libc::setrlimit(resource as _, &limit) };
    if rc != 0 {
        bail!(
            "failed to set rlimit resource={resource:?} value={soft_and_hard}: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::model::ResourceLimits;
    use crate::MAX_OUTPUT_SIZE;

    #[test]
    fn resolve_caps_request_timeout_by_policy() {
        let policy = ResourceLimits {
            timeout_ms: 1_000,
            max_output_bytes: MAX_OUTPUT_SIZE,
            ..ResourceLimits::default()
        };
        let budget = ResolvedResourceBudget::resolve(&policy, 5_000).unwrap();
        assert_eq!(budget.timeout_ms, 1_000);
        assert_eq!(budget.max_output_bytes, MAX_OUTPUT_SIZE);
    }

    #[test]
    fn resolve_uses_policy_output_ceiling() {
        let policy = ResourceLimits {
            max_output_bytes: 2_048,
            ..ResourceLimits::default()
        };
        let budget = ResolvedResourceBudget::resolve(&policy, 30_000).unwrap();
        assert_eq!(budget.max_output_bytes, 2_048);
    }

    #[test]
    fn resolve_rejects_call_depth_as_unenforcible() {
        let policy = ResourceLimits {
            max_call_depth: Some(32),
            ..ResourceLimits::default()
        };
        let error = ResolvedResourceBudget::resolve(&policy, 1_000)
            .unwrap_err()
            .to_string();
        assert!(error.contains("max_call_depth"), "{error}");
    }

    #[test]
    fn resolve_rejects_zero_process_or_memory_limits() {
        let policy = ResourceLimits {
            max_processes: Some(0),
            ..ResourceLimits::default()
        };
        assert!(ResolvedResourceBudget::resolve(&policy, 1_000).is_err());
        let policy = ResourceLimits {
            max_memory_bytes: Some(0),
            ..ResourceLimits::default()
        };
        assert!(ResolvedResourceBudget::resolve(&policy, 1_000).is_err());
    }

    #[test]
    fn gate2_capabilities_can_enforce_optional_process_and_memory() {
        let caps = BackendCapabilities::native_gate2();
        assert_eq!(caps.resource_process_limit, cfg!(windows));
        assert_eq!(
            caps.resource_memory_limit,
            cfg!(any(windows, target_os = "linux"))
        );

        let memory_only = ResourceLimits {
            max_memory_bytes: Some(64 * 1024 * 1024),
            ..ResourceLimits::default()
        };
        let budget = ResolvedResourceBudget::resolve(&memory_only, 1_000).unwrap();
        if caps.resource_memory_limit {
            budget.validate_for_backend(caps).unwrap();
        } else {
            let error = budget.validate_for_backend(caps).unwrap_err().to_string();
            assert!(error.contains("memory limit"), "{error}");
        }

        let with_processes = ResourceLimits {
            max_processes: Some(32),
            ..ResourceLimits::default()
        };
        let budget = ResolvedResourceBudget::resolve(&with_processes, 1_000).unwrap();
        if caps.resource_process_limit {
            budget.validate_for_backend(caps).unwrap();
        } else {
            let error = budget.validate_for_backend(caps).unwrap_err().to_string();
            assert!(error.contains("process limit"), "{error}");
        }
    }
}
