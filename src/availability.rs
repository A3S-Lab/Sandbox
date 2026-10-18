use std::fmt;

/// Why a host cannot admit a command requiring complete workload cleanup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionUnavailable {
    RuntimeProbeRequired,
    ProcessTreeCleanup,
    HostExitCleanup,
}

impl ExecutionUnavailable {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RuntimeProbeRequired => "runtime_probe_required",
            Self::ProcessTreeCleanup => "process_tree_cleanup_unavailable",
            Self::HostExitCleanup => "host_exit_cleanup_unavailable",
        }
    }

    pub fn parse(value: &str) -> anyhow::Result<Self> {
        match value {
            "runtime_probe_required" => Ok(Self::RuntimeProbeRequired),
            "process_tree_cleanup_unavailable" => Ok(Self::ProcessTreeCleanup),
            "host_exit_cleanup_unavailable" => Ok(Self::HostExitCleanup),
            _ => anyhow::bail!("unknown execution unavailability reason {value:?}"),
        }
    }
}

impl fmt::Display for ExecutionUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::error::Error for ExecutionUnavailable {}
