use crate::policy::EnforcedPolicy;
use crate::{CommandOutput, CommandRequest};
use anyhow::{bail, Result};
use std::path::Path;

#[derive(Debug)]
pub(crate) struct PlatformSandbox;

impl PlatformSandbox {
    pub(crate) fn effective_capabilities(&self) -> crate::policy::BackendCapabilities {
        crate::policy::BackendCapabilities::native_gate2()
    }
    pub(crate) fn new(_workspace: &Path) -> Result<Self> {
        bail!(
            "the A3S native sandbox is unsupported on {}",
            std::env::consts::OS
        )
    }

    pub(crate) async fn execute(
        &self,
        _policy: &EnforcedPolicy,
        _request: CommandRequest,
    ) -> Result<CommandOutput> {
        bail!(
            "the A3S native sandbox is unsupported on {}",
            std::env::consts::OS
        )
    }
}
