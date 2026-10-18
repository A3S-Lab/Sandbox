#![cfg(test)]

use super::*;
use crate::NativeSandbox;
use windows_sys::Win32::System::JobObjects::IsProcessInJob;

pub(super) fn require_atomic_job_membership(process: &OwnedHandle, job: &JobGuard) -> Result<()> {
    let mut contained = 0;
    let queried = unsafe { IsProcessInJob(process.as_raw_handle(), job.raw(), &mut contained) };
    if queried != 0 && contained != 0 {
        return Ok(());
    }
    unsafe {
        TerminateProcess(process.as_raw_handle(), 1);
    }
    if unsafe { WaitForSingleObject(process.as_raw_handle(), PIPE_SETTLEMENT_MS as u32) }
        != WAIT_OBJECT_0
    {
        return Err(ExecutionFailure::SettlementUnknown.into());
    }
    bail!("CreateProcess returned a live process outside the sandbox Job before resume")
}

#[tokio::test]
async fn create_process_returns_already_contained_before_resume() {
    let workspace = tempfile::tempdir().unwrap();
    let sandbox = NativeSandbox::new(workspace.path()).unwrap();
    let output = sandbox
        .exec_command("[Console]::Out.Write('atomic-job')")
        .await
        .unwrap();
    assert_eq!(output.exit_code, 0, "{output:?}");
    assert!(!output.timed_out);
    assert_eq!(output.stdout, "atomic-job");
}
