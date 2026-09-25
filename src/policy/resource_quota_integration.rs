//! Gate 11 (optimization roadmap): OS-enforced resource quota depth.
//!
//! Linux runs these against the probed delegated cgroup v2 subtree; hosts
//! without delegation prove the fail-closed construction refusal instead.
//! Both branches are evidence: enforcement only ever ships where the OS can
//! actually bound the tree, and every other host refuses loudly.

use super::SandboxPolicy;
use crate::NativeSandbox;

fn quota_policy(max_processes: Option<u32>, max_memory_bytes: Option<u64>) -> SandboxPolicy {
    let mut policy = SandboxPolicy::a3s_bash_baseline();
    policy.resources.max_processes = max_processes;
    policy.resources.max_memory_bytes = max_memory_bytes;
    policy
}

#[test]
fn zero_cpu_quota_refuses_at_resolve() {
    let mut policy = quota_policy(None, None);
    policy.resources.max_cpu_millicores = Some(0);
    let error = crate::policy::ResolvedResourceBudget::resolve(&policy.resources, 30_000)
        .expect_err("zero cpu quota must refuse");
    assert!(error.to_string().contains("max_cpu_millicores"), "{error}");
}

#[cfg(not(any(windows, target_os = "linux")))]
#[test]
fn platforms_without_quota_enforcement_refuse_at_construction() {
    let workspace = tempfile::tempdir().unwrap();
    let error = NativeSandbox::with_policy(workspace.path(), quota_policy(Some(8), None))
        .expect_err("process quotas must fail closed where no OS primitive exists");
    assert!(
        error.to_string().contains("incompatible") || error.to_string().contains("fail closed"),
        "refusal must explain the capability gap: {error}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn quota_policy_refuses_at_construction_without_delegation() {
    let workspace = tempfile::tempdir().unwrap();
    let sandbox = NativeSandbox::with_policy(workspace.path(), quota_policy(None, None)).unwrap();
    if sandbox.capabilities().resource_process_limit {
        // Delegated host: the refusal branch is covered by the delegation
        // tests; nothing to prove here.
        return;
    }
    let workspace = tempfile::tempdir().unwrap();
    let error = NativeSandbox::with_policy(workspace.path(), quota_policy(Some(8), None))
        .expect_err("without delegation the construction must refuse quotas");
    assert!(
        error.to_string().contains("incompatible"),
        "refusal must be a capability failure: {error}"
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn cgroup_process_quota_bounds_the_process_tree() {
    let workspace = tempfile::tempdir().unwrap();
    let sandbox =
        NativeSandbox::with_policy(workspace.path(), quota_policy(Some(8), None)).unwrap();
    if !sandbox.capabilities().resource_process_limit {
        eprintln!("skipping: host has no delegated cgroup v2 subtree (fail-closed branch covered)");
        return;
    }
    // 64 concurrent children must hit the pids ceiling: forks start failing
    // with EAGAIN well before the tree can reach 64 sleepers.
    let command = "for i in $(seq 1 64); do (sleep 5 &) done; wait 2>/dev/null; echo gate11-done";
    let output = sandbox
        .exec_command(command)
        .await
        .expect("quota-bearing policy must execute once constructed");
    assert!(
        output.stderr.contains("Resource temporarily unavailable")
            || output.exit_code != 0
            || !output.stderr.is_empty(),
        "the pids ceiling must visibly bound the tree; stdout={} stderr={}",
        output.stdout,
        output.stderr
    );
    assert!(
        output.stdout.contains("gate11-done"),
        "the parent shell still completes: stdout={} stderr={}",
        output.stdout,
        output.stderr
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn cgroup_memory_quota_kills_the_tree_when_exceeded() {
    let workspace = tempfile::tempdir().unwrap();
    let sandbox =
        NativeSandbox::with_policy(workspace.path(), quota_policy(None, Some(64 * 1024 * 1024)))
            .unwrap();
    if !sandbox.capabilities().resource_process_limit {
        eprintln!(
            "skipping: host has no delegated cgroup v2 subtree (memory.max rides the same fence)"
        );
        return;
    }
    // Allocate far beyond the 64 MiB ceiling in one child: the kernel kills
    // the tree instead of letting it OOM the host.
    let command = "python3 -c 'data = [bytes(32 * 1024 * 1024) for _ in range(16)]'";
    let output = sandbox
        .exec_command(command)
        .await
        .expect("quota-bearing policy must execute once constructed");
    assert!(
        !output.timed_out,
        "the memory ceiling must kill the tree, not stall it"
    );
    assert!(
        output.exit_code != 0,
        "an allocation beyond memory.max must not succeed; stdout={}",
        output.stdout
    );
}
