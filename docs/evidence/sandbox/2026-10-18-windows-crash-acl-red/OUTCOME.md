# Windows crash/restart ACL regression preparation

## Result

A real-process crash/restart contract is prepared for the next S4 obligation.
Native execution of this new contract is pending; no observed red result or
durable recovery implementation is claimed.

Preparation base: `fa883b32ad78811b91ec490c5931424289c9e007`.
Toolchain: Rust 1.97.1. Preparation host: macOS ARM64.

The preparation base passed native CI: Linux 240 / 0 / 0, macOS 228 / 0 / 0,
Windows 219 / 0 / 0, including both Windows mutation oracles. The
[ownership certificate](../2026-10-18-windows-workspace-mutex/OUTCOME.md) retains
the exact-source logs. That passing result does not execute this new contract.

## Contract

The parent records ACEs and inheritance protection for a private workspace,
its existing `.git` directory and `.git/config`. A second real host runs the
same contract in a parent-assigned child role. The child creates a NativeSandbox,
starts a real PowerShell command, writes a readiness file from inside the
AppContainer, then remains active. The parent verifies temporary authorization
is observable before forcibly terminating that host.

A newly constructed sandbox must execute a real command on the same physical
workspace. Afterwards, the original host ACEs and protection state must be
restored, temporary sandbox entries must be absent, and the protected file's
bytes must remain unchanged. ACE ordering is ignored; entry bytes and protection
state are compared. The fixture reuses the existing ACL inspection helper.

A normal test invocation always runs the complete parent contract. The child
role cannot make an ordinary invocation pass without host termination/restart.
Readiness and command-result assertions prevent a pre-spawn failure or an unused
fixture from masquerading as a crash/recovery proof. Timeouts bound test protocol
waits; they are not measured performance guarantees.

## Local checks

- Strict Windows all-target cross-target Clippy succeeds;
  [output](windows-clippy.log). This does not execute the Windows contract.
- Full Rust formatting and `git diff --check` pass. The sibling test module is
  already registered; there are no production or wire-protocol changes.
- Local macOS common-core tests previously passed 228 / 0 / 0 on the preparation
  base. The new Windows-only contract is excluded from that host's execution.

## Explicitly not claimed

- No observed native crash/restart red or green result yet.
- No durable journal, ACL recovery, DOS-device/profile recovery, or S4 completion.
- No change to `host_exit_cleanup=false`, task quotas or performance claims.
- No public-main merge, release, Code deployment or installed-application E2E.
