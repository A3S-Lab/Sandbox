# Windows crash/restart ACL regression

## Result

The real-process crash/restart contract fails on native Windows, both in the
full suite and alone. The memory-only ACL cleanup leaves the terminated host's
AppContainer grant on the workspace. Linux and macOS jobs succeed. No recovery
implementation was present in this failing source.

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

## Observed native red

[CI 39098909932](https://github.com/A3S-Lab/Sandbox/actions/runs/39098909932)
ran exact source `71337f23c931d3b76c3734b023ae413e3ce9db70`.
The Windows library suite recorded 206 passed / 1 failed / 0 ignored. Its only
failure was this crash/restart contract, at the final ACL equality assertion:
`restarting left stale workspace authorization`. The old package SID's explicit
workspace grant remained. The newly started command itself returned exit 0 and
`recovered`, so this was not a launcher or restart availability failure.

The automatic solo rerun reproduced the same ACL assertion: 0 passed / 1 failed /
0 ignored. [The complete Windows job log](native-windows.log) retains both runs,
including exact source and toolchain. Trailing whitespace and extra EOF blank
lines are normalized; the linked CI run retains the original logs. Integration
suites after the failing library suite did not execute on Windows in this run.

## Local preparation checks

- Strict Windows all-target cross-target Clippy succeeds;
  [output](windows-clippy.log). This does not execute the Windows contract.
- Full Rust formatting and `git diff --check` pass. The sibling test module is
  already registered; there are no production or wire-protocol changes.
- Local macOS common-core tests previously passed 228 / 0 / 0 on the preparation
  base. The new Windows-only contract is excluded from that host's execution.

## Explicitly not claimed

- No native crash/restart green result on this failing source.
- No durable journal, ACL recovery, DOS-device/profile recovery, or S4 completion.
- No change to `host_exit_cleanup=false`, task quotas or performance claims.
- No public-main merge, release, Code deployment or installed-application E2E.
