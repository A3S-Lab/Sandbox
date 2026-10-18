# Windows authorization recovery journal candidate

## Result

The first durable, host-only ACL recovery candidate was prepared on top of
`71337f23c931d3b76c3734b023ae413e3ce9db70` and committed as
`91720eb4f10923ee7d8a747058a6f5a3b416e506`. Native testing rejects it;
[the replacement](../2026-10-18-windows-acl-journal-batch/OUTCOME.md) retains the
failing job and addresses its toolchain compatibility and write amplification.
The prerequisite [crash/restart red](../2026-10-18-windows-crash-acl-red/OUTCOME.md)
is observed in the Windows full suite and solo rerun. This candidate does not
promote `host_exit_cleanup`; complete S4 qualification remains open.

## Native rejection

[CI 39100432917](https://github.com/A3S-Lab/Sandbox/actions/runs/39100432917)
passes its Linux and macOS jobs. The Windows root-pin contract passes alone.
The next isolated ordinary-operation contract fails before command start on the
reparse-point executable `Program Files (x86)\pipx_bin\yamllint.exe`.
The failed attempt takes 126.91 seconds, including setup and error cleanup;
this is not a measurement of pure command runtime. The Windows full suite and
crash/restart contract are skipped after that early failure.

The uncanonicalized system-prefix comparison missed this extended-length PATH
root. The new blanket reparse-point rejection then turned an optional toolchain
entry into a fatal error. Per-target journal writes and hive flushes also cause
avoidable write amplification. These results reject this implementation; they
do not weaken the existing ordinary-operation contract.

## Original change and affected surfaces

- Store an internal, versioned recovery record under the protected per-user
  `Software\A3S\Sandbox\Recovery.v1` registry key, with one value per physical
  workspace identity. The key explicitly denies both AppContainer package groups;
  its existing protected DACL must match the host-only descriptor before use.
  Registry handles are not inherited. Stored data is internal recovery state,
  not product configuration; no configuration or bridge schema changes.
- Record the sandbox package SID, each target's volume/file identity, local-only
  mutation mode, and original inheritance-conversion delta. Windows paths use
  UTF-16 without a lossy Unicode conversion. Bounded reads, strict schema/version,
  absolute-path and package-SID validation reject malformed records before replay.
- Write and flush recovery intent under the existing host-global ACL mutation
  mutex before the first authorization or protection change to each target.
  Restore only this SID and its recorded inheritance delta. Keep other live
  grants and unrelated host edits. Successful per-target cleanup updates the
  record; unsuccessful obligations remain available for retry.
- Open an ACL target once; query, identity-check and mutate through that same
  handle. Restoring a replaced object refuses before changing its ACL. This also
  avoids a second name lookup between the identity check and the ACL write.
- Acquire the existing physical workspace lease before recovery, scratch or
  policy preparation. Recovery runs on a blocking worker that owns the lease
  until the actual worker returns, even if its async waiter is cancelled.
- Wire the Windows recovery module and reuse the existing Windows identity and
  allocation helpers. Add a direct Windows-only serde/derive declaration for
  typed serialization; all packages and versions already exist in Cargo.lock.
  Enable the existing windows-sys registry feature. No dependency is upgraded.
- Keep the real host-death/restart contract. Add native contracts for failed intent
  writes leaving ACLs unchanged, replacement-object refusal with retained debt,
  unrelated authority preservation, corrupt-record pre-start refusal and live
  AppContainer registry-write denial. Add an early isolated crash/restart CI
  check and a mutation oracle that removes intent persistence and requires the
  original stale-workspace-authorization assertion to fail.

## Local checks

- `rustup run 1.97.1 cargo clippy --all-targets --locked --target
  x86_64-pc-windows-msvc --offline -- -D warnings` passes;
  [output](windows-clippy.log). Affected Windows tests compile but do not run.
- Strict all-target macOS Clippy passes; [output](macos-clippy.log).
- Full local macOS all-target suite passes 228 / 0 / 0;
  [output](macos-suite.log). Windows-only tests are excluded on this host.
- Rust formatting, relative links added in these evidence files and
  `git diff --check` pass. Existing test-module wiring remains intact.

Logs normalize trailing whitespace and extra EOF blank lines only.

## Platform basis

- [RegCreateKeyExW](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regcreatekeyexw)
  provides nonvolatile keys with explicit creation security; an already-existing
  key is opened, so its security is independently verified rather than assumed.
- [RegFlushKey](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regflushkey)
  persists the hive before returning and is expensive. This correctness-first
  candidate flushes per change; batching and measured startup costs remain S6 work.
- [SetSecurityInfo](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-setsecurityinfo)
  changes the handle-identified file and propagates inheritable entries. Existing
  non-propagating ancestor updates continue to use SetKernelObjectSecurity.

## Explicitly not claimed

- No native passing result for this candidate until the exact-source CI completes.
- No complete S4 or host-exit capability promotion, DOS-device/profile recovery,
  arbitrary crash-cutpoint, runtime-abort, cross-principal or power-loss proof.
- No recovery of legacy unjournaled executions or automatic relocation of missing
  or renamed ACL targets. Unknown identities retain debt and refuse execution;
  finding the original object and complete physical-identity recovery remain open.
- No latency, throughput or quota SLO. Synchronous ACL setup still needs S6
  profiling; per-change hive flush cost is an explicit implementation limit.
- No public-main merge, version bump, new tag, published package, Code consumer
  deployment, or installed-application end-to-end acceptance.
