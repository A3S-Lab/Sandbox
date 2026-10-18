# Batched Windows authorization recovery candidate

## Result

A replacement for rejected source
`91720eb4f10923ee7d8a747058a6f5a3b416e506` is prepared. Native testing observes successful ordinary operation and ACL
crash recovery, but two system-path classification contracts fail in the suite
and alone; [diagnostic follow-up](../2026-10-18-windows-system-path-diagnostics/OUTCOME.md)
retains the exact-source job. Full qualification remains pending. [The complete rejected Windows job](rejected-candidate-windows.log)
retains its isolated 0 / 1 / 0 ordinary-operation failure and 126.91-second
failed attempt. Linux and macOS jobs passed in
[CI 39100432917](https://github.com/A3S-Lab/Sandbox/actions/runs/39100432917).
That run did not reach Windows crash recovery or the full suite.

## Replacement and verification scope

- Build the complete ACL operation plan under the existing host-global mutation
  mutex. Open and retain each planned target handle, bind file identities, and
  capture original protection/inheritance deltas before any ACL mutation.
- Persist and flush the complete intent once, then apply the ordered operations
  through their retained handles. A failure during planning applies no grants;
  a failure after intent persistence retains enough state for cleanup/replay.
  Existing ancestor and optional toolchain access-denial handling stays intact.
- Cleanup replays the per-SID deltas under the same mutation gate and persists
  only the remaining obligations once at the end. A host crash partway through
  cleanup leaves the old intent available for idempotent replay. Unknown target
  identities still refuse mutation; no whole old DACL is copied over new edits.
- Canonicalize trusted system prefixes before comparing them with canonical PATH
  roots, so system toolchains are excluded as originally intended. The new
  isolated-process fixture proves that canonical system roots and their binaries
  receive no temporary grants without mutating the test runner's environment.
- Classify a non-followed reparse ACL target as unmodifiable. Optional toolchain
  entries skip it; required workspace/mount restrictions still propagate the
  refusal. Keep the no-follow handle and identity checks. A real symbolic-link
  fixture proves the target gets no grant while an ordinary sibling tool gets
  read access and no write access, then loses that temporary read grant.
- Update the negative CI oracle to remove the actual batched intent write and
  require the original real host-crash stale-authorization assertion to fail.
  No existing positive or security contract is removed or relaxed.

## Local checks

- `rustup run 1.97.1 cargo clippy --all-targets --locked --target
  x86_64-pc-windows-msvc --offline -- -D warnings` succeeds;
  [output](windows-clippy.log). This compiles all Windows test targets, without
  executing them on this macOS ARM64 host.
- Strict local macOS all-target Clippy succeeds; [output](macos-clippy.log).
- Full local macOS all-target tests pass 228 / 0 / 0;
  [output](macos-suite.log). Windows-only fixtures do not run on macOS.
- Formatting, new relative evidence links and `git diff --check` pass.

Logs normalize trailing whitespace and extra EOF blank lines only. Full
exact-source native CI remains required.

## Application delivery destination

The user moved the application to `/Users/roylin/code/aster/apps/work`.
The old `nano-crab` path resolves to that same physical directory and Git
worktree. Its existing unrelated spreadsheet E2E edit remains untouched.

The Aster root is a separate, not-yet-committed import. Its current local
Sandbox manifest and source-provenance record say 0.2.3. Code Core uses that
local Sandbox path. Work's ACP build/discovery scripts still reference the old
OS layout. After upstream qualification, delivery must migrate the relevant
Sandbox and Rust Core/ACP changes, preserve the Aster workspace's local dependency
layout and source provenance, repair Work's ACP discovery for the new layout,
and validate the actual built/installed application. No application migration
or deployment is claimed by this development-branch commit.

## Explicitly not claimed

- No native passing result for this replacement until exact-source CI completes.
- No measured startup SLO or general S6 completion; 126.91 seconds describes the
  rejected failed attempt, not a qualified before/after benchmark.
- No complete S4, DOS-device/profile recovery, arbitrary crash-cutpoint,
  runtime-abort, cross-principal, relocation or power-loss qualification.
  `host_exit_cleanup` remains false; missing/replaced objects retain debt.
- No public-main merge, version bump, tag, package release, Aster source migration,
  Work ACP packaging/deployment, or installed-application E2E acceptance.
