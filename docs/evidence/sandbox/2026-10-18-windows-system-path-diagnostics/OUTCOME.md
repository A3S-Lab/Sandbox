# Windows system-path classification diagnostics

## Result

Native [CI 39101215027](https://github.com/A3S-Lab/Sandbox/actions/runs/39101215027)
on source `664409ae46343b176e7edc2857f5b27746e1001a` passes Linux and macOS.
Windows records 211 / 2 / 0 in the full library suite. Both distinct failures
also fail alone; [the full job](native-windows.log) retains their assertions.
Windows integration suites and mutation oracles did not run after those failures.

The ordinary-operation contract passes alone in 3.20 seconds. The real host-crash
ACL recovery passes alone in 1.81 seconds and again in the full suite. Replaced
object refusal, corrupt-journal pre-start refusal, failed-intent nonmutation,
other-authority preservation and live registry-write denial also pass. These
individual results do not qualify the entire source or establish a performance SLO.

## Failure triage and change

- `canonical_system_toolchains_do_not_receive_temporary_grants` sees a temporary
  package grant on its fixture's canonical system root, in the suite and alone.
  The normalization is already present; the remaining mismatch is not yet
  diagnosed. Add only bounded test diagnostics for the configured PROGRAMFILES
  value before/after profile creation, canonical fixture root and observed trusted
  prefixes. Run this contract early and alone in CI for a shorter feedback cycle.
- The previous `windows_apps_execution_aliases_are_not_acl_targets` asserts that
  an internal helper returns exactly the uncanonicalized path string. That is
  representation-pinning after canonicalization. Replace it with an observable
  contract: pass the canonical WindowsApps path through authorization planning,
  then compare its real ACL and existence before/after. Absent WindowsApps stays
  absent. No assertion or deny for actual authorization is relaxed.
- ACL observation opens only READ_CONTROL/attribute access, independently of
  whether the caller can change the object. Production mutation still requires
  WRITE_DAC, retains no-follow handles and physical identity checks.

## Subsequent diagnostic result

The early tests on source `16c83c1714e1eecb4ddb23bd79ea60ab8be1a127`
show that PROGRAMFILES still equals the real `C:\Program Files` before and after
profile creation, instead of the child fixture's claimed temporary system root.
The fixture setup did not establish its premise; production correctly grants
that otherwise ordinary user toolchain root. The replacement WindowsApps ACL
nonmutation contract passes in the same native run. The
[profile red certificate](../2026-10-18-windows-profile-red/OUTCOME.md) retains
that run's complete Windows output. The fixture will set and verify the value
inside its isolated child before invoking authorization.

## Local checks

Strict Windows all-target Clippy succeeds; [output](windows-clippy.log).
Affected tests compile without executing on the macOS preparation host.
Rust formatting, new relative evidence links and `git diff --check` pass.
No production authorization, capability flag, public API or wire schema changes.

## Explicitly not claimed

- No fix or passing native result for the canonical fixture mismatch yet.
- No full native passing source, mutation-oracle pass, S4 completion or capability
  promotion; `host_exit_cleanup` remains false.
- No profile/device recovery, arbitrary crash-cutpoint, relocation, runtime-abort,
  cross-principal, power-loss or performance-SLO qualification.
- No public-main merge, version bump, release, Aster source migration, Work ACP
  packaging/deployment or installed-application E2E acceptance.
