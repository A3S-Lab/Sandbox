# Windows workspace identity mutex and compatible root pin

## Result

The first directory share-mode candidate is rejected after native testing caught
a normal-operation regression. Its replacement separates cross-host ownership
from the root-name pin: a named Windows mutex coordinates a physical directory,
and a directory-read handle denies delete sharing while allowing read/write
sharing. An initial attribute-only root pin was also rejected by native testing;
the corrected directory-read pin still requires native qualification.

Base: `e2bf1fd411532967cb1e9c2732d8a2bcba9da06c`.
Toolchain: Rust 1.97.1. Local preparation host: macOS ARM64.

## Native regression that rejected the first candidate

[CI 39096372575](https://github.com/A3S-Lab/Sandbox/actions/runs/39096372575)
ran the exact base above. Linux and macOS jobs succeeded. The Windows library
suite recorded 205 passed / 1 failed / 0 ignored. All six new ownership contracts
passed, but the existing positive ordinary-directory rename in
`native_backend_cannot_remove_or_rename_protected_workspace_entries` failed.
The same test failed alone: 0 passed / 1 failed / 0 ignored. The full Windows job,
including the solo run, is retained in [native-regression-windows.log](native-regression-windows.log).

The exclusive directory write sharing conflicts with legitimate guest operations
on ordinary children. Passing the new negative ownership tests alone therefore
does not qualify that implementation. The ordinary-operation assertion is kept;
the new direct root-pin contract additionally renames and deletes ordinary child
entries while root ownership is active.

## Native failure of the attribute-only root pin

[CI 39097086127](https://github.com/A3S-Lab/Sandbox/actions/runs/39097086127)
ran source `24a774caa289462aafb488235faa323fe74cb643`. Linux and macOS jobs
succeeded. The Windows library suite recorded 205 passed / 1 failed / 0 ignored.
The cross-host, case-alias, independent-owner, cross-thread release and replaced
root identity contracts passed. The existing ordinary guest directory operation
also passed, resolving the previous candidate's regression.

The active-root pin test failed in the suite and alone: a rename of the root
succeeded despite the live attribute-only handle. That handle did not enforce
the requested delete-sharing exclusion. [Complete native output](root-pin-red-windows.log)
retains both failures. The corrected pin requests directory-list access in
addition to attributes; it keeps read/write sharing and omits delete sharing.
CI now runs the root-pin and ordinary guest contracts individually before the
long full suite, retaining both smoke logs. The full suite and mutation checks
remain mandatory.

## Replacement

- Name the host-global mutex using the volume and 128-bit directory identity,
  rather than a path. Case aliases coordinate against the same object. Retain the
  existing identity handle to prevent identifier reuse while the sandbox lives.
- Reuse the existing host mutex security-descriptor construction. Its explicit
  AppContainer denials and host synchronization permissions are unchanged; the
  existing live ACL-mutex denial contract still exercises this shared factory.
- A blocking worker acquires and releases the mutex on the same OS thread.
  A one-shot channel keeps ownership until lease disposal, including disposal on
  another async or host thread. If the acquisition Future is cancelled, its
  readiness receiver closes and the worker stops waiting; if cancellation races
  acquisition, failed readiness delivery releases ownership immediately.
- One local async gate per sandbox is moved into the actual worker and retained
  until it exits. Queued calls on that instance cannot accumulate lock workers.
  Cross-instance/global worker admission and task-wide deadlines remain S5 work.
- The root pin requests directory-list/attribute access and shares read/write
  access. It denies delete sharing while active. The acquired identity must still
  match the bound identity before any scratch/policy initialization. No add-file permission is
  required by this replacement; directory-read permission is required.
- CI bypasses the real mutex wait and requires both original cross-host and
  case-alias assertions to fail. It restores the source in `finally` and checks
  an empty diff. Removing Job kill-on-close remains a separate negative oracle.

The six ownership contracts, original positive/negative guest filesystem tests,
existing ACL restoration and host-death contracts all remain mandatory. Durable
ACL crash/restart recovery is a separate, still-open S4 contract.

## Local validation

- Full macOS `cargo test --all-targets --locked`: 228 passed / 0 failed / 0 ignored;
  [output](macos-suite.log). Windows-only contracts do not execute on macOS.
- Strict all-target Windows cross-target Clippy succeeds;
  [output](windows-clippy.log). This proves type checking, not native execution.
- Strict local all-target Clippy and formatting pass;
  [Clippy output](macos-clippy.log). `git diff --check` passes.
- Existing modules/callers are wired; no public API, SDK or bridge wire changes.
  No guard, positive-operation assertion, or capability refusal is weakened.

Logs retain all job/test diagnostics, with trailing whitespace and extra EOF
blank lines removed. Original logs remain on the linked native run.

## Platform basis

- [Windows mutex ownership and abandonment](https://learn.microsoft.com/en-us/windows/win32/sync/mutex-objects)
  requires release by the owning thread; abandonment is not proof of resource
  recovery. The worker preserves thread affinity, and full host-exit admission
  remains unavailable.
- [Global kernel object namespace](https://learn.microsoft.com/en-us/windows/win32/termserv/kernel-object-namespaces)
  coordinates Windows sessions. The privilege requirement for creating global
  file mappings/symbolic links is not a blanket requirement for named mutexes.

## Explicitly not claimed

- No passing native replacement/mutation result yet and no performance SLO.
- No durable ACL, DOS-device or profile crash recovery. An abandoned mutex alone
  is not a recovered execution. `host_exit_cleanup` stays false and S4 is open.
- No global blocking-worker quota, runtime-abort certification, read-only host
  root qualification, or filesystem/alias guarantee beyond tested contracts.
- No resolution of intermittent macOS CONNECT `EPERM`, despite this run's macOS
  success. No public-main merge, new release, Code deployment or installed-app E2E.
