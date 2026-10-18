# Windows derived AppContainer identity candidate

## Result

A candidate removes persistent profile registration from sandbox construction.
It follows the three independently observed native
[profile lifecycle failures](../2026-10-18-windows-profile-red/OUTCOME.md) on source
`16c83c1714e1eecb4ddb23bd79ea60ab8be1a127`. Native qualification of this
replacement remains pending. Full S4 admission stays unavailable.

## Implementation and affected surfaces

- Derive the unique package SID with the documented Windows API and retain the
  existing aligned SID buffer/FreeSid ownership. Keep unique name generation and
  error propagation. The factory no longer creates per-user profile folders or
  registry storage. No separate orphan-profile collector or persistent ownership
  database is added.
- The same SID continues to reach ACL grants, process SECURITY_CAPABILITIES,
  mediation pipes and their denials. Job Object creation/atomic assignment,
  kill-on-close, root ownership and recovery journals are unchanged. Existing
  independent-identity and real execution/security tests remain mandatory.
- Keep all three lifecycle contracts. Add a CI mutation that restores actual
  CreateAppContainerProfile registration in the factory; the constructor oracle
  must fail with its original persistent-state assertion. Restore the source in
  finally and require an empty diff.
- Correct the canonical system-root test's premise: set PROGRAMFILES inside the
  isolated child and assert the read-back value before inspecting ACLs. The
  native diagnostic showed that passing this variable through process startup
  had not established the expected value. No production system-path classification
  or authorization boundary is loosened to accommodate that fixture.
- No public API, dependency, SDK/bridge schema or generated artifact changes.
  Existing test-only name retention and module wiring remain in place.

## Local checks

Strict Windows all-target Clippy passes; [output](windows-clippy.log).
This compiles the affected production and test paths on macOS ARM64; it is not
native Windows execution. Formatting, new relative evidence links and
`git diff --check` pass. Non-Windows implementation paths are unchanged.

## Platform basis

[CreateAppContainerProfile](https://learn.microsoft.com/en-us/windows/win32/api/userenv/nf-userenv-createappcontainerprofile)
creates per-user folders and registry storage. This sandbox redirects command
scratch storage and uses the package SID for its native process boundary.
[DeriveAppContainerSidFromAppContainerName](https://learn.microsoft.com/en-us/windows/win32/api/userenv/nf-userenv-deriveappcontainersidfromappcontainername)
provides that SID with explicit FreeSid ownership.

[Chromium AppContainerBase::Open](https://chromium.googlesource.com/chromium/src/+/refs/tags/140.0.7339.185/sandbox/win/src/app_container_base.cc)
constructs a derived identity separately from profile registration and supplies
security capabilities/tokens from the package SID. This is an implementation
precedent; it does not substitute for this candidate's real PowerShell, process,
ACL, mediation, crash and negative-mutation qualification.

## Explicitly not claimed

- No native passing result for this candidate until exact-source CI completes.
- No cleanup of legacy unjournaled profiles, DOS-device recovery, complete S4,
  arbitrary crash-cutpoint, relocation, runtime-abort, cross-principal or
  power-loss proof. `host_exit_cleanup` remains false.
- No performance SLO, task-quota completion or resolution of macOS lifetime and
  intermittent CONNECT qualification.
- No main merge, version bump, release, Aster source migration, Work ACP packaging
  or installed-application end-to-end acceptance.
