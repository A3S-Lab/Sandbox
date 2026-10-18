# Windows AppContainer profile lifecycle regression preparation

## Result

Three native profile lifecycle contracts are prepared on top of
`76ae1ca260c374e4d7d6cddc65d0f3d8c1c9feed`. Their native red/green results
are pending. Production profile creation and capability claims remain unchanged.
The preceding [system-path diagnostic preparation](../2026-10-18-windows-system-path-diagnostics/OUTCOME.md)
retains the failing batch-source native run and isolated results.

## Contracts and oracle

- Constructing a sandbox must not register a persistent AppContainer profile.
  The test observes registration while the sandbox object is still alive, so
  deleting a profile only in Drop cannot satisfy the no-start construction path.
- A real PowerShell command must return exit 0 and its marker. After completion
  and sandbox disposal, the unique profile name must not remain registered.
- A separate real host writes its own profile identity to a parent-owned control
  file outside the untrusted workspace, then starts a real sleeping command.
  Readiness comes from inside the AppContainer. The parent kills that host,
  starts a new sandbox on the same workspace, verifies another real command,
  and checks that neither the abandoned nor replacement profile remains.

The profile oracle calls CreateAppContainerProfile for the exact test-owned
name. ERROR_ALREADY_EXISTS proves prior registration; success proves that the
name was absent immediately before the oracle. Other HRESULTs are fixture/API
errors. The oracle frees returned SID memory and deletes only that known owned
profile before asserting, including on an expected registered-profile failure.
The child exposes its name only through test-gated identity retention; there is
no production name override, environment hook or external profile deletion path.

## CI and local checks

CI runs each of the two system-classification and three profile contracts alone,
retains a separate log, and runs all five even when one fails. The step fails
if any contract fails. Existing root pin, ordinary operation, ACL restoration,
full suites, solo failure triage and mutation oracles remain mandatory.

Strict Windows all-target Clippy succeeds; [output](windows-clippy.log).
This compiles affected tests on macOS ARM64 but does not execute them.
Formatting, new relative evidence links and git diff checks pass. The sibling
whole-file test module is registered in the Windows backend.

## Explicitly not claimed

- No observed native profile lifecycle red or green result yet.
- No profile cleanup fix, DOS-device recovery, full S4 qualification or capability
  promotion; `host_exit_cleanup` remains false.
- No resolution yet of the canonical system-root fixture mismatch, arbitrary
  crash-cutpoint, relocation, runtime-abort, cross-principal or power-loss proof.
- No main merge, version bump, release, Aster source migration, Work ACP packaging
  or installed-application end-to-end acceptance.
