# a3s-sandbox 0.3.0

This release makes native lifecycle guarantees explicit, bounds observer and
cancellation cleanup, and tightens Windows AppContainer filesystem grants.

## Migration

`NativeSandbox::probe()` now returns `CapabilityReport`. Wrappers returning
`Result<()>` can use `.map(|_| ())`. Hosts that require full descendant and
host-exit containment must call `report.require_lifetime_containment()`.
Launcher availability alone does not establish either guarantee.

The bridge's `probe` response includes the full report with
`runtime_probed=true`. Initialize and static capability reports use `false`.
The Go SDK adds `ProbeReport`; its existing error-only `Probe` remains valid.

## Fixes

- Bound live and completion observers; preserve typed cancellation,
  observer-timeout and unknown-settlement failures.
- Retain execution ownership while a caller is cancelled, including before
  the execution owner first polls.
- Stop Unix process groups after root exit while draining inherited pipes.
- Create Windows processes atomically inside a kill-on-close Job.
- Give independent Windows sandboxes distinct AppContainer SIDs and revoke
  their grants from the current ACL instead of restoring stale descriptors.
- Replace ineffective package-SID denials with restricted grants, restore
  inheritance, and remove parent delete-child rights over protected entries.
- Coordinate Windows ACL mutations with a host-global mutex and bounded waits.
- Preserve signal failures as nonzero CLI exits.
- Keep Go SDK close idempotent after forced bridge termination or a pipe-close race.
- Preserve the Go SDK, bridge, runtime-probed Linux cgroup quota support,
  credential hardlink checks and bubblewrap executable discovery.

## Qualified scope

Windows requires Windows 10 / Server 2016 or newer and PowerShell 7. Linux
requires bubblewrap and usable unprivileged namespaces. Requested cgroup
quotas refuse when the host does not delegate the required controls.

macOS detached descendants and host-exit cleanup remain unqualified. Windows
host-exit admission remains unavailable until cross-host workspace ownership
and durable ACL/device/profile recovery are qualified. These restrictions
remain visible through the capability report. This release does not certify
new WSL2 or enterprise GA claims, and mediated network remains opt-in.

Native CI logs, source identities, SHA-256 checksums, signatures and an SBOM
accompany the release artifacts.
