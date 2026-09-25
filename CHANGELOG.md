## [0.2.0] - 2026-09-25

### Added

- Gate 10 slice 1 — typed policy grants: `NetworkGrant` and
  `NativeSandbox::apply_network_grant`, the only sanctioned broadening path.
  Digest-pinned lineage (stale approvals refuse and are audited), minimal
  widening (one origin rule; deny-all baselines gain `mediated_network`
  scoped to the granted origin), idempotent regrants, existing decision
  aliasing semantics inherited, `ReasonCode::GrantApplied` audit events.
  macOS live test proves the full loop: denied command → grant → same
  command flows through mediation.

- Gate 9 slice 1 — Linux `mediated_socks` claimed via the HTTP bridge fence
  family. New `Socks5Mediator::bind_unix` hosts the SOCKS5 mediator on a
  bind-mounted scratch socket; the in-guest relay wrapper starts one
  TCP→Unix relay per mediated protocol (`GUEST_SOCKS_CONNECT_RELAY_PORT`
  24732 alongside HTTP 24731) with per-relay PID capture and cleanup, and
  `ALL_PROXY` points at the guest relay. Live wire tests prove allowed
  tunnels, ruleset denials, and socket cleanup. `mediated_socks` capability
  is now `cfg!(any(target_os = "macos", target_os = "linux"))`; macOS
  behavior unchanged; Windows SOCKS and non-macOS unix-socket allowlists
  stay fail-closed.
- Gate 8 slice 2 — egress re-injection at the mediation point. The host
  CONNECT/HTTP mediator now mediates absolute-form plain-HTTP requests
  (`GET http://host/path`) under the same `network.allow` authority, and
  matching `SecretHeaderInjection` rules inject `{header}: {value_prefix}`
  + the host-held secret, replacing any client-supplied instance (guest
  sentinels are swallowed, never forwarded). `https://` absolute forms
  refuse (TLS interception stays a non-goal); chunked bodies refuse;
  bodies cap at 1 MiB; missing or control-character-bearing secrets fail
  closed before any upstream byte. All mediator binds carry the
  per-execution secret map (`MediationContext`).
- Gate 8 slice 1 — host-held secret environment entries via
  `NativeSandbox::execute_with_secrets`. Secret values never reach the child
  process: each entry is delivered as an `a3s:secret:<NAME>` sentinel, the
  host re-injects real bytes only at a mediation point (later slice).
  Entries fail closed before spawn when `mediated_network` is off, when a
  name is reserved (re-homed, scrubbed, toolchain, or mediator keys), when a
  name collides with an explicit env entry, or when an entry is malformed.
  Sentinel injection is auditable (`AuditSurface::Environment`); secret bytes
  never reach the audit log, policy digest, or captured output.

## [0.1.5] - 2026-09-25

### Fixed

- Windows AppContainer ACL updates on ancestor directories (for example `%TEMP%`)
  use `SetKernelObjectSecurity` for non-inheriting grants. `SetNamedSecurityInfoW`
  was walking every descendant that already carried inheritable ACEs, which hung
  host executes after many sandbox runs polluted Temp DACLs.
- Windows user-owned PATH toolchains receive a non-inheritable execute grant;
  system trees and `WindowsApps` execution aliases are skipped. Alias stubs that
  return `ERROR_CANT_RESOLVE_FILENAME` (1920) fail soft like access denied.
- Long PowerShell guest commands fall back to `-File` under scratch when the
  encoded command line would exceed the Windows limit.
- PowerShell compat shim adds `test` / `grep` / `printf` helpers and preserves
  `$LASTEXITCODE` for deny checks.
- Job Object process-limit tests accept non-English Start-Process failure text.
- Shell scripts use LF via `.gitattributes` so WSL/Linux can execute Gate 7 SBOM
  helpers checked out on Windows.

### Added

- WSL GA runner: `scripts/run-wsl-ga-tests.sh` (refuses `/mnt/<drive>` 9p paths).
- Windows evidence collector: `scripts/collect-release-evidence.ps1`.
- Bash evidence collector auto-uses `--test-threads=1` on Windows and records
  live AppContainer named-pipe CONNECT proof when run on Windows.
- WSL/Windows GA evidence notes: `docs/WINDOWS_WSL_GA.md`.

## [0.1.4] - 2026-09-16

### Fixed

- Linux `set_rlimit` takes `libc::c_int` so musl cross-builds (Node SDK
  `*-unknown-linux-musl`) no longer fail looking up `__rlimit_resource_t`.

# Changelog

## Unreleased

## 0.1.3 — 2026-09-16

### Added

- Host-supervised HTTP CONNECT mediation (`mediated_http`) on macOS (Seatbelt
  loopback), Linux (netns Unix-bridge relay staged into guest scratch), and
  Windows (AppContainer inherited connected named-pipe handle
  `A3S_SANDBOX_MEDIATOR_PIPE_HANDLE`).
- Gate 7 assurance package: CONNECT protocol fuzz corpus, soak/p50 starters,
  in-command symlink race + overlapping same-workspace isolation tests,
  CycloneDX SBOM generator, sign-release / collect-release-evidence helpers,
  and `docs/INDEPENDENT_REVIEW.md` + `docs/RELEASE_CHECKLIST.md`.
- CONNECT request-line / header size bounds (8KiB / 16KiB).

### Security

- Default A3S Bash profile remains network deny-all; mediation stays opt-in
  until independent review approves any default-profile change.
- Windows claims `mediated_http` only after live AppContainer pipe allow/deny
  and raw-egress block proof on Windows CI.
- SECURITY.md Linux section corrected for baseline vs mediated `--unshare-net`.

### Fixed

- Linux CONNECT relay: stage relay binary into guest-visible scratch before
  netns exec (avoids "No such file" under HOME tmpfs mask).
- Windows AppContainer: inherit connected pipe client handle (name-open stays
  Access Denied); grant mount_roots ACLs; serialize same-workspace ACL
  apply/restore; tolerate Low-IL pipe relabel denial.

## 0.1.2 — 2026-09-08

### Fixed

- Native policy construction no longer bulk-enumerates hardlinks under
  `node_modules` / `target`. Those trees routinely exceed the 1M entry scan
  ceiling and Seatbelt literal limits on monorepos (for example A3S with many
  `crates/*/target` trees), which previously failed the capability probe and
  denied Bash until restart.
- Source-tree multi-link files remain denied. Package/build-store paths that
  hard-link to an already-discovered credential inode are still recovered and
  denied. Nested `.env*` discovery and source hardlink scanning share one walk.

### Security

- Document residual risk for pre-planted package-store hardlinks to arbitrary
  non-credential outside files. Runtime hardlink creation stays denied.
