## [Unreleased]

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
