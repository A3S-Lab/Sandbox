# Changelog

## Unreleased

### Security

- CONNECT request-line / header size bounds (8KiB / 16KiB) and Gate 7 protocol
  fuzz corpus.
- Windows claims `mediated_http` after live AppContainer guest proof: connected
  named-pipe pair with inherited client handle (`A3S_SANDBOX_MEDIATOR_PIPE_HANDLE`).
- Gate 7 in-command symlink race + overlapping same-workspace isolation tests.
- Release helpers: SBOM generator, sign-release provenance, collect-release-evidence,
  independent review package under `docs/`. SBOM script tests run on Unix only.
- SECURITY.md Linux section corrected for baseline vs mediated `--unshare-net`.

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
