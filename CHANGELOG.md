# Changelog

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
