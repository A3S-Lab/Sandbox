# Release checklist (Gate 7 / production standard)

This package is the in-repo evidence and process checklist for an `a3s-sandbox`
production release. Completing code gates is not enough: independent review and
signed artifacts are required before mediated network may become a **default**
profile.

## Must remain true

Verified by `policy::gate7_release_invariants` plus CI on each OS:

- [x] Default A3S Bash profile keeps `mediated_network` / `mediated_socks` off
- [x] Capability probe lists unavailable surfaces (`mediated_http`, etc.)
- [x] Claims match `THREAT_MODEL.md` (no silent OS widening) — matrix asserted in
  `gate7_release_claims_match_capability_matrix`
- [x] `cargo fmt --all -- --check` (local + CI)
- [x] `cargo clippy --all-targets -- -D warnings` (local + CI)
- [x] `cargo test --all-targets` green on macOS, Linux, **and** Windows CI for
  the release commit (includes
  `windows_appcontainer_named_pipe_connect_allow_deny_and_blocks_raw_egress`)
- [x] WSL2 Linux suite green on a **native** ext4/xfs path (not `/mnt/<drive>`),
  via `scripts/run-wsl-ga-tests.sh` (bubblewrap required)

## Capability matrix (claim only with live proof)

| Surface | macOS | Linux | Windows |
| --- | --- | --- | --- |
| Network deny-all | claimed | claimed | claimed |
| Mediated HTTP CONNECT | claimed | claimed | claimed |
| Mediated SOCKS5 | claimed | claimed (live wire proof) | fail-closed |
| Unix-socket allowlist | claimed | fail-closed | fail-closed |

## Gate 7 assurance artifacts

- [x] Adversarial negatives (`policy/gate7_integration.rs`)
- [x] In-command symlink race + overlapping same-workspace executes
- [x] CONNECT protocol fuzz corpus (`policy/gate7_fuzz.rs`)
- [x] Soak (≥64 baseline executes; `GATE7_SOAK_ROUNDS`) + starter p50 benchmarks
  — enterprise GA target: record ≥256 rounds via
  `collect-release-evidence.ps1` / `collect-release-evidence.sh` before tag
- [x] SBOM generator: `./scripts/generate-sbom.sh`
- [x] Checksums / signatures helper: `./scripts/sign-release.sh <artifacts...>`
- [x] Local evidence collector: `./scripts/collect-release-evidence.sh` (+ Windows
  `scripts/collect-release-evidence.ps1`)
- [x] Independent review package: `docs/INDEPENDENT_REVIEW.md`

## Independent review (external)

- [ ] Reviewer reads `THREAT_MODEL.md` + this checklist + `INDEPENDENT_REVIEW.md`
- [ ] Reviewer confirms mediator fencing on each claiming OS
- [ ] Reviewer sign-off recorded (PR comment or release attestation)
- [ ] Mediated network is **not** made the default profile without that sign-off
- [x] Windows + WSL local evidence recorded in [`WINDOWS_WSL_GA.md`](WINDOWS_WSL_GA.md)

## Versioning

- [x] `CHANGELOG.md` entry for the release
- [x] Crate version bumped intentionally (immutable crates.io versions)
- [x] Tag matches the signed artifact commit SHA (`v0.2.0` when this release
  is tagged; prior production tags `v0.1.5`, `v0.1.3`)
- [ ] Provenance JSON attached to a published GitHub Release for `v0.2.0`
## Explicit non-goals for this release

- TLS interception
- Windows SOCKS / Unix-socket allowlists without dedicated fences
- Linux / Windows Unix-socket allowlists without path-granular enforcement
