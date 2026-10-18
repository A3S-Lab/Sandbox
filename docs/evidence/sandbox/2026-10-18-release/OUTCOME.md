# 0.3.0 release qualification

## Result

The native lifecycle and Windows ACL repair lane is merged with the existing
upstream Go SDK, machine bridge and Linux cgroup quota implementation. Version
0.3.0 reflects the breaking Rust probe return type. The exact release commit
must pass the three-platform CI workflow before tagging and publication.

Local Rust 1.97.1 verification: macOS all-target suite 228/0 and parallel
Linux ARM64 suite 240/0, zero ignored. Native macOS and all-target MSVC strict
Clippy pass. The Go SDK passes `go test -race ./...`; its five real-bridge
integration cases also pass with the race detector on macOS. The imported
Linux quota tests initially exposed two stale assertions; both reproduced
individually before their report/error-chain assertions were corrected.

## What landed

The public workflow pins Rust 1.97.1 and action identities, records its source
and host, runs format/strict Clippy/all-target tests, and exercises the Go
protocol on each host. Unix hosts also drive the real bridge from Go.
Windows runs a 64-round soak, repeats each failed contract alone, and checks
that removing Job kill-on-close makes the host-death oracle fail. Mutation
source is restored before building release binaries.

The workflow retains raw logs and archives all three native executables with
the exact source commit. Published assets must carry checksums, cryptographic
signatures and a CycloneDX SBOM. CI identities and final results are retained
with the release provenance instead of referring to private development logs.

## Explicitly not claimed

macOS native detached and host-exit cleanup, Windows cross-host workspace and
durable ACL/device/profile crash recovery, new WSL2 qualification, enterprise
GA, and mediated-network defaults are not certified by this release.
The lifecycle admission contract continues to refuse unqualified guarantees.
