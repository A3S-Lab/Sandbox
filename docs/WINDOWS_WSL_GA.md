# Windows and WSL GA evidence

Local verification for enterprise GA readiness of `a3s-sandbox` on Windows host
and WSL2 Linux. CI still owns macOS / GitHub-hosted Linux / Windows matrix.

## Windows (native AppContainer)

Host: Windows 10/11 x64 with PowerShell 7.

```text
GATE7_SOAK_ROUNDS=8 cargo test --all-targets -- --test-threads=1
```

Observed (2026-09-25 local):

| Suite | Result |
| --- | --- |
| lib | 161 passed (`GATE7_SOAK_ROUNDS=8`) |
| cli_gate6 | 3 passed |
| sbom_gate7 | skipped (Unix-only) |
| Gate 7 soak 256 | ok in 426.80s |
| AppContainer named-pipe CONNECT live proof | ok in 7.02s |

Critical regression closed: ancestor ACL updates no longer hang after Temp DACL
pollution. Live path: `gate2_execute_records_attributable_audit_events` (~1.4s).

Evidence bundle (local, gitignored `release-out/`): `EVIDENCE.windows.md`,
`SHA256SUMS.windows`.
## WSL2 (bubblewrap Linux backend)

Requirements:

- WSL2 Ubuntu (or similar) with `bwrap`, `cargo`, `rustc`, `python3`
- Crate tree on a **native** Linux filesystem (not `/mnt/<drive>`)
- Runner: [`../scripts/run-wsl-ga-tests.sh`](../scripts/run-wsl-ga-tests.sh)

```bash
rsync -a --exclude target --exclude .git /path/to/crates/sandbox/ ~/a3s-sandbox-ga/
~/a3s-sandbox-ga/scripts/run-wsl-ga-tests.sh
```

Observed (2026-09-25 local, native ext4 copy under `~/a3s-monorepo-fake`):

| Suite | Result |
| --- | --- |
| lib | 175 passed |
| cli_gate6 | 3 passed |
| sbom_gate7 | 1 passed |
| Full evidence collector (`GATE7_SOAK_ROUNDS=256`) | OK — SBOM + SHA256 + provenance |

Evidence bundle (local): `release-out/EVIDENCE.wsl.md`, `sbom.wsl.cdx.json`,
`provenance.wsl.json`.
## Still required for full enterprise GA

These are Gate 7 residuals from [`RELEASE_CHECKLIST.md`](RELEASE_CHECKLIST.md):

1. External independent review sign-off (`INDEPENDENT_REVIEW.md`)
2. Extended soak evidence (`GATE7_SOAK_ROUNDS≥256`) attached to a release tag —
   collect with `scripts/collect-release-evidence.ps1` (Windows) or
   `GATE7_SOAK_ROUNDS=256 ./scripts/collect-release-evidence.sh` (WSL/Linux)
3. Signed artifacts + provenance on a published GitHub Release
4. Mediated network must **not** become the default profile without (1)

## Collectors

| Host | Command | Output |
| --- | --- | --- |
| Windows | `powershell -File scripts/collect-release-evidence.ps1` | `release-out/EVIDENCE.windows.md` |
| WSL2 / Linux | `./scripts/collect-release-evidence.sh` | `release-out/EVIDENCE.md` |
| WSL2 suite-only | `./scripts/run-wsl-ga-tests.sh` | stdout (refuse `/mnt/*`) |