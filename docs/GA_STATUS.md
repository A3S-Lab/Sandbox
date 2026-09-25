# a3s-sandbox enterprise GA status

Authoritative status board for the enterprise GA objective. Update only from
live evidence (CI, local collectors, release artifacts, reviewer attestation).

Last engineering update: 2026-09-25 — candidate `0.1.5` on
`release/0.1.5-windows-wsl-ga` @ `4bb995e`.

## Claim split (do not collapse)

| Claim | Meaning | Status |
| --- | --- | --- |
| **A. Deny-all production boundary** | Default A3S Bash profile is fail-closed OS isolation; mediation off | **Ready after** merge + `v0.1.5` GitHub Release with provenance |
| **B. Mediated-network-as-default** | Any profile may turn mediation on by default | **Blocked** on independent review sign-off |

Enterprise GA for this crate means **A is shipped and evidenced**, and **B stays
explicitly refused** until an independent reviewer signs
[`INDEPENDENT_REVIEW.md`](INDEPENDENT_REVIEW.md).

## Gate evidence (Claim A)

| Requirement | Evidence | Status |
| --- | --- | --- |
| Windows AppContainer suite | Local `cargo test --all-targets -- --test-threads=1` → 161 lib + 3 CLI | Verified locally |
| Windows soak ≥256 | `GATE7_SOAK_ROUNDS=256` soak test → ok ~427s | Verified locally |
| Windows CONNECT live proof | `windows_appcontainer_named_pipe_connect_allow_deny_and_blocks_raw_egress` | Verified locally |
| WSL2 native-FS suite | `scripts/run-wsl-ga-tests.sh` / evidence collector → 175+3+1 | Verified locally |
| WSL soak ≥256 + SBOM/provenance | `collect-release-evidence.sh` → `release-out/EVIDENCE.wsl.md` | Verified locally |
| ACL hang fix | `SetKernelObjectSecurity` path + Temp pollution root cause | In `4bb995e` |
| Default mediation off | `gate7_release_invariants` | In tree |
| CI matrix green on tip | GitHub Actions on PR/main | **Open** — PR not created (`gh` unauthenticated) |
| Tag `v0.1.5` + Release assets | GitHub Release + SHA256/provenance | **Open** — needs merge + token |
| Independent review (Claim B only) | External attestation | **Open** — cannot be self-signed |

## Branch / publish path

```text
origin/release/0.1.5-windows-wsl-ga @ 4bb995e
PR create URL:
https://github.com/A3S-Lab/Sandbox/pull/new/release/0.1.5-windows-wsl-ga
```

Blocked automation: `gh auth login` / `GH_TOKEN` required to open PR, watch
checks, tag, and attach release assets from this environment.

## First-principles refusal

Do **not** mark enterprise GA complete by:

- treating local green as a substitute for CI on the release commit;
- self-signing `INDEPENDENT_REVIEW.md`;
- enabling `mediated_network` on the default profile;
- claiming Claim B when only Claim A evidence exists.
