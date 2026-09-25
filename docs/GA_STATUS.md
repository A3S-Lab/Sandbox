# a3s-sandbox enterprise GA status

Authoritative status board for the enterprise GA objective. Update only from
live evidence (CI, local collectors, release artifacts, reviewer attestation).

Last engineering update: 2026-09-25 — **`v0.2.0` published**.
CI green on the release commit `031849a` (windows/macos/ubuntu); GitHub
Release carries SHA256SUMS, provenance.json, SBOM, EVIDENCE.md, and
darwin-arm64 binaries. macOS host evidence collector fixed for bash 3.2
empty-array expansion during this cut.

## Claim split (do not collapse)

| Claim | Meaning | Status |
| --- | --- | --- |
| **A. Deny-all production boundary** | Default A3S Bash profile is fail-closed OS isolation; mediation off | **Shipped: `v0.1.5`, re-cut as `v0.2.0`** — CI green on the release commit, Release page carries provenance |
| **B. Mediated-network-as-default** | Any profile may turn mediation on by default | **Blocked** on independent review sign-off |

Enterprise GA for this crate means **A is shipped and evidenced**, and **B stays
explicitly refused** until an independent reviewer signs
[`INDEPENDENT_REVIEW.md`](INDEPENDENT_REVIEW.md).

## Gate evidence (Claim A)

| Requirement | Evidence | Status |
| --- | --- | --- |
| Windows / Linux / macOS CI | Actions run on `eec5229` (`v0.1.5`) and tip `5b2e46d` — all `check (*)` success | **Verified** |
| Windows AppContainer local | Full suite + soak 256 + CONNECT live proof | Verified locally |
| WSL2 native-FS local | Full suite + soak 256 + SBOM/provenance | Verified locally |
| ACL hang fix | `SetKernelObjectSecurity` for non-inheriting grants | On `main` |
| Default mediation off | `gate7_release_invariants` | On `main` |
| Code on default branch | `origin/main` includes `eec5229`+ | **Done** |
| Annotated tag | `v0.1.5` → `eec5229` | **Done** |
| GitHub Release + provenance assets | Release page for `v0.1.5` | **Open** — `gh` unauthenticated here |
| Independent review (Claim B only) | External attestation | **Open** |

### CI runs

- `v0.2.0` release commit `031849a`: https://github.com/A3S-Lab/Sandbox/actions/runs/36152909937 (windows/ubuntu/macos success)
- `v0.1.5` tag commit `eec5229`: https://github.com/A3S-Lab/Sandbox/actions/runs/36084293634 (windows/ubuntu/macos success)
- `v0.1.5` tip `5b2e46d`: https://github.com/A3S-Lab/Sandbox/actions/runs/36084473762 (windows/ubuntu/macos success)

## Publish path

```text
main tip @ 5b2e46d
tag v0.1.5 -> eec5229
After: gh auth login   # or GH_TOKEN
  ./scripts/publish-ga-release.sh
# or: collect evidence then
#   gh release create v0.1.5 ./release-out/* --notes-file docs/RELEASE_NOTES_0.1.5.md
```

## First-principles refusal

Do **not** mark enterprise GA complete by:

- treating local green as a substitute for CI on the release commit;
- self-signing `INDEPENDENT_REVIEW.md`;
- enabling `mediated_network` on the default profile;
- claiming Claim B when only Claim A evidence exists;
- claiming Claim A complete before the GitHub Release carries provenance.
