# a3s-sandbox enterprise GA status

Authoritative status board for the enterprise GA objective. Update only from
live evidence (CI, local collectors, release artifacts, reviewer attestation).

Last engineering update: 2026-09-25 — **`v0.1.5` tagged** at `eec5229` on `main`.

## Claim split (do not collapse)

| Claim | Meaning | Status |
| --- | --- | --- |
| **A. Deny-all production boundary** | Default A3S Bash profile is fail-closed OS isolation; mediation off | **In progress** — code on `main` + tag `v0.1.5`; awaiting CI green + GitHub Release assets |
| **B. Mediated-network-as-default** | Any profile may turn mediation on by default | **Blocked** on independent review sign-off |

Enterprise GA for this crate means **A is shipped and evidenced**, and **B stays
explicitly refused** until an independent reviewer signs
[`INDEPENDENT_REVIEW.md`](INDEPENDENT_REVIEW.md).

## Gate evidence (Claim A)

| Requirement | Evidence | Status |
| --- | --- | --- |
| Windows AppContainer suite | Local full suite + soak 256 + CONNECT proof | Verified locally |
| WSL2 native-FS suite | Local full suite + soak 256 + SBOM/provenance | Verified locally |
| ACL hang fix | `SetKernelObjectSecurity` for non-inheriting grants | On `main` @ `eec5229` |
| Default mediation off | `gate7_release_invariants` | On `main` |
| Code on default branch | `origin/main` @ `eec5229` | **Done** |
| Annotated tag | `v0.1.5` → `eec5229` | **Done** |
| CI matrix green on tip | Actions on `main` / tag | **Verify** |
| GitHub Release + provenance assets | Release page with SHA256/SBOM/EVIDENCE | **Open** (`gh` auth required) |
| Independent review (Claim B only) | External attestation | **Open** |

## Publish path

```text
main @ eec5229 = v0.1.5
Attach assets (after gh auth):
  ./scripts/publish-ga-release.sh
# or manually: collect-release-evidence + gh release create v0.1.5 ...
```

## First-principles refusal

Do **not** mark enterprise GA complete by:

- treating local green as a substitute for CI on the release commit;
- self-signing `INDEPENDENT_REVIEW.md`;
- enabling `mediated_network` on the default profile;
- claiming Claim B when only Claim A evidence exists;
- claiming Claim A complete before the GitHub Release carries provenance.