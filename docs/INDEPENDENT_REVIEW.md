# Independent security review package

This package gathers the evidence an external reviewer needs before any
profile makes mediated network the **default**. Completing in-tree Gate 7
tests is necessary but not sufficient.

## Scope

Review `a3s-sandbox` native OS fences and host-supervised mediators for:

- macOS Seatbelt (network deny-all + mediated HTTP/SOCKS + Unix allowlists)
- Linux namespaces/seccomp (network deny-all + mediated HTTP via Unix bridge)
- Windows AppContainer/Job (network deny-all + mediated HTTP via inherited
  named-pipe handle)

## Required reading

1. [`../THREAT_MODEL.md`](../THREAT_MODEL.md)
2. [`../ROADMAP.md`](../ROADMAP.md) Gate 7 section
3. [`RELEASE_CHECKLIST.md`](RELEASE_CHECKLIST.md)
4. Capability matrix from `a3s-sandbox probe` / `capabilities`

## Evidence to verify (do not trust docs alone)

| Claim | How to verify |
| --- | --- |
| Default profile fail-closed | Inspect `SandboxPolicy::a3s_bash_baseline` — `mediated_network` / `mediated_socks` off |
| macOS mediated HTTP | Live guest allow/deny + Seatbelt fence tests under `policy::gate4_integration` |
| Linux mediated HTTP | OrbStack/Linux guest allow/deny/egress under `platform::linux` bridge tests |
| Windows mediated HTTP | Live AppContainer pipe allow/deny/egress under `platform::windows` + `gate5_windows_bridge` |
| CONNECT DoS bounds | `network::connect` 8KiB/16KiB limits + `policy::gate7_fuzz` |
| Soak / p50 | `policy::gate7_integration` (optional `GATE7_SOAK_ROUNDS`) |
| In-command races | `gate7_in_command_symlink_swap_during_sleep_does_not_leak` |
| Release invariants | `policy::gate7_release_invariants` |
| SBOM | `./scripts/generate-sbom.sh` |
| Checksums / signatures | `./scripts/sign-release.sh <bins>` |
| Local evidence bundle | `./scripts/collect-release-evidence.sh` → `release-out/` |

## Sign-off template

Reviewer records (PR comment or release attestation):

```text
Reviewer: <name>
Date: <ISO-8601>
Commit: <sha>
Platforms exercised: <macos|linux|windows>
Findings: <none | link to issues>
Mediated-as-default approved: NO (required unless findings are empty and
all claiming OS live fences were re-run by the reviewer)
```

Mediated network must **not** become the default profile without an explicit
`Mediated-as-default approved: YES` from an independent reviewer.
