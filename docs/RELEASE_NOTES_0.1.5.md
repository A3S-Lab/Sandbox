# a3s-sandbox 0.1.5

## Highlights

- Windows AppContainer no longer hangs when granting ancestor traverse ACLs on
  polluted directories such as `%TEMP%` (uses `SetKernelObjectSecurity` for
  non-inheriting updates).
- User-owned PATH toolchains get non-inheritable execute grants; `WindowsApps`
  execution aliases are skipped.
- WSL2 GA path: native filesystem runner + evidence collectors; refuse `/mnt/*`.

## Verify

```bash
# Windows
powershell -File scripts/collect-release-evidence.ps1

# WSL2 (native ext4/xfs copy — not /mnt/<drive>)
./scripts/run-wsl-ga-tests.sh
GATE7_SOAK_ROUNDS=256 ./scripts/collect-release-evidence.sh
```

## Release attach checklist

1. Merge `release/0.1.5-windows-wsl-ga` with CI green.
2. Tag `v0.1.5` at the merge commit.
3. Attach `release-out/SHA256SUMS`, `provenance.json`, and SBOM from
   `scripts/collect-release-evidence.sh` (Linux/WSL) and
   `scripts/collect-release-evidence.ps1` (Windows).
4. Record independent review only if approving mediated-as-default (not part of
   this deny-all production cut).
