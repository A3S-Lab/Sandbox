# Collect Gate 7 release evidence on native Windows (PowerShell).
# Prefer this over Git Bash when verifying AppContainer fences.
#
# Usage:
#   powershell -File scripts/collect-release-evidence.ps1
#   $env:GATE7_SOAK_ROUNDS=256; powershell -File scripts/collect-release-evidence.ps1
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $Root
$Out = if ($env:OUT_DIR) { $env:OUT_DIR } else { Join-Path $Root 'release-out' }
New-Item -ItemType Directory -Force -Path $Out | Out-Null
$Report = Join-Path $Out 'EVIDENCE.windows.md'
$SoakRounds = if ($env:GATE7_SOAK_ROUNDS) { $env:GATE7_SOAK_ROUNDS } else { '64' }

function Log([string]$Line) {
  Add-Content -Path $Report -Value $Line
  Write-Host $Line
}

'' | Set-Content -Path $Report
$Git = try { git rev-parse HEAD } catch { 'unknown' }
$Version = (Select-String -Path Cargo.toml -Pattern '^version = "([^"]+)"').Matches[0].Groups[1].Value
$Dirty = @(git status --porcelain).Count

Log '# a3s-sandbox Windows release evidence'
Log ''
Log ("- collected: {0:yyyy-MM-ddTHH:mm:ssZ}" -f (Get-Date).ToUniversalTime())
Log ("- host: {0} {1}" -f [Environment]::OSVersion.VersionString, $env:PROCESSOR_ARCHITECTURE)
Log "- git: $Git"
Log "- crate: $Version"
Log "- dirty: $Dirty paths"
Log "- soak rounds: $SoakRounds"
Log ''

Log '## fmt'
cargo fmt --all -- --check
Log '- cargo fmt --all -- --check: OK'
Log ''

Log '## clippy'
cargo clippy --all-targets -- -D warnings
Log '- cargo clippy --all-targets -- -D warnings: OK'
Log ''

Log '## tests'
$env:GATE7_SOAK_ROUNDS = $SoakRounds
cargo test --all-targets -- --test-threads=1
Log '- cargo test --all-targets -- --test-threads=1: OK'
Log ''

Log '## Gate 7 soak'
$env:GATE7_SOAK_ROUNDS = $SoakRounds
cargo test --lib gate7_soak_repeated_baseline_executes_stay_stable -- --nocapture --test-threads=1
Log "- soak rounds=${SoakRounds}: OK"
Log ''

Log '## Windows mediation live proof'
cargo test --lib windows_appcontainer_named_pipe_connect_allow_deny_and_blocks_raw_egress -- --nocapture --test-threads=1
Log '- windows AppContainer named-pipe CONNECT allow/deny/egress: OK'
Log ''

Log '## release binaries'
cargo build --release -q
$Arts = @()
if (Test-Path 'target/release/a3s-sandbox.exe') { $Arts += 'target/release/a3s-sandbox.exe' }
if (Test-Path 'target/release/a3s-sandbox-relay.exe') { $Arts += 'target/release/a3s-sandbox-relay.exe' }
Log ("- built: {0}" -f ($Arts -join ', '))
Get-FileHash -Algorithm SHA256 $Arts | ForEach-Object {
  $line = "{0}  {1}" -f $_.Hash.ToLowerInvariant(), $_.Path
  $line | Add-Content (Join-Path $Out 'SHA256SUMS')
  Log "- sha256: $line"
}
Log ''

Log '## remaining external gates'
Log '- [x] Windows live pipe proof green (this host)'
Log '- [ ] Independent review sign-off (docs/INDEPENDENT_REVIEW.md)'
Log '- [ ] Attach provenance to published GitHub Release + tag'
Log '- [ ] Version bump + CHANGELOG cut from Unreleased (if cutting a release)'
Log ''
Log 'Evidence collection finished.'
Write-Host "wrote $Report"
