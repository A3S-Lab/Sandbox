#!/usr/bin/env bash
# Collect local Gate 7 release evidence into release-out/.
#
# This does NOT publish a GitHub Release or replace independent review.
# It produces artifacts a release manager can attach after review sign-off.
#
# Usage:
#   ./scripts/collect-release-evidence.sh
#   GATE7_SOAK_ROUNDS=256 ./scripts/collect-release-evidence.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
OUT="${OUT_DIR:-$ROOT/release-out}"
mkdir -p "$OUT"
REPORT="$OUT/EVIDENCE.md"
: >"$REPORT"

log() {
  echo "$@" | tee -a "$REPORT"
}

log "# a3s-sandbox release evidence"
log ""
log "- collected: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
log "- host: $(uname -s) $(uname -m)"
log "- git: $(git rev-parse HEAD 2>/dev/null || echo unknown)"
log "- crate: $(sed -n 's/^version = \"\(.*\)\"/\1/p' Cargo.toml | head -1)"
log ""

log "## fmt"
cargo fmt --all -- --check
log "- cargo fmt --all -- --check: OK"
log ""

log "## clippy"
cargo clippy --all-targets -- -D warnings
log "- cargo clippy --all-targets -- -D warnings: OK"
log ""

log "## tests"
cargo test --all-targets
log "- cargo test --all-targets: OK"
log ""

log "## Gate 7 soak (optional longer via GATE7_SOAK_ROUNDS)"
GATE7_SOAK_ROUNDS="${GATE7_SOAK_ROUNDS:-64}" \
  cargo test --lib gate7_soak_repeated_baseline_executes_stay_stable -- --nocapture
log "- soak rounds=${GATE7_SOAK_ROUNDS:-64}: OK"
log ""

log "## SBOM"
./scripts/generate-sbom.sh "$OUT/sbom.cdx.json"
log "- wrote $OUT/sbom.cdx.json"
log ""

log "## release binaries + provenance"
cargo build --release -q
ARTS=(target/release/a3s-sandbox)
if [[ -f target/release/a3s-sandbox-relay ]]; then
  ARTS+=(target/release/a3s-sandbox-relay)
fi
OUT_DIR="$OUT" ./scripts/sign-release.sh "${ARTS[@]}"
log "- sign-release artifacts in $OUT"
log ""

log "## remaining external gates"
log "- [ ] Windows live pipe proof green (if claiming Windows mediation)"
log "- [ ] Independent review sign-off (docs/INDEPENDENT_REVIEW.md)"
log "- [ ] Attach provenance to published GitHub Release + tag"
log "- [ ] Version bump + CHANGELOG cut from Unreleased"
log ""
log "Evidence collection finished."
echo "wrote $REPORT"
