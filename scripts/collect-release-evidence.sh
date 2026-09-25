#!/usr/bin/env bash
# Collect local Gate 7 release evidence into release-out/.
#
# This does NOT publish a GitHub Release or replace independent review.
# It produces artifacts a release manager can attach after review sign-off.
#
# Usage:
#   ./scripts/collect-release-evidence.sh
#   GATE7_SOAK_ROUNDS=256 ./scripts/collect-release-evidence.sh
#
# Windows hosts: run from Git Bash or WSL against a native checkout. AppContainer
# soaks need --test-threads=1 (set automatically when uname is MINGW*/MSYS*/CYGWIN*).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
OUT="${OUT_DIR:-$ROOT/release-out}"
mkdir -p "$OUT"
REPORT="$OUT/EVIDENCE.md"
: >"$REPORT"

HOST="$(uname -s 2>/dev/null || echo unknown)"
ARCH="$(uname -m 2>/dev/null || echo unknown)"
case "$HOST" in
  MINGW*|MSYS*|CYGWIN*)
    TEST_THREADS=(-- --test-threads=1)
    SOAK_THREADS=(-- --nocapture --test-threads=1)
    ;;
  *)
    TEST_THREADS=()
    SOAK_THREADS=(-- --nocapture)
    ;;
esac

log() {
  echo "$@" | tee -a "$REPORT"
}

log "# a3s-sandbox release evidence"
log ""
log "- collected: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
log "- host: ${HOST} ${ARCH}"
log "- git: $(git rev-parse HEAD 2>/dev/null || echo unknown)"
log "- crate: $(sed -n 's/^version = \"\(.*\)\"/\1/p' Cargo.toml | head -1)"
log "- dirty: $(git status --porcelain 2>/dev/null | wc -l | tr -d ' ') paths"
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
cargo test --all-targets "${TEST_THREADS[@]}"
log "- cargo test --all-targets: OK"
log ""

log "## Gate 7 soak (optional longer via GATE7_SOAK_ROUNDS)"
SOAK_ROUNDS="${GATE7_SOAK_ROUNDS:-64}"
GATE7_SOAK_ROUNDS="$SOAK_ROUNDS" \
  cargo test --lib gate7_soak_repeated_baseline_executes_stay_stable "${SOAK_THREADS[@]}"
log "- soak rounds=${SOAK_ROUNDS}: OK"
log ""

log "## Windows mediation live proof (when on Windows)"
case "$HOST" in
  MINGW*|MSYS*|CYGWIN*)
    cargo test --lib windows_appcontainer_named_pipe_connect_allow_deny_and_blocks_raw_egress \
      -- --nocapture --test-threads=1
    log "- windows AppContainer named-pipe CONNECT allow/deny/egress: OK"
    ;;
  *)
    log "- skipped (not a Windows host); rely on Windows CI / docs/WINDOWS_WSL_GA.md"
    ;;
esac
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
elif [[ -f target/release/a3s-sandbox-relay.exe ]]; then
  ARTS+=(target/release/a3s-sandbox-relay.exe)
fi
# Windows cargo emits .exe
if [[ -f target/release/a3s-sandbox.exe ]]; then
  ARTS=(target/release/a3s-sandbox.exe)
  if [[ -f target/release/a3s-sandbox-relay.exe ]]; then
    ARTS+=(target/release/a3s-sandbox-relay.exe)
  fi
fi
OUT_DIR="$OUT" ./scripts/sign-release.sh "${ARTS[@]}"
log "- sign-release artifacts in $OUT"
log ""

log "## remaining external gates"
log "- [x] Windows live pipe proof green when collected on Windows (see above)"
log "- [ ] Independent review sign-off (docs/INDEPENDENT_REVIEW.md)"
log "- [ ] Attach provenance to published GitHub Release + tag"
log "- [ ] Version bump + CHANGELOG cut from Unreleased (if cutting a release)"
log ""
log "Evidence collection finished."
echo "wrote $REPORT"
