#!/usr/bin/env bash
# Run a3s-sandbox Gate 0–7 tests on WSL2 from a native Linux filesystem.
#
# Do NOT run against /mnt/<drive>/... — the monorepo workspace scan and
# bubblewrap bind mounts are pathologically slow (or flaky) on 9p.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
if [[ "$ROOT" == /mnt/* ]]; then
  echo "error: refuse WSL GA from '$ROOT' (9p mount)." >&2
  echo "copy the crate to a native path, for example:" >&2
  echo "  rsync -a --exclude target --exclude .git '$ROOT'/ ~/a3s-sandbox-ga/" >&2
  echo "  ~/a3s-sandbox-ga/scripts/run-wsl-ga-tests.sh" >&2
  exit 2
fi

if ! command -v bwrap >/dev/null 2>&1; then
  echo "error: bubblewrap (bwrap) is required on WSL." >&2
  exit 2
fi

# Ensure scripts stay LF even when the tree was synced from a Windows checkout.
find "$ROOT/scripts" -name '*.sh' -print0 2>/dev/null | xargs -0 -r sed -i 's/\r$//'

export GATE7_SOAK_ROUNDS="${GATE7_SOAK_ROUNDS:-8}"
cd "$ROOT"
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo build --bins
cargo test --all-targets -- --test-threads=1
