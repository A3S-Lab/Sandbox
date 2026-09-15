#!/usr/bin/env bash
# Produce release provenance for a3s-sandbox artifacts.
#
# Creates:
#   - SHA-256 checksums for the listed files
#   - optional cosign keyless / key-based signatures when `cosign` is installed
#
# Usage:
#   ./scripts/sign-release.sh dist/a3s-sandbox dist/a3s-sandbox-relay
#   OUT_DIR=./release-out ./scripts/sign-release.sh target/release/a3s-sandbox
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="${OUT_DIR:-$ROOT/release-out}"
mkdir -p "$OUT_DIR"

if [[ $# -lt 1 ]]; then
  echo "usage: $0 <artifact> [artifact...]" >&2
  exit 2
fi

CHECKSUMS="$OUT_DIR/SHA256SUMS"
: >"$CHECKSUMS"

for artifact in "$@"; do
  if [[ ! -f "$artifact" ]]; then
    echo "missing artifact: $artifact" >&2
    exit 1
  fi
  base="$(basename "$artifact")"
  cp -f "$artifact" "$OUT_DIR/$base"
  (
    cd "$OUT_DIR"
    if command -v shasum >/dev/null 2>&1; then
      shasum -a 256 "$base" >>SHA256SUMS
    else
      sha256sum "$base" >>SHA256SUMS
    fi
  )
done

echo "wrote $CHECKSUMS"
cat "$CHECKSUMS"

if command -v cosign >/dev/null 2>&1; then
  echo "cosign found; signing artifacts in $OUT_DIR"
  while read -r _hash file; do
    [[ -z "${file:-}" ]] && continue
    cosign sign-blob --yes --output-signature "$OUT_DIR/${file}.sig" "$OUT_DIR/$file"
    cosign verify-blob --signature "$OUT_DIR/${file}.sig" "$OUT_DIR/$file" >/dev/null
    echo "signed $file"
  done <"$CHECKSUMS"
else
  echo "cosign not installed; checksums only (install cosign for signatures)" >&2
fi

# Provenance stub for review packages (filled by CI with real build metadata).
PROV="$OUT_DIR/provenance.json"
python3 - "$PROV" "$CHECKSUMS" <<'PY'
import json, sys, datetime, pathlib
out, sums = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
entries = []
for line in sums.read_text().splitlines():
    line = line.strip()
    if not line:
        continue
    digest, name = line.split(None, 1)
    entries.append({"path": name, "sha256": digest})
payload = {
    "type": "a3s-sandbox-release-provenance",
    "created": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "artifacts": entries,
    "notes": "Attach CI run URL, git SHA, and cosign bundle when publishing.",
}
out.write_text(json.dumps(payload, indent=2) + "\n")
print(f"wrote {out}")
PY
