#!/usr/bin/env bash
# Generate a CycloneDX 1.5 JSON SBOM from `cargo metadata` (no extra crates).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
OUT="${1:-sbom.cdx.json}"
META="$(mktemp)"
trap 'rm -f "$META"' EXIT
cargo metadata --format-version 1 --manifest-path Cargo.toml >"$META"
python3 - "$META" "$OUT" <<'PY'
import json, sys, datetime, hashlib, uuid

meta_path, out_path = sys.argv[1], sys.argv[2]
meta = json.load(open(meta_path))
resolve = {p["id"]: p for p in meta["packages"]}
root_ids = set(meta["workspace_members"])

components = []
for pkg_id in sorted(resolve):
    pkg = resolve[pkg_id]
    purl = f"pkg:cargo/{pkg['name']}@{pkg['version']}"
    components.append({
        "type": "library",
        "bom-ref": pkg_id,
        "name": pkg["name"],
        "version": pkg["version"],
        "purl": purl,
        "scope": "required" if pkg_id in root_ids else "optional",
    })

bom = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "serialNumber": f"urn:uuid:{uuid.uuid4()}",
    "version": 1,
    "metadata": {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "tools": {"components": [{"type": "application", "name": "a3s-sandbox-sbom", "version": "0.1.3"}]},
        "component": {
            "type": "library",
            "name": "a3s-sandbox",
            "version": resolve[next(iter(root_ids))]["version"] if root_ids else "0.0.0",
            "purl": "pkg:cargo/a3s-sandbox",
        },
    },
    "components": components,
}

raw = json.dumps(bom, indent=2, sort_keys=True) + "\n"
open(out_path, "w").write(raw)
digest = hashlib.sha256(raw.encode()).hexdigest()
print(f"wrote {out_path} components={len(components)} sha256={digest}")
PY
