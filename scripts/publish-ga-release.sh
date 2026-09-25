#!/usr/bin/env bash
# Publish Claim A (deny-all) enterprise GA cut for a3s-sandbox.
#
# Prerequisites:
#   - gh authenticated with repo + release permissions
#   - clean working tree on the release commit
#   - CI already green on that commit (PR merge or main tip)
#
# Does NOT approve mediated-as-default (Claim B).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

VERSION="$(sed -n 's/^version = \"\(.*\)\"/\1/p' Cargo.toml | head -1)"
TAG="v${VERSION}"
COMMIT="$(git rev-parse HEAD)"
BRANCH="$(git rev-parse --abbrev-ref HEAD)"

if [[ -n "$(git status --porcelain)" ]]; then
  echo "error: working tree dirty; commit or stash first" >&2
  exit 2
fi

if ! command -v gh >/dev/null 2>&1; then
  echo "error: gh CLI required" >&2
  exit 2
fi

if ! gh auth status >/dev/null 2>&1; then
  echo "error: gh not authenticated (gh auth login / GH_TOKEN)" >&2
  exit 2
fi

echo "Publishing ${TAG} at ${COMMIT} (branch ${BRANCH})"
echo "Claim B (mediated-as-default) remains refused."

# Ensure an open PR exists from this branch when not on main.
if [[ "$BRANCH" != "main" ]]; then
  if ! gh pr view --json url >/dev/null 2>&1; then
    gh pr create \
      --base main \
      --head "$BRANCH" \
      --title "release: ${VERSION} Windows/WSL enterprise GA candidate" \
      --body-file docs/RELEASE_NOTES_0.1.5.md
  fi
  echo "Waiting for PR checks..."
  gh pr checks --watch
  gh pr merge --merge --delete-branch=false
  git fetch origin main
  git checkout main
  git pull --ff-only origin main
  COMMIT="$(git rev-parse HEAD)"
fi

OUT="${OUT_DIR:-$ROOT/release-out}"
rm -rf "$OUT"
GATE7_SOAK_ROUNDS="${GATE7_SOAK_ROUNDS:-256}" ./scripts/collect-release-evidence.sh

if git rev-parse "$TAG" >/dev/null 2>&1; then
  echo "tag ${TAG} already exists locally"
else
  git tag -a "$TAG" -m "a3s-sandbox ${TAG} deny-all production boundary"
fi
git push origin "refs/tags/${TAG}"

NOTES="$OUT/RELEASE_BODY.md"
{
  cat docs/RELEASE_NOTES_0.1.5.md
  echo
  echo "## Provenance"
  echo
  echo "- commit: \`${COMMIT}\`"
  echo "- tag: \`${TAG}\`"
  echo "- claim: deny-all production boundary (Claim A)"
  echo "- mediated-as-default: NO"
  echo
  if [[ -f "$OUT/EVIDENCE.md" ]]; then
    echo "## Collector evidence"
    echo
    echo '```'
    head -n 40 "$OUT/EVIDENCE.md"
    echo '```'
  fi
} >"$NOTES"

ASSETS=()
for f in SHA256SUMS provenance.json sbom.cdx.json EVIDENCE.md; do
  if [[ -f "$OUT/$f" ]]; then
    ASSETS+=("$OUT/$f")
  fi
done
# Prefer release binaries if present.
shopt -s nullglob
for bin in "$OUT"/a3s-sandbox "$OUT"/a3s-sandbox.exe "$OUT"/a3s-sandbox-relay "$OUT"/a3s-sandbox-relay.exe; do
  ASSETS+=("$bin")
done
shopt -u nullglob

if gh release view "$TAG" >/dev/null 2>&1; then
  gh release upload "$TAG" "${ASSETS[@]}" --clobber
else
  gh release create "$TAG" "${ASSETS[@]}" \
    --title "a3s-sandbox ${TAG}" \
    --notes-file "$NOTES"
fi

echo "Published ${TAG}. Update docs/GA_STATUS.md Claim A after verifying the Release page."
echo "Claim B still requires independent review sign-off."
