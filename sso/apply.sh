#!/usr/bin/env bash
# Produce an SSO-integrated HyperDX source tree at a chosen upstream tag.
#
#   sso/apply.sh <upstream-tag> [out-dir]
#   sso/apply.sh '@hyperdx/app@2.42.0' build
#
# Checks out the requested upstream tag into a clean git worktree, applies the
# upstream security patches it lacks, then runs the deterministic
# overlay+codemod. The result in <out-dir> is ready to feed to `docker build`
# (docker/hyperdx/Dockerfile, target prod).
set -euo pipefail

TAG="${1:?usage: sso/apply.sh <upstream-tag> [out-dir]}"
OUT="${2:-build}"

if [[ ! "$TAG" =~ ^@hyperdx/app@[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "[sso] invalid upstream tag: $TAG" >&2
  exit 1
fi

# Upstream commits not yet in a release, cherry-picked onto the tag. Each is
# skipped once the tag contains it, so this list only needs pruning, not care.
UPSTREAM_PATCHES=(
  947b0678f5647d0efcba174d2854329545beb8d0 # next 16.3.8 -> 16.4.1 (RCE advisories)
)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel)"
cd "$REPO_ROOT"

UPSTREAM_URL="https://github.com/hyperdxio/hyperdx.git"
# Fetched into a private namespace: this fork also carries tags with upstream
# names (e.g. made by inherited release workflows), and those must never be
# what gets built.
REF="refs/sso-upstream/tags/${TAG}"

echo "[sso] fetching tag $TAG from $UPSTREAM_URL"
git fetch --no-tags --force "$UPSTREAM_URL" "refs/tags/${TAG}:${REF}"
echo "[sso] $TAG -> $(git rev-parse "${REF}^{commit}")"

echo "[sso] preparing worktree at $OUT"
git worktree remove --force "$OUT" 2>/dev/null || true
rm -rf "$OUT"
git worktree add --detach "$OUT" "${REF}^{commit}"

for sha in "${UPSTREAM_PATCHES[@]}"; do
  git fetch --no-tags --quiet "$UPSTREAM_URL" "$sha"
  if git merge-base --is-ancestor "$sha" "${REF}^{commit}"; then
    echo "[sso] $TAG already contains $sha, skipping"
    continue
  fi
  echo "[sso] applying upstream patch $sha"
  git -C "$OUT" cherry-pick --no-commit "$sha"
done

node "$SCRIPT_DIR/integrate.mjs" "$OUT"

echo "[sso] integrated '$TAG' -> $OUT"
