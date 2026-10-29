#!/usr/bin/env bash
# Produce an SSO-integrated HyperDX source tree at a chosen upstream tag.
#
#   sso/apply.sh <upstream-tag> [out-dir]
#   sso/apply.sh '@hyperdx/app@2.28.0' build
#
# Checks out the requested upstream tag into a clean git worktree, then runs
# the deterministic overlay+codemod. The result in <out-dir> is ready to feed
# to `docker build` (docker/hyperdx/Dockerfile, target prod).
set -euo pipefail

TAG="${1:?usage: sso/apply.sh <upstream-tag> [out-dir]}"
OUT="${2:-build}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel)"
cd "$REPO_ROOT"

UPSTREAM_URL="https://github.com/hyperdxio/hyperdx.git"
if ! git remote get-url upstream >/dev/null 2>&1; then
  echo "[sso] adding 'upstream' remote -> $UPSTREAM_URL"
  git remote add upstream "$UPSTREAM_URL"
fi

echo "[sso] fetching tag $TAG"
# Forced (+): a same-named tag may already exist locally (e.g. the CI checkout
# of the fork, fetch-depth 0, copies every tag the fork holds). Without + git
# refuses with "would clobber existing tag" and the build dies before the
# overlay is applied. Upstream is the source of truth for upstream tags.
git fetch --no-tags upstream "+refs/tags/${TAG}:refs/tags/${TAG}"

echo "[sso] preparing worktree at $OUT"
git worktree remove --force "$OUT" 2>/dev/null || true
rm -rf "$OUT"
git worktree add --detach "$OUT" "refs/tags/${TAG}"

node "$SCRIPT_DIR/integrate.mjs" "$OUT"

echo "[sso] integrated '$TAG' -> $OUT"
