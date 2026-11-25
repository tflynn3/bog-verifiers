#!/bin/sh
set -eu

reject() {
  printf '%s\n' "$1" >&2
  { printf '%s\n' "$1" > /dev/termination-log; } 2>/dev/null || true
  exit 1
}

infra() {
  printf 'Bog verifier infrastructure error: %s\n' "$1" >&2
  exit 2
}

# The bootstrap image and explicit full invocation use the same entrypoint.
if [ "${1:-}" = --full ]; then
  shift
fi
[ "$#" -eq 0 ] || infra 'usage: verify.sh [--full]'

repository=${SLIPWAY_REPOSITORY:-}
branch=${SLIPWAY_CANDIDATE_BRANCH:-}
expected=${SLIPWAY_CANDIDATE_COMMIT:-}
# The conductor's post-cycle probe supplies the tested main SHA in general mode.
if [ -z "$repository$branch$expected" ] && [ "${SLIPWAY_PARAM_MODE:-}" = post-cycle ]; then
  repository=http://bog-git.kagent.svc.cluster.local/bog.git
  branch=main
  expected=${SLIPWAY_INPUT_TESTEDCOMMIT:-}
fi
[ -n "$repository" ] && [ -n "$branch" ] && [ -n "$expected" ] ||
  reject 'missing Bog candidate inputs: repository, branch and full commit SHA are required (suites=0)'
case "$expected" in
  *[!0-9a-f]*) reject 'Bog candidate commit must be a full lowercase SHA-1 (suites=0)' ;;
esac
[ "${#expected}" -eq 40 ] || reject 'Bog candidate commit must be a full lowercase SHA-1 (suites=0)'

for tool in git go python3 timeout; do
  command -v "$tool" >/dev/null || infra "missing verifier tool: $tool"
done
ref="refs/heads/$branch"
git check-ref-format "$ref" || reject 'invalid Bog candidate branch (suites=0)'
verifier_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd) || infra 'cannot locate verifier'
work=$(mktemp -d /tmp/bog-verify-XXXXXX) || infra 'cannot create verifier workspace'
trap 'rm -rf "$work"' EXIT
trap 'exit 2' HUP INT TERM
checkout="$work/source"

export GIT_TERMINAL_PROMPT=0 GIT_ALLOW_PROTOCOL=file:http:https:ssh
git init -q "$checkout" || infra 'cannot initialize checkout'
timeout -k 5s 60s git -C "$checkout" fetch -q --no-tags -- "$repository" "$ref" ||
  infra "cannot fetch Bog candidate branch $ref (suites=0)"
sha=$(git -C "$checkout" rev-parse --verify 'FETCH_HEAD^{commit}') || infra 'cannot resolve fetched commit'
[ "$sha" = "$expected" ] || reject "Bog revision mismatch: fetched $sha, expected $expected (suites=0)"
git -C "$checkout" checkout -q --detach "$sha" || infra "cannot check out Bog revision $sha"
[ "$(git -C "$checkout" rev-parse --verify HEAD)" = "$sha" ] || infra 'checked-out SHA did not match the verified fetch'
printf 'bog full verification candidate_sha=%s\n' "$sha"

status=0
timeout -k 5s 240s python3 -B -u "$verifier_dir/verify.py" "$checkout" "$work" "$sha" || status=$?
case "$status" in
  0)
    [ -s "$work/passed" ] || infra 'missing full-suite completion record'
    ;;
  1)
    diagnostic=$(cat "$work/rejection" 2>/dev/null) || infra 'missing rejection diagnostic'
    reject "$diagnostic"
    ;;
  124|137)
    stage=$(cat "$work/stage" 2>/dev/null) || stage='harness initialization'
    reject "Bog $sha exceeded the 240s watchdog ($stage)"
    ;;
  *) infra "SHA $sha, status $status" ;;
esac
