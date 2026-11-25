#!/bin/sh
set -eu

reject() {
  outcome="$1"
  printf '%s\n' "$1" >&2
  { printf '%s\n' "$1" > /dev/termination-log; } 2>/dev/null || true
  exit 1
}

infra() {
  outcome="$1"
  printf 'Bog verifier infrastructure error: %s\n' "$1" >&2
  exit 2
}

mode=${SLIPWAY_PARAM_MODE:-}
profile=pr
case "$mode" in
  full|legacy|post-cycle) profile=$mode ;;
esac
case "${1:-}" in
  --full)
    if [ "$profile" = pr ]; then profile=full; fi
    shift
    ;;
  --legacy)
    case "$profile" in
      full|post-cycle) infra '--legacy cannot be combined with a comparison run' ;;
    esac
    profile=legacy
    shift
    ;;
esac
[ "$#" -eq 0 ] || infra 'usage: verify.sh [--full|--legacy]'
verifier_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd) || infra 'cannot locate verifier'

repository=${SLIPWAY_REPOSITORY:-}
branch=${SLIPWAY_CANDIDATE_BRANCH:-}
expected=${SLIPWAY_CANDIDATE_COMMIT:-}
allow_ancestor=false
factory_repository=http://bog-git.kagent.svc.cluster.local/bog.git
# General verifier steps use Slipway parameters instead of a repository lease.
if [ -z "$repository$branch$expected" ]; then
  case "$profile:$mode" in
    legacy:*)
      command -v python3 >/dev/null || infra 'missing verifier tool: python3'
      repository=${SLIPWAY_PARAM_REPOSITORY:-$factory_repository}
      branch=${SLIPWAY_PARAM_BRANCH:-main}
      expected=${SLIPWAY_PARAM_COMMIT:-}
      if [ -z "$expected" ]; then
        expected=$(python3 -B "$verifier_dir/verify.py" --baseline) || infra 'cannot read pinned Cycle 1 SHA'
      fi
      if [ "$branch" = main ]; then allow_ancestor=true; fi
      ;;
    pr:smoke|full:|full:smoke|full:full)
      repository=${SLIPWAY_PARAM_REPOSITORY:-$factory_repository}
      branch=${SLIPWAY_PARAM_BRANCH:-}
      expected=${SLIPWAY_PARAM_COMMIT:-}
      ;;
    post-cycle:post-cycle)
      repository=${SLIPWAY_PARAM_REPOSITORY:-$factory_repository}
      branch=main
      expected=${SLIPWAY_INPUT_TESTEDCOMMIT:-}
      allow_ancestor=true
      ;;
  esac
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
work=$(mktemp -d /tmp/bog-verify-XXXXXX) || infra 'cannot create verifier workspace'
trap 'rm -rf "$work"' EXIT
trap 'exit 2' HUP INT TERM
checkout="$work/source"

finalize() {
  code=$?
  trap - EXIT
  # Slipway keeps verifier pod stdout and the termination message. A runner
  # with a writable artifact mount can also retain the raw log files.
  if ! python3 -B "$verifier_dir/verify.py" --report "$work" "$code" "${outcome:-}" "$expected" "${sha:-}" "$profile"; then
    printf '%s\n' 'Bog verifier infrastructure error: cannot publish verifier report' >&2
    code=2
  fi
  if [ -n "${SLIPWAY_PARAM_ARTIFACT_DIR:-}" ]; then
    if destination=$(mktemp -d "$SLIPWAY_PARAM_ARTIFACT_DIR/bog-verify-XXXXXX") &&
       cp -R "$work/artifacts/." "$destination/"; then
      printf 'bog artifacts=%s\n' "$destination"
    else
      printf '%s\n' 'Bog verifier infrastructure error: cannot copy verifier artifacts' >&2
      code=2
    fi
  fi
  rm -rf "$work"
  exit "$code"
}
trap finalize EXIT

export GIT_TERMINAL_PROMPT=0 GIT_ALLOW_PROTOCOL=file:http:https:ssh
git init -q "$checkout" || infra 'cannot initialize checkout'
timeout -k 5s 60s git -C "$checkout" fetch -q --no-tags -- "$repository" "$ref" ||
  infra "cannot fetch Bog candidate branch $ref (suites=0)"
fetched=$(git -C "$checkout" rev-parse --verify 'FETCH_HEAD^{commit}') || infra 'cannot resolve fetched commit'
if [ "$fetched" != "$expected" ]; then
  if [ "$allow_ancestor" != true ] ||
     ! git -C "$checkout" merge-base --is-ancestor "$expected" "$fetched"; then
    reject "Bog revision mismatch: fetched $fetched, expected $expected (suites=0)"
  fi
fi
git -C "$checkout" checkout -q --detach "$expected" || infra "cannot check out Bog revision $expected"
[ "$(git -C "$checkout" rev-parse --verify HEAD)" = "$expected" ] || infra 'checked-out SHA did not match the requested SHA'
sha=$expected
printf 'bog verification candidate_sha=%s profile=%s\n' "$sha" "$profile"

watchdog=240
case "$profile" in
  full) watchdog=1800 ;;
  post-cycle) watchdog=7200 ;;
esac
status=0
timeout -k 5s "${watchdog}s" python3 -B -u "$verifier_dir/verify.py" "$checkout" "$work" "$sha" "$profile" || status=$?
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
    infra "Bog $sha exceeded the ${watchdog}s watchdog ($stage)"
    ;;
  *) infra "SHA $sha, status $status" ;;
esac
