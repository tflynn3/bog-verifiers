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
  full|compare) profile=full ;;
  legacy|post-cycle|indexed) profile=$mode ;;
esac
case "${1:-}" in
  --full|--compare)
    case "$profile" in
      pr|full) profile=full ;;
      post-cycle) ;;
      *) infra "$1 conflicts with mode $profile" ;;
    esac
    shift
    ;;
  --legacy)
    case "$profile" in
      full|post-cycle|indexed) infra '--legacy cannot be combined with a comparison run' ;;
    esac
    profile=legacy
    shift
    ;;
esac
[ "$#" -eq 0 ] || infra 'usage: verify.sh [--full|--compare|--legacy]'
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
    pr:smoke|full:|full:smoke|full:full|full:compare)
      repository=${SLIPWAY_PARAM_REPOSITORY:-$factory_repository}
      branch=${SLIPWAY_PARAM_BRANCH:-}
      expected=${SLIPWAY_PARAM_COMMIT:-}
      ;;
    post-cycle:post-cycle|indexed:indexed)
      repository=${SLIPWAY_PARAM_REPOSITORY:-$factory_repository}
      branch=${SLIPWAY_PARAM_BRANCH:-main}
      expected=${SLIPWAY_INPUT_TESTEDCOMMIT:-${SLIPWAY_PARAM_COMMIT:-}}
      if [ "$branch" = main ]; then allow_ancestor=true; fi
      ;;
    pr:post-land)
      # bog-conductor's post-land QA probe: gate the landed main commit with the PR
      # profile (240s watchdog). Prefer the commit the conductor landed over the QA
      # agent's reported testedCommit; main may have advanced past it.
      repository=${SLIPWAY_PARAM_REPOSITORY:-$factory_repository}
      branch=${SLIPWAY_PARAM_BRANCH:-main}
      expected=${SLIPWAY_PARAM_COMMIT:-${SLIPWAY_INPUT_TESTEDCOMMIT:-}}
      if [ "$branch" = main ]; then allow_ancestor=true; fi
      ;;
  esac
fi
for tool in git go grep python3 timeout; do
  command -v "$tool" >/dev/null || infra "missing verifier tool: $tool"
done
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

[ -n "$repository" ] && [ -n "$branch" ] && [ -n "$expected" ] ||
  reject 'missing Bog candidate inputs: repository, branch and full commit SHA are required (suites=0)'
case "$expected" in
  *[!0-9a-f]*) reject 'Bog candidate commit must be a full lowercase SHA-1 (suites=0)' ;;
esac
[ "${#expected}" -eq 40 ] || reject 'Bog candidate commit must be a full lowercase SHA-1 (suites=0)'

ref="refs/heads/$branch"
git check-ref-format "$ref" || reject 'invalid Bog candidate branch (suites=0)'
export GIT_TERMINAL_PROMPT=0 GIT_ALLOW_PROTOCOL=file:http:https:ssh
git init -q "$checkout" || infra 'cannot initialize checkout'
if ! LC_ALL=C timeout -k 5s 60s git -C "$checkout" fetch -q --no-tags -- "$repository" "$ref" > "$work/fetch.log" 2>&1; then
  cat "$work/fetch.log" >&2
  if grep -Fq "couldn't find remote ref" "$work/fetch.log"; then
    reject "Bog revision $expected is unavailable: branch $ref was not found (suites=0)"
  fi
  infra "cannot fetch Bog revision $expected from $ref (suites=0)"
fi
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
toolchain=$(go version) || infra 'cannot read Go toolchain version'
printf 'bog verification candidate_sha=%s profile=%s toolchain=%s\n' "$sha" "$profile" "$toolchain"

watchdog=240
case "$profile" in
  full|post-cycle) watchdog=1800 ;;
  indexed) watchdog=7200 ;;
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
