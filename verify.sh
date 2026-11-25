#!/bin/sh
set -eu
TERM_LOG=/dev/termination-log
fail() {
  echo "$1" >&2
  printf '%s' "$1" > "$TERM_LOG" 2>/dev/null || true
  exit 1
}

if [ -n "${SLIPWAY_REPOSITORY:-}" ] && [ -n "${SLIPWAY_CANDIDATE_COMMIT:-}" ]; then
  WORK=$(mktemp -d /tmp/bog-verify-XXXXXX)
  trap 'rm -rf "$WORK"' EXIT
  git init -q "$WORK"
  git -C "$WORK" remote add origin "$SLIPWAY_REPOSITORY"
  git -C "$WORK" fetch -q origin "refs/heads/${SLIPWAY_CANDIDATE_BRANCH}"
  TIP=$(git -C "$WORK" rev-parse FETCH_HEAD)
  if [ "$TIP" != "$SLIPWAY_CANDIDATE_COMMIT" ]; then
    fail "candidate branch tip $TIP does not match $SLIPWAY_CANDIDATE_COMMIT"
  fi
  git -C "$WORK" checkout -q "$SLIPWAY_CANDIDATE_COMMIT"
  # Run project test suite if present (Go, Cargo, Python, or Makefile).
  if [ -f "$WORK/go.mod" ]; then
    (cd "$WORK" && go test -race ./...) || fail "go test -race failed"
  fi
  if [ -f "$WORK/pytest.ini" ] || [ -d "$WORK/tests" ]; then
    (cd "$WORK" && python3 -m unittest discover -s tests) || fail "python tests failed"
  fi
  echo "bootstrap verifier passed for $SLIPWAY_CANDIDATE_COMMIT"
  exit 0
fi

echo "bootstrap verifier passed (non-git mode)"
exit 0
