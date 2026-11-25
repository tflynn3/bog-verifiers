# bog-verifiers

Cycle 3 PRs share one black-box gate. The verifier fetches the candidate branch,
checks its exact commit, and builds `./cmd/bog` with Go 1.27 in a writable Linux
checkout. It exercises the executable through its CLI, HTTP, process signals,
and offline copies of its documented WAL and commit marker.

## Slipway entrypoint

- PR verification uses `SLIPWAY_REPOSITORY`, `SLIPWAY_CANDIDATE_BRANCH`, and
  `SLIPWAY_CANDIDATE_COMMIT`. The fetched branch tip must match the full SHA.
  Standalone runs can set `SLIPWAY_PARAM_MODE=smoke` and supply
  `SLIPWAY_PARAM_BRANCH`, `SLIPWAY_PARAM_COMMIT`, and optionally
  `SLIPWAY_PARAM_REPOSITORY`.
- With the same candidate inputs, use `--full` or `SLIPWAY_PARAM_MODE=full`
  for the Cycle 3 comparison and WAL handoffs against
  `907c3510744f54d6259e0429d876ffd34f5ed6d2`.
- `--legacy` or `SLIPWAY_PARAM_MODE=legacy` checks the pinned Cycle 1 build
  `25d0c0acc103bd73f0552a8f10240c8d8c1d023d`. It omits cursor tests because
  that revision predates the paged API. Standalone runs default to that SHA
  on `main` and accept `SLIPWAY_PARAM_REPOSITORY`.
- `SLIPWAY_PARAM_MODE=post-cycle` retains the historical indexed comparison
  against Cycle 1 with its original workload and ratio targets. Supply the
  tested commit in `SLIPWAY_INPUT_TESTEDCOMMIT` for a standalone run against
  a revision reachable from `main`. `SLIPWAY_PARAM_REPOSITORY` overrides the
  default Slipway remote.
- The image runs as UID and GID 65532. Exit 0 passes. Exit 1 rejects and writes
  a diagnostic to stderr and to the runner's `/dev/termination-log`. Exit 2
  denotes an infrastructure error. Overall watchdogs are four minutes for
  the PR and legacy runs, 30 minutes for `--full`, and two hours for the
  historical indexed comparison.
- The disk suites use a private, writable 1–128 MiB Linux mount, such as the
  default 64 MiB container `/dev/shm`. `SLIPWAY_PARAM_ENOSPC_MOUNT` selects
  another suitable mount.

## Default coverage

- Captured access and application logs and seeded events exercise literal,
  case-sensitive filters, out-of-order ingest, exact duplicates, Unicode,
  pre-epoch and extreme dates, and half-open nanosecond windows. The independent
  NDJSON and timestamp oracle uses UTC nanoseconds, serial append order,
  and row order. See [fixture provenance](corpus/README.md).
- Cursor walks cover changing limits, a full terminal page without a cursor,
  more than 1,000 ties, equivalent time zones, and malformed, tampered,
  mismatched, and pre-restart tokens. The verifier walks established and fresh
  cursors while one backfill is committed and another upload is still open.
- Eight writers and overlapping readers check complete batches and stable
  tie order. Each writer queries immediately after each observed 204 and
  checks that its whole batch is visible. HTTP edge cases include an exact
  4 MiB body with a record larger than 256 KB, an oversized body, truncated
  uploads, and fresh lone-surrogate rejection at batch scope.
- Twenty-four SIGKILL rounds each send three batches with observed 204s and
  two with observed 400s, leave two uploads incomplete, and fully send four
  more requests concurrently without reading their final responses. An
  external ledger records unique request IDs and reconciles all rows after
  every restart. Each acknowledged batch must appear once, each rejected or
  incomplete batch must stay absent, and each unknown outcome may contribute
  zero rows or one whole batch. IDs are sent once.
- Offline copies check historical surrogate replay, truncation of uncommitted
  suffixes, and startup refusal for committed corruption or invalid markers
  with file preservation. Process and disk checks also cover exclusive
  directory ownership, SIGTERM draining, concurrent ENOSPC rejections, and
  reopening acknowledged data at zero allocatable blocks.

## Timing and compatibility

The default smoke ingests 8,192 rows in eight-row POSTs on eight persistent
connections. It reconciles every row live and after restart, and records
durable requests and rows per second, POST latency, narrow and wide query
latency, peak RSS, and restart-to-health time. Timing measurements carry
no PR verdict thresholds.

Full mode runs 12 alternating-order pairs on one Linux host and filesystem.
Each pair uses fresh stores and identical seeded HTTP bodies. Steady, burst,
and backfill each use two seeds and two repetitions, with 32,768 rows per
run, eight rows per POST, and either one or eight persistent connections.
Results include per-pair timings and median candidate-to-baseline ratios.
Full mode also opens each revision's WAL with the other revision, appends
eight concurrent small batches in each direction, and reopens the result
with the original writer. The handoffs verify the original WAL prefix and
the complete query results at each step.

The historical indexed comparison retains its 48 planned pairs, with
1,000,000 rows per run in 500-row POSTs and the Cycle 1 baseline. Its median
candidate-to-baseline targets are:

| Metric | Target |
| --- | --- |
| Wide query p95 | ≤ 0.50 |
| Narrow query p95 | ≤ 1.25 |
| Rare or absent filter query p95 | ≤ 1.50 |
| Durable ingest rows per second | ≥ 0.80 |
| Peak RSS | ≤ 1.25 |
| Restart-to-health | ≤ 1.25 |

`BOG_RESULT` records the tested SHA, binary and fixture digests, seeds, suite
outcomes, and timings. `BOG_BUILD`, `BOG_PROCESS`, `BOG_SIGKILL`,
`BOG_FULL_DISK`, and `BOG_PERFORMANCE_PAIR` provide detailed evidence.
Set `SLIPWAY_PARAM_ARTIFACT_DIR` to a writable directory to retain
`result.json`, process logs, the crash ledger, and per-pair samples. The
Cycle 3 POST metrics use all requests for percentiles and retain up to 128
raw samples per run. Match a Slipway report to its WorkflowRun UID, step, and
image digest. Standalone runs can set `BOG_VERIFIER_IMAGE_DIGEST`.

## Reproduce the pinned check

With the supplied checkout at `../bog` on the pinned `main`, copy a Git
bundle into the image's container and run the default entrypoint.

```sh
docker build -t bog-verifier .
qa_dir=$(mktemp -d)
git -C ../bog bundle create "$qa_dir/bog.bundle" refs/heads/main
container=$(docker create \
  -e SLIPWAY_REPOSITORY=/tmp/bog.bundle \
  -e SLIPWAY_CANDIDATE_BRANCH=main \
  -e SLIPWAY_CANDIDATE_COMMIT=907c3510744f54d6259e0429d876ffd34f5ed6d2 \
  bog-verifier)
docker cp "$qa_dir/bog.bundle" "$container:/tmp/bog.bundle"
docker start -a "$container"
```

Run harness regressions with `python3 -B -m unittest discover -s tests -v`.
