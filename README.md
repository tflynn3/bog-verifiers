# bog-verifiers

The default PR gate exercises the public contract of Bog
`4ff49aae9672cf5aec8e3fbd20ffe0a84ae15bc0`. The verifier fetches the requested
branch, checks out the exact commit, and builds `./cmd/bog` with Go 1.27 on Linux.
It launches Bog in a private data directory on a local filesystem and drives
its HTTP API from a separate process. Recovery checks use stopped copies of
the documented WAL and commit marker.

## Slipway entrypoint

- PR verification uses `SLIPWAY_REPOSITORY`, `SLIPWAY_CANDIDATE_BRANCH`, and
  `SLIPWAY_CANDIDATE_COMMIT`. The fetched branch tip must match the full SHA.
  Standalone runs can set `SLIPWAY_PARAM_MODE=smoke` and supply
  `SLIPWAY_PARAM_BRANCH`, `SLIPWAY_PARAM_COMMIT`, and optionally
  `SLIPWAY_PARAM_REPOSITORY`.
- With the same candidate inputs, use `--full`, `--compare`, or
  `SLIPWAY_PARAM_MODE=full` or `compare` for the paired post-cycle matrix and
  WAL handoffs against `4ff49aae9672cf5aec8e3fbd20ffe0a84ae15bc0`.
  Both revisions must be present in the fetched history and build before the
  suites start. A missing or unbuildable candidate fails at checkout or build.
  A missing or unbuildable pinned baseline is an infrastructure error.
- `SLIPWAY_PARAM_MODE=post-cycle` runs the same matrix. For a standalone
  post-cycle step, use `SLIPWAY_INPUT_TESTEDCOMMIT` to select an exact commit
  reachable from `main`. Set `SLIPWAY_PARAM_REPOSITORY` to override the
  default Slipway remote.
- `--legacy` or `SLIPWAY_PARAM_MODE=legacy` checks the pinned Cycle 1 build
  `25d0c0acc103bd73f0552a8f10240c8d8c1d023d`. It omits cursor tests because
  that revision predates the paged API. Standalone runs default to that SHA
  on `main` and accept `SLIPWAY_PARAM_REPOSITORY`.
- `SLIPWAY_PARAM_MODE=indexed` runs the historical indexed comparison against
  Cycle 1 with its original workload and ratio targets. It accepts the same
  candidate inputs as post-cycle mode.
- The image runs as UID and GID 65532. Exit 0 passes. Exit 1 rejects and writes
  a diagnostic to stderr and to the runner's `/dev/termination-log`. Exit 2
  denotes an infrastructure error. Overall watchdogs are four minutes for
  the PR and legacy runs, 30 minutes for `--full`, and two hours for the
  historical indexed comparison.
- The disk suites use a private, writable 1–128 MiB Linux mount, such as the
  default 64 MiB container `/dev/shm`. `SLIPWAY_PARAM_ENOSPC_MOUNT` selects
  another suitable mount.

## Default coverage

- Captured Apache, Git daemon, and application logs and seeded events exercise
  narrow and wide windows with rare, absent, common, and one-character literals.
  The independent oracle compares decoded NDJSON rows in timestamp, serial
  commit, and row order. Cases cover exact duplicates, Unicode, escaped
  controls, pre-epoch and extreme dates, and half-open nanosecond bounds.
  See [fixture provenance](corpus/README.md).
- Cursor walks cover changing limits, a full terminal page without a cursor,
  more than 1,000 ties, equivalent time zones, and malformed, tampered,
  mismatched, and pre-restart tokens. The verifier walks established and fresh
  cursors across two backfill commits. Active walks change page size and
  express the same bounds in different time zones.
- Eight writers and overlapping readers check that batches are visible whole.
  Each writer queries immediately after each observed 204 and checks that its
  whole batch is visible. Cross-batch ties are tested with serial POSTs.
  HTTP edge cases include an exact 4 MiB body with a record larger than
  256 KB, fixed-length and chunked bodies one byte over the limit, truncated
  uploads, and valid and invalid UTF-16 surrogate escapes.
- Twenty-four SIGKILL rounds each send three batches with observed 204s and
  two with observed 400s, leave two uploads incomplete, and fully send four
  more requests concurrently without reading their final responses. The
  client syncs observed 204s and 400s to a receipt ledger outside Bog's data
  directory before SIGKILL and reads the ledger to reconcile after each
  restart. Each acknowledged batch must appear once, each rejected or
  incomplete batch must stay absent, and each unknown outcome may contribute
  zero rows or one whole batch. Each request ID is sent once.
- Offline copies check historical surrogate replay, truncation of uncommitted
  suffixes, and startup refusal for committed corruption or invalid markers
  with file preservation. The default gate also covers exclusive directory
  locking and concurrent ENOSPC rejections.

## Timing and compatibility

The default smoke ingests 8,192 rows in eight-row POSTs on eight persistent
connections. It reconciles every row live and after restart, and records
durable requests and rows per second, POST latency, narrow and wide query
latency, peak RSS, and restart-to-health time. Timing measurements carry
no PR verdict thresholds.

Full mode also checks SIGTERM draining and reopening acknowledged data at
zero allocatable blocks. It runs 12 alternating-order pairs on one Linux
host and filesystem.
Each pair uses fresh stores and identical seeded HTTP bodies. Steady, burst,
and backfill each use two seeds and two repetitions, with 32,768 rows per
run, eight rows per POST, and either one or eight persistent connections.
Results include both exact SHAs, per-pair timings, and median
candidate-to-baseline ratios.
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

`BOG_RESULT` records the requested and tested SHAs, the comparison baseline
SHA when configured, binary and fixture digests, seeds, suite outcomes, and
timings. `BOG_BUILD`, `BOG_PROCESS`, `BOG_SIGKILL`,
`BOG_FULL_DISK`, and `BOG_PERFORMANCE_PAIR` provide detailed evidence.
Set `SLIPWAY_PARAM_ARTIFACT_DIR` to a writable directory to retain
`result.json`, process logs, the crash ledger, and per-pair samples. The
Small-batch POST metrics use all requests for percentiles and retain up to 128
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
  -e SLIPWAY_CANDIDATE_COMMIT=4ff49aae9672cf5aec8e3fbd20ffe0a84ae15bc0 \
  bog-verifier)
docker cp "$qa_dir/bog.bundle" "$container:/tmp/bog.bundle"
docker start -a "$container"
```

Run harness regressions with `python3 -B -m unittest discover -s tests -v`.
