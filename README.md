# bog-verifiers

Both ordered PRs use the same `bog-blackbox` verifier image. The default
entrypoint and `--full` require snapshot pagination, legacy query behavior,
and durable WAL compatibility with Cycle 1. Each gate builds `./cmd/bog`
from the exact fetched revision on Linux and exercises the executable via
its CLI, HTTP endpoints, process signals, and offline copies of its
documented WAL and commit marker.

## Slipway contract

- PR verification uses `SLIPWAY_REPOSITORY`, `SLIPWAY_CANDIDATE_BRANCH`, and
  `SLIPWAY_CANDIDATE_COMMIT`. The remote branch tip must match the requested
  full SHA. A standalone PR-equivalent run can use `mode=smoke` with
  `branch`, `commit`, and optional `repository` params.
- Use `--legacy` or `mode=legacy` to validate the pinned Cycle 1 baseline
  `25d0c0acc103bd73f0552a8f10240c8d8c1d023d`. Standalone legacy runs default
  to that SHA on `main` and accept a `repository` override. The two-revision
  handoff runs in each PR gate and the post-cycle evaluation, where the
  candidate and pinned baseline binaries are both available.
- Use `mode=post-cycle` with `SLIPWAY_INPUT_TESTEDCOMMIT` for the exact landed
  indexed revision reachable from `main`. It runs the PR suite and then the
  paired performance evaluation. Use `repository` to override the factory
  remote for a standalone run.
- The container runs as UID and GID 65532. Exit 0 passes. Exit 1 rejects and
  writes the diagnostic to stderr and `/dev/termination-log`. Exit 2 denotes
  an infrastructure error. The PR and legacy watchdog is 240 seconds.
  Post-cycle has a two-hour watchdog for the paired runs.
- The two disk suites require a private, writable 1–128 MiB Linux mount
  such as the default 64 MiB container `/dev/shm`. Set `enospc_mount` to
  use a different disposable mount.

## Correctness workloads

- Captured access and application logs and seeded syslog, structured JSON,
  and escaped stack traces exercise literal case-sensitive filters,
  out-of-order ingest, identical duplicates, pre-epoch and extreme dates,
  and windows on either side of the old 32-minute cutoff. The independent
  oracle orders decoded rows by UTC nanosecond, acknowledged batch order,
  and row order. Concurrent writers use disjoint timestamp keys.
  See [fixture provenance](corpus/README.md).
- The paged API uses `page=1`, the response header `Bog-Next-Cursor`, and
  subsequent `cursor` requests. Walks verify page sizes 1 and 1,000, limits
  changed on continuation, a full terminal page without a cursor, and more
  than 1,000 rows at one instant. They test malformed, tampered, mismatched,
  and pre-restart cursors. While a walk is active, a late POST adds rows
  before, between, and after its boundaries. The original cursor retains its
  first-page snapshot and a fresh walk sees the new rows.
- HTTP and process checks cover whole-batch visibility under concurrent
  reads and writes, the exact 4 MiB ingest boundary, malformed and truncated
  bodies, fresh rejection of lone-surrogate escapes, second-writer
  exclusion, and SIGTERM draining an active POST.
- Twenty-four seeded SIGKILL trials cover idle, acknowledged, partial-upload,
  and fully sent requests with unread responses. An external client ledger
  records each outcome. Each restart reconciles all rows. Acknowledged
  batches survive exactly once, rejected or incomplete batches stay absent,
  and requests with unknown outcomes may survive as a whole batch.
- Offline copies verify historical lone-surrogate replay, truncation of
  uncommitted suffixes, and startup refusal for committed corruption or
  invalid markers. The handoff runs both Cycle 1 → candidate → Cycle 1 and
  candidate → Cycle 1 → candidate. Each target reopens the source's files,
  checks the rows, and durably appends before the source reopens them again.
- The disk suites force a live append to encounter ENOSPC and verify reopening
  acknowledged rows at zero allocatable blocks. They check that the
  acknowledged marker and WAL survive and that ingest resumes after space
  is released.

## Benchmark and evidence

The PR smoke ingests 100,000 rows in 500-row batches with four writers. It
reports durable ingest throughput, narrow and wide query latency, peak RSS,
and restart-to-health. The verifier checks timed responses and reconciles
all 100,000 rows before and after restart. PR verdicts depend on correctness
and bounded completion. The smoke timings are recorded for comparison.

Post-cycle uses 1,000,000 rows per run. Each of steady, burst, and backfill
gets four seeds with four paired runs per seed. Each pair uses identical
fixture bytes and fresh stores on the same Linux host and filesystem.
The runner alternates execution order and warms up query classes before
taking samples. It gates on the median candidate-to-baseline ratio for each
workload. Query targets apply both live and after replay.

| Metric | Candidate-to-baseline target |
| --- | --- |
| Wide query p95 | ≤ 0.50 |
| Narrow query p95 | ≤ 1.25 |
| Rare or absent filter query p95 | ≤ 1.50 |
| Durable ingest rows per second | ≥ 0.80 |
| Peak RSS | ≤ 1.25 |
| Restart-to-health | ≤ 1.25 |

`BOG_RESULT` retains schema version 1 and records the tested SHA, binary and
fixture digests, seeds, suite outcomes, and timings. `BOG_BUILD`,
`BOG_PROCESS`, `BOG_SIGKILL`, `BOG_FULL_DISK`, and `BOG_PERFORMANCE_PAIR`
provide build, process, crash, filesystem, and paired performance evidence.
Use the WorkflowRun verification image digest and match the run UID and step
to the report. Standalone runs can record the image via
`BOG_VERIFIER_IMAGE_DIGEST`. A writable `artifact_dir` retains `result.json`,
logs, the crash ledger, and per-pair latency samples.

Build with `docker build -t bog-verifier .`. Run the harness regressions with
`python3 -B -m unittest discover -s tests -v`.
