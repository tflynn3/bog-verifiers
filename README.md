# bog-verifiers

Slipway uses one immutable verifier for the scan baseline PR and the subsequent
time-index PR. Both delivery recipes use `bog-blackbox` and land only the exact
candidate commit that passes. The Linux ARM64 image for this gate is

```text
docker.io/library/bog-verifier@sha256:62eefcbfc2cc774d9f9ecdebc257d8ce9414515f6bf1f9b03e76eefcf5d6b94f
```

The image uses Go 1.27.4 and runs as UID and GID 65532. The entrypoint fetches a
candidate into a clean checkout, checks the full SHA, builds `./cmd/bog` with the
bundled toolchain, and starts the real executable with `-addr` and `-data-dir`.
Each required suite must start a process that serves `GET /healthz`. The default
entrypoint and `--full` run the same eleven suites.

The Linux Kubernetes preflight used one CPU, 1 GiB of memory, and a private
64 MiB tmpfs. Retained scan revision
`7e4b9b01ac826bfce51d067caf27fe0ae2fc779b` passed all eleven suites.
README-only `7655ed627bccad30700b8de4b6f47c8d7d5d8579` exited 1 and wrote
`missing ./cmd/bog` in the termination message.

## Runner contract

- PR verification uses `SLIPWAY_REPOSITORY`, `SLIPWAY_CANDIDATE_BRANCH`, and
  `SLIPWAY_CANDIDATE_COMMIT`. The remote branch tip must match the requested SHA.
- A standalone Slipway step can use `mode=smoke` with `branch`, `commit`, and
  optional `repository` params. Use `mode=post-cycle` and
  `SLIPWAY_INPUT_TESTEDCOMMIT` for a specific landed revision reachable from
  the Bog factory remote's `main`.
- Exit 0 passes. Exit 1 rejects and writes a diagnostic to stderr and
  `/dev/termination-log`. Exit 2 identifies an infrastructure error. The
  build-and-suite watchdog is 240 seconds.
- Both disk suites require a dedicated, writable 1–128 MiB Linux filesystem.
  The container's private 64 MiB `/dev/shm` works with all capabilities dropped.
  Set `enospc_mount` to use an alternative disposable mount. Missing filesystem
  support is an infrastructure error.

## Required workloads

- Captured access and application logs and seeded records exercise
  literal case-sensitive filters, nanosecond half-open bounds,
  stable ties across serialized POSTs, duplicates, late arrivals, Unicode,
  escaped newlines, and ordering before and after restart. The independent
  oracle orders and filters decoded records using integer nanoseconds.
  [Fixture provenance](corpus/README.md)
- HTTP tests cover the exact 4 MiB ingest boundary, the default and maximum
  query limits, malformed batches, and truncated uploads. The concurrency
  test checks whole-batch snapshots with at most 386 expected rows per query.
  Process tests check second-writer exclusion and draining an active POST
  on SIGTERM.
- Twenty-four seeded SIGKILL trials interrupt a partial upload, kill after a
  complete upload with the response unread, or kill after an observed HTTP
  204. A client ledger outside the data directory records each outcome. Every
  restart reconciles all stored rows, including prior acknowledgments.
  Rejected and incomplete batches must be absent. Batches whose responses
  were unread must be complete or absent.
- Disposable copies of a committed store exercise a torn or uncommitted
  suffix, corruption inside the committed prefix, and a missing WAL or
  marker. Recovery must discard the suffix and accept a durable append.
  Invalid committed stores must exit before readiness and preserve their
  canonical files.
- The live ENOSPC test forces a POST to run out of blocks during append.
  The reopen test fills a valid store's filesystem until the unprivileged
  service user has zero allocatable blocks and free inodes. A write to a
  newly created file must receive kernel ENOSPC. Bog must reopen and return
  the acknowledged rows with the original marker inode and unchanged marker
  and WAL bytes. After space is freed, a new 204 must survive SIGKILL and
  restart.
- The fixed smoke workload ingests 20,000 rows with four writers and 500 rows
  per batch. It reports acknowledged rows/s, narrow and broad HTTP query
  latency, and populated startup time after SIGKILL. Every timed response is
  oracle-checked. The reports include full latency samples, workload SHA-256,
  WAL size, and peak RSS.

## Evidence

`BOG_RESULT` records the tested revision, binary and fixture digests, seeds,
suite outcomes, and timings. `BOG_BUILD`, `BOG_PROCESS`, `BOG_SIGKILL`, and
`BOG_FULL_DISK` report build and process diagnostics, crash observations, and
filesystem evidence. Use the WorkflowRun verification image as the
authoritative digest and match its run UID and step to the report. Standalone
runs can record the image via `BOG_VERIFIER_IMAGE_DIGEST`. A writable artifact
mount can retain the full logs, ledger, and `result.json` via `artifact_dir`.

Run the harness regressions with
`python3 -B -m unittest discover -s tests -v`.

## Post-landing comparison

Run this same digest on the two exact landed SHAs. Benchmark both revisions
on one Linux host and filesystem with matched fresh stores, seeds, batch
sizes, query windows, concurrency, and warmup. Alternate which revision runs
first across repeats. Record per-run samples and workload hashes at 20K,
100K, and 1M rows. Evaluate the 2× narrow-query p95 speedup and the 20% maximum
acknowledged-ingest throughput loss at 1M rows after both PRs land. The PR
gate records timings and uses correctness and bounded completion for its verdict.
