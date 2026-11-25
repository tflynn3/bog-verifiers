# bog-verifiers

Independent black-box verification for both Cycle 8 PRs. The verifier fetches
the candidate branch, requires its tip to match the supplied full SHA, and builds
`./cmd/bog` in a clean detached checkout. The default entrypoint and `--full`
run the same ten suites. A successful run must build an executable and start a
ready Bog subprocess in every applicable suite.

## Slipway

Build this Dockerfile for the runner's Linux architecture. The base image
digest pins Go, Python, Git, and coreutils. The build uses the bundled Go
toolchain with the module proxy disabled. Before registering the resulting OCI
digest as `bog-blackbox`, run it on README-only `7655ed6` and the retained
service candidate `bb17a1e`. Require exit 1 with a build diagnostic on the
former and all applicable suites to pass on the latter. Use the same digest
for both Cycle 8 PRs. Each delivery
recipe's `land` step depends on `verify` and uses its verification of the exact
candidate commit.

### Cycle 8 registration

`bog-blackbox` is registered for Linux ARM64 as
`docker.io/library/bog-verifier@sha256:eebe327fa017c7784ef4b0715466db2a12df659f010896c81943e870ad702691`.
Before registration, a non-root container with one CPU and 1 GiB of memory
produced these results with Go 1.27.4 and Python 3.11.2.

| Candidate SHA | Exit | Result |
| --- | --- | --- |
| `7655ed627bccad30700b8de4b6f47c8d7d5d8579` | 1 | Missing `./cmd/bog`; diagnostic verified in `/dev/termination-log` |
| `bb17a1eceeaf7d809769219ed91774cb11cc1d50` | 0 | 10 suites passed, including real ENOSPC on a private 64 MiB tmpfs |

### Runner inputs and evidence

Candidate steps supply `SLIPWAY_REPOSITORY`, `SLIPWAY_CANDIDATE_BRANCH`, and
`SLIPWAY_CANDIDATE_COMMIT` (full lowercase SHA-1). A general verifier step can
smoke-test the registration with `mode=smoke`, `branch`, and `commit` params.
The optional `repository` param defaults to the factory Bog remote. The
factory's post-cycle probe uses `mode=post-cycle` and
`SLIPWAY_INPUT_TESTEDCOMMIT` to build the exact supplied revision reachable
from remote `main`, including the earlier landed baseline.

- Exit 0 means every applicable suite passed.
- Exit 1 rejects the candidate or its inputs. The entrypoint writes a short
  diagnostic to stderr and `/dev/termination-log`.
- Exit 2 indicates a verifier infrastructure error.
- The gate bounds individual HTTP operations, subprocess startup, builds, and
  the full build-and-suite run (240-second watchdog).

The verdict uses the Slipway Job's exit status and termination message. Save
the Pod logs and the WorkflowRun verification record together. `BOG_RESULT`
contains the requested and tested SHAs, binary SHA-256, seeds, corpus hash,
suite outcomes, timings, and log filenames. `BOG_BUILD`, `BOG_PROCESS`, and
`BOG_SIGKILL` provide build and process log tails and crash observations. Use
the WorkflowRun's recorded verification image as the authoritative digest and
match it to the report via run UID and step. For standalone invocations, pass
the actual immutable digest with `BOG_VERIFIER_IMAGE_DIGEST`. A runner with a
writable artifact mount may set the `artifact_dir` param to retain full process
and build logs and `result.json` in a unique run directory.

## Mandatory workloads

- The archived replay contains 513 Apache access events, 36 proxy errors,
  1,009 Python application events, and 1,000 seeded rows. The Python oracle
  compares ordered NDJSON at integer nanosecond precision before and after
  restart. Separate seeded cases exercise late rows, exact wire duplicates,
  timestamp ties, Unicode, multiline text, half-open and equal bounds, and
  filtering before limit.
- HTTP cases cover wrong methods, malformed and interrupted requests, exact
  4 MiB and one-byte-oversized bodies, concurrent batch visibility, data-directory
  locking, and SIGTERM with an active POST that must drain and survive restart.
- Three seeded SIGKILL waves reconcile every batch against a client ledger
  written outside the Bog store. Acknowledged writes must
  survive exactly once, definitive rejections must stay absent, and requests
  with unknown outcomes must be whole or absent. Offline copies of
  `bog.wal` and `bog.commit` check byte-for-byte suffix discard, committed
  corruption and truncation refusal, and missing or corrupt marker refusal.
- ENOSPC uses the runner's private bounded mount when available. Use the
  `enospc_mount` param for a dedicated, writable 1–128 MiB mount or let the
  verifier discover the container's private `/dev/shm` tmpfs. The control
  write must receive kernel ENOSPC. The test then verifies the rejected batch,
  unchanged committed files after restart, and a durable write after space is
  freed. PR runs explicitly report an unavailable default mount. In
  `mode=post-cycle`, unavailable filesystem support is an infrastructure error.
  An explicitly configured but unusable mount is also an infrastructure error.
- The fixed 20,000-row workload uses 500-row batches and four writers.
  It reports the workload SHA-256, acknowledged ingest
  rows/s, POST and narrow/broad query latency samples with percentiles, empty
  and populated readiness, Linux peak RSS, and WAL bytes. Every timed query is
  oracle-checked and all 20,000 rows are reconciled before and after restart.

Run the harness regressions with `python3 -B -m unittest discover -s tests -v`.

## Post-cycle QA

After both PRs land, rerun the same digest on the exact landed scan baseline
and indexed SHAs. Use matched fresh stores on one Linux host and filesystem.
Require the ENOSPC check in the pinned verifier on final main. Run 48
trials across both revisions, 100k and 1M rows, 200 and 1,000 rows per batch,
read-only and mixed workloads, and three repeats per combination. Alternate
revision order and use the same seeds, concurrency, query mix, and warmup
within each pair. Archive raw ingest and query measurements, RSS, WAL bytes,
restart readiness, per-seed variance, workload hashes, and reproduction
commands. Investigate a 1M-row narrow-query p95 speedup below 2× or a matched
ingest throughput drop above 20%. The PR gate measures correctness and bounded
completion. The paired measurements belong to post-cycle QA.
