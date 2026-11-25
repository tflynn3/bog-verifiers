# bog-verifiers

Independent black-box and end-to-end verification for bog. The verifier fetches
the candidate branch, checks that its tip matches the requested SHA, and builds
`./cmd/bog` in a fresh checkout. It reports the binary SHA-256 and the outcome of
each required suite. Both the default bootstrap entrypoint and `--full` run the
same gate.

## Slipway

The Bog factory builds this repository's Dockerfile and registers the resulting
OCI digest as `bog-blackbox`. The delivery recipes for both the durable service
and the time-ordered query index must use that registration in their `verify`
steps. Each `land` step must depend on `verify` and reference that verification
for the exact candidate commit. Check the registered digest before scheduling
delivery and keep it in place through both PRs.

Candidate jobs supply `SLIPWAY_REPOSITORY`, `SLIPWAY_CANDIDATE_BRANCH`, and
`SLIPWAY_CANDIDATE_COMMIT` (full lowercase SHA-1). The factory's post-cycle probe
can also invoke the same gate on its exact tested main SHA with
`SLIPWAY_PARAM_MODE=post-cycle` and `SLIPWAY_INPUT_TESTEDCOMMIT`.

- Exit 0 means every required suite passed.
- Exit 1 means the candidate or inputs were rejected. The diagnostic goes to
  stderr and `/dev/termination-log`.
- Exit 2 means a verifier infrastructure error. The ENOSPC suite requires a
  private, writable Linux `/dev/shm` tmpfs between 8 and 128 MiB. Docker's default
  private 64 MiB tmpfs works under UID and GID 65532 with all capabilities dropped.

## Required workloads

- The Python query oracle compares decoded rows at nanosecond precision. The
  archived corpus is checked before ingest and reconciled before and after
  restart across disjoint HTTP query windows. It contains 513 Apache access
  events, 36 proxy errors, 1,009 Python application events, and 1,000 seeded
  rows. Its 2,558 records have SHA-256
  `7b79f2ac83692126019934e6a7738524aaa55f3e2151237d8421cae0539aff72`.
- Malformed and oversized requests and unfinished uploads cannot publish a
  prefix. Readers check batch-atomic snapshots during concurrent writes. Ties
  have an exact order under sequential POSTs and retain their observed order
  across restart under concurrent POSTs.
- Lock contention, three concurrent-client SIGKILL waves, torn WAL fixtures,
  and complete corruption cover recovery. The ENOSPC suite uses a disposable
  directory on the bounded tmpfs and confirms a subsequent durable write after
  releasing space and restarting.
- The 20,000-row smoke test uses 500-row batches and four writers. It checks
  query results before and after restart and reports throughput, POST and query
  p50/p95, WAL bytes, and restart-to-ready time. The gate has a 240-second watchdog.

Run the harness regressions with `python3 -B -m unittest discover -s tests -v`.
They use the archived Git bundle for the exact README-only revision and a
minimal buildable Go executable to exercise the zero-suite rejection.

## Post-cycle QA

Run the full benchmark matrix only after both PRs, on the exact merged SHA.
Use one documented machine, fresh stores, and a seeded, checksummed replay-derived
workload. Test 100,000 and 1,000,000 rows, batch sizes of 1 and 500, and 1 and 4
writers, with three repeats per cell. Allow 60 minutes per single-row run and
15 minutes per 500-row run. Record all 24 outcomes and eight cell medians with
sample counts. Include cache conditions, acknowledged throughput, POST and
narrow/full-span query p50/p95, WAL bytes per row, peak RSS, and populated
restart-to-ready time. Oracle-check timed queries and reconcile after restart.
