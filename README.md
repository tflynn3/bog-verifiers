# bog-verifiers

The Cycle 7 PR gate uses Bog `be7f937a1025a57166d15888727012ed4989a6b4` as
its reference. The verifier fetches the requested
branch, checks out the exact commit, and builds `./cmd/bog` with Go 1.27 on Linux.
It launches Bog in a private data directory on a local filesystem and drives
its HTTP API from a separate process. Recovery checks use stopped copies of
the documented WAL and commit marker.

## Slipway entrypoint

- PR verification uses `SLIPWAY_REPOSITORY`, `SLIPWAY_CANDIDATE_BRANCH`, and
  `SLIPWAY_CANDIDATE_COMMIT`. The fetched branch tip must match the full SHA.
  Standalone runs can set `SLIPWAY_PARAM_MODE=smoke` and supply
  `SLIPWAY_PARAM_BRANCH`, `SLIPWAY_PARAM_COMMIT`, and optionally
  `SLIPWAY_PARAM_REPOSITORY`. Run the same entrypoint on the baseline and
  each PR head. The fetched history must contain the Cycle 7 reference for
  the paired smoke and WAL handoffs.
- Set `SLIPWAY_PARAM_REQUIRE_QUERY_RESPONSE_BYTES=1` on the candidate
  verification step for the PR implementing #7. That run rejects a binary
  whose `-help` lacks `-query-max-response-bytes`. Leave the parameter unset
  for baseline runs and unrelated tracks, where that missing flag skips
  only the response byte suite.
- Set `SLIPWAY_PARAM_REQUIRE_QUERY_ADMISSION=1` on the #19 release candidate
  verification step. The gate requires both `-query-concurrency` and
  `-query-work-budget` in `-help` and passing reports for both suites. The
  published report must match the tested SHA, profile, and completion record.
  Leave the parameter unset for baseline runs and unrelated tracks. Each
  missing flag marks its own suite as skipped with `coverage: unavailable`
  in `BOG_RESULT`. The existing query, ingest, pagination, and recovery
  suites still run.
- With the same candidate inputs, use `--full`, `--compare`, or
  `SLIPWAY_PARAM_MODE=full` or `compare` for the paired post-cycle matrix and
  WAL handoffs against `4ff49aae9672cf5aec8e3fbd20ffe0a84ae15bc0`.
  Both revisions must be present in the fetched history and build before the
  suites start. A missing or unbuildable candidate fails at checkout or build.
  A missing or unbuildable pinned baseline is an infrastructure error.
- `SLIPWAY_PARAM_MODE=post-cycle` also gates controlled log replay performance
  against `be7f937` and the pre-Bloom reference `4ff49aa`. For a standalone step,
  use `SLIPWAY_INPUT_TESTEDCOMMIT` to select an exact commit reachable from
  `main`. Set `SLIPWAY_PARAM_REPOSITORY` to override the default Slipway remote.
- `--legacy` or `SLIPWAY_PARAM_MODE=legacy` checks the pinned Cycle 1 build
  `25d0c0acc103bd73f0552a8f10240c8d8c1d023d`, which predates the paged API.
  Standalone runs default to that SHA on `main` and accept
  `SLIPWAY_PARAM_REPOSITORY`.
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
- The work budget suite sets `-query-work-budget=32` when advertised and
  checks HTTP 503 without rows or `Bog-Next-Cursor` for ordinary scans and
  for lookahead on first pages and continuations. When candidate help
  advertises `-retained-tail-max-bytes`, the suite requires the sparse
  first page to reject before issuing an uncertifiable cursor.
- The admission suite independently detects `-query-concurrency` and sets it
  to 1. An unread response holds the slot through TCP backpressure. Ordinary
  queries, first pages, and continuations must return HTTP 503 within two
  seconds without NDJSON or `Bog-Next-Cursor`, while health and ingest still
  succeed. After the held client disconnects, a retry succeeds, the existing
  cursor excludes the backfill, and a fresh walk includes it. The verifier
  also checks that the acknowledged backfill survives SIGKILL and restart.
- The response byte suite counts raw UTF-8 NDJSON, including JSON escapes
  and record newlines. It checks the exact-fit ordinary prefix and HTTP 422
  with no rows or cursor when the first matching record exceeds the cap by
  one byte. A snapshot walk crosses a byte cut within tied duplicates,
  excludes matching backfill acknowledged after its first page, and ends
  without a cursor. A fresh walk includes the backfill.
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
- The Linux log replay builds 65,573 rows per run from seeded selections of
  captured Apache access, Git daemon, and multiline application logs, and
  authored syslog messages. It uses fresh stores for steady and shuffled
  append orders. Serial acknowledgments establish the append order for the
  stable timestamp sort in the independent oracle. Ordinary queries and
  complete cursor walks compare exact rows, including duplicates and ties.
- An 8,192-row dense prefix precedes long stretches with one dense-literal
  match per 8,192 rows. The replay also checks rare and absent literals,
  four-byte grams that occur on distinct rows of one sealed block, Unicode
  in composed and decomposed forms, quotes, backslashes, and control
  characters. Dedicated queries hit the first sealed block, the final
  37-row partial block, and the end of a 96 KiB line in an over-budget block.
- Dense and rare walks start before an early and tied backfill. Each walk
  continues after the first acknowledged POST and finishes after a second
  POST seals the partial block. Fresh ordinary and paged queries include
  the backfill. After SIGKILL and restart the verifier checks the same data,
  requires HTTP 400 for old cursors, and tests a second restart after
  appending a near-4 MiB frame followed by a small backfill.
- The PR gate opens each revision's WAL with the other, verifies the
  committed files, appends using the receiver, and reopens the extended
  WAL with the original writer. The oracle checks both ordinary queries
  and complete walks at every step.

## Timing and compatibility

The default smoke ingests 8,192 rows in eight-row POSTs on eight persistent
connections. It reconciles every row live and after restart, and records
durable requests and rows per second, POST latency, narrow and wide query
latency, peak RSS, and restart-to-health time. Timing measurements carry
no PR verdict thresholds.

The paired log replay smoke runs one pair per append order on identical
HTTP bodies, with the baseline first for steady and the candidate first for
shuffled. Each side records 36 raw HTTP latency samples per dense, rare,
and absent query category before and after restart, all timed POSTs,
durable ingest throughput, Linux peak RSS, and restart-to-health time.
Query latency includes receiving the response body. The PR gate checks
correctness and sample completeness.

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

Post-cycle QA runs 56 SIGKILL trials. It also runs six alternating-order
performance pairs per workload and reference on the same Linux host and
local filesystem with the same Go version and resource limits. Each side
ingests one million rows across four connections, with 500 rows per POST.
Timestamp ties are contained within a POST. Complete cursor walks reconcile
every row before and after restart. Query timings include ordinary requests
and cursor continuations, with first-page timings for the absent literal.
A fixed-cadence control measures steady dense queries after restart.
The median candidate-to-reference ratio across the six pairs must meet
each applicable limit for each append order and phase.

| Reference | Metric | Target |
| --- | --- | --- |
| `be7f937` | Each query p95 and durable POST p99 | ≤ 1.15 |
| `be7f937` | Durable rows per second | ≥ 0.90 |
| `be7f937` | Ingest and WAL replay peak RSS | ≤ 1.05 |
| `be7f937` | Steady restart-to-health | ≤ 0.95 |
| `be7f937` | Shuffled restart-to-health | ≤ 1.05 |
| `4ff49aa` | Steady dense query p95 after restart | ≤ 1.15 |
| `4ff49aa` | Rare and absent query p95 | ≤ 0.25 |

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
`BOG_FULL_DISK`, `BOG_PERFORMANCE_PAIR`, and `BOG_LOG_REPLAY_PAIR` provide
detailed evidence. `BOG_LOG_REPLAY_SAMPLE` publishes raw samples in each
PR's run log. The paired replay suite also writes its samples and ratios
to `pairs.jsonl`.
Set `SLIPWAY_PARAM_ARTIFACT_DIR` to a writable directory to retain
`result.json`, process logs, the crash ledger, and per-pair samples. The
small-batch POST metrics use all requests for percentiles and retain up to 128
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
  -e SLIPWAY_CANDIDATE_COMMIT=be7f937a1025a57166d15888727012ed4989a6b4 \
  bog-verifier)
docker cp "$qa_dir/bog.bundle" "$container:/tmp/bog.bundle"
docker start -a "$container"
```

Run harness regressions with `python3 -B -m unittest discover -s tests -v`.

## Linux release qualification for #108 and #116

Storage owns writable recovery and checkpoint publication under #53.
Query/HTTP owns the cursor progress contract under #70.
Release Verification owns the native gate, producers, and validators.
Core Architecture owns the registry and fitness companion. Recheck the
Storage and Query/HTTP leases and the selector and query delivery handoffs
before dispatching the reviewed #108 and #116 revision.

Dispatch **Linux release verification** from the verifier ref with the full
composed Bog commit SHA. The workflow builds one clean Go 1.27.0 binary on
each of the native Ubuntu 24.04 amd64 and arm64 runners. All producers on each
runner share that binary and the `linux-release-v1` fixture. The final job
requires both architecture results for the dispatched revision and distinct
binary digests. The `linux-release-evidence-amd64` and
`linux-release-evidence-arm64` artifacts contain the reports, build metadata,
digests, and logs.

Both runners require explicit passing Go test events for all seven real-TCP
query test groups and their required subtests in the candidate checkout.
These cover failed opening writes, capture slot reuse, retirement, shutdown
while a resume is held, fitting pages, and refusal framing. The pinned query
model also requires fitting pages at opening limits 1 and 10 in ordinary WAL
and retained modes, replay in both modes, and listener startup tests. The
query tooling checkout also runs `TestPinnedQueryGenerationReplacement` in
the same model invocation. It starts the pinned binary on a tail-only
restore and checks fixed-budget paging across successive publications,
terminal replay, and capture release. The gate checks the candidate revision
and native binary SHA-256 and retains the raw model, handler, and validation
events. When the paired parity probe explicitly reports missing loopback
control or writable tail selection, the runner omits the replacement case
and still runs the existing model and handler checks. Strict native
qualification requires exactly one replacement pass and one matching
identity in the model events.

The workflow runs the pinned #70 production-client paging probe against the
candidate binary and runs the candidate checkout's #53 Linux durability
producer. The tied fixture must reject cleanly at 10 work units and exhaust
at 11. The sparse fixture must reject cleanly at 313 and exhaust at 314 with
a 96-byte response cap and resume limit 1. The walks check exact row order,
duplicate multiplicity, and snapshot membership after acknowledged appends
between issuance and resume. Current reports record resume limit 1 for each
successful tied, duplicate, and sparse boundary walk. A separate tied
fixture uses a 96-byte cap to trim the four-row request to two rows, then
resumes at limit 1 after appending two more ties. The snapshot must exhaust
in exactly three pages with the original four rows, including duplicates.
Schema version 1 reports record the failure
page, budget, HTTP status, and diagnostic when issuance or continuation fails.
The durability report must demonstrate prior-process cursor
rejection and verify readiness and ingest in both filesystem retarget
directions. The native workflow checks that the producer removed its fixture
root and records `fixture_root_cleanup` in the schema v1 durability report.
New native qualifications require that case to pass, kernel-observed ENOSPC,
exact restart replay in both retarget directions, and recovery after freeing
space. Historical reports may
omit it, and an explicit cleanup failure rejects either report format.

At both 196,608 and 393,216 seed rows under the 128 MiB cgroup limit, the
capacity producer records clustered and scattered backfill timelines.
Each proves an acknowledged append and continuation during compaction,
publication at the exact newer cutoff, exhaustion of the held snapshot,
and fresh visibility. The workflow builds the capacity producer, pinned query
model, and both strict consumers from `93fe02f`. The strict release consumer
also receives the query model and TCP handler event files and checks the
replacement test's candidate identity. The producer uses 2,147,483,648
work units for live queries. The report records peak sampled
checkpoint staging bytes. After each held walk exhausts, the
producer retries its terminal page, checks the NDJSON response byte for
byte, records the positive predecessor pin count, and retires the capture
with the continuation token that fetched that page.
Qualification requires an observed zero after retirement and an exact fresh
walk. On restart in the same directory, the producer reads back the published
generation, covered cutoff, and committed row count. The independent append
ledger checks the full ordered walk through the committed suffix and terminal
exhaustion. Each fixture also requires process, cgroup, and fixture root cleanup.

The capacity producer handoff uses these additive fields in each schema v1 result.

- The producer uses distinct disposable subtrees for the two scales and
  records `cgroup_memory_limit_bytes` and `cgroup_swap_max_bytes` from
  kernel readbacks. Strict validation requires 128 MiB and disabled swap.
- `cgroup_peak_memory_bytes` and `diagnostics.cgroup_memory_events` come
  from `memory.peak` and `memory.events` before subtree removal, including
  on early exit. Qualification requires zero `oom_kill` and `oom_group_kill`
  when the group counter is present. The capacity tooling and release
  validators read the same producer report file. A timed
  `cgroup_memory_current.bytes` observation may equal the reported peak
  for its fixture cgroup. Both validators must accept the producer's passing
  report and reject the same serialized fixtures with missing, null, or nonzero
  raw `oom_kill`, decreasing sample time, terminal replay before exhaustion,
  or a 128 MiB overlap observation with a 64 MiB final peak.
- `diagnostics.restart` records the same directory identity across process
  lifetimes, the recovered checkpoint, and the exact acknowledged ledger
  and WAL suffix counts.
- Release Verification keeps missing pin counters pending through the
  drain deadline. An observed zero after explicit retirement completes the
  proof. An observation window ending with a missing counter preserves
  pending evidence for diagnosis.
- `diagnostics.candidates` records clean exit and reaping for the startup
  and restart processes. Qualification also checks that each process was
  live at teardown, the kernel recorded zero OOM kills, and the fixture
  store was removed.

Failed runs upload the producer report and logs when available. The workflow
records the fixture-root check even when the producer exits with an error.
Historical schema v1 parsing remains available without the current evidence flags.

Both native jobs run the combined parity producer and strict parity validator
from Bog revision `dcbfa3fa98d75f9dca1dbff1b035d814f37fe438`. They require
passing Go test events in `parity-events.jsonl` and
`parity-validation-events.jsonl` and matching schema-v1 `parity.json`
evidence for ordinary WAL reopen, held-cursor restore, immediate
post-acknowledgment SIGKILL, and `tail_only_two_cycle_parity`. The selected-tail
case checks both generations' exact recovery points, consumed frame and
suffix digests, and ordered walks after restart and after independent
restore. The joint verdict requires both native binaries to qualify for
the same candidate revision and parity gate revision, with the SHA-256 of
each binary checked against its native build. Standard schema-v1 validation
still accepts historical parity reports. HTTP 404 from the opted-in
loopback probe or an absent `bog.authority` after the first writable tail
publication skips selected-tail parity. Ordinary WAL parity still runs.
The selector reader follows ADR 0038's proposed v2 encoding. Storage
confirmation is pending. The probe opens `bog.backup` through the same
checked artifact opener and tests that FIFO metadata is rejected within
the parity deadline. Native qualification requires selected-tail parity
to pass.

Strict native qualification also requires `writable_restore_cycles` in the
combined report. This probe advances a verified v1 restore at two exact
cutoffs, exports and verifies each v2 image, and checks held and fresh
framed walks and same-directory restart. Each cycle measures positive
predecessor pins while its cursor is held, explicitly retires the capture,
and measures zero pins at the same published cutoff. The first restore
checks `/ready` after the configured directory symlink is retargeted to
procfs. The final restored append survives SIGKILL and replay.
The shared proof and both strict consumers accept an acknowledgment at
the fresh-visibility sample and reject one after that sample, even if it
precedes the end of the full walk. Their fixtures cover the passing report
and standard schema-v1 archive compatibility. Both native jobs run these
tests under the race detector before collecting live evidence and record
the capacity validation revision with the qualification.
Route capacity fixture failures to the existing Release Verification owner
with the native architecture, checkout and candidate revisions, and the
capacity report and runner log. Release Verification owns the pinned parity producer and immediate SIGKILL fixture.

The supplemental parity report checks legacy WAL replay, append, and restart, then removes the original data and
bundle and starts the candidate on the verified v1 restore. Ordinary queries
and framed cursor walks check restored rows and exact parity after restart.
After the reopened restore acknowledges a second append with HTTP 204, the
verifier requests SIGKILL of that live process before reading or closing the
response body and checks its reaped exit signal before restarting.
Cutover qualification requires both observations
and exact ordered replay of all eight rows. Restored launches use the shipped control defaults.
The two-cycle tail-only fixture also kills each live replacement after
the held walk, byte-exact terminal retry, pin retirement, and fresh walk.
Each cycle submits a malformed batch after opening a cursor and checks that
its valid prefix never enters the visible or recovered history. After exporting the exact
selected suffix it reopens the same directory, appends a probe row, and
kills the process directly on HTTP 204. A second reopen must replay that
row and the complete ordered history. When status advertises
generation-correlated predecessor pins, each cycle requires the matching
reclamation observation after the final pin drains.

Both native runners run the command-owned `cmd/bog-verify` race tests.
They require the default drill phase and operator-signal tests to pass.
For candidates advertising `-retained-tail-max-bytes`, they also require the
shipped-server drill against the runner's pinned binary. The same package
run includes #117's opt-in schema tests when such tests land.

The parity report counts six HTTP 404 responses across status, start, and
retirement probes on restored startup and restart. When the operator CLI is available, a separate restored copy
serves the default backup comparison. If `compare -help` advertises `-max-pages`,
the comparison must also finish at the exact page ceiling and report an
incomplete comparison at a lower ceiling. The resource probe discovers `-retained-tail-max-bytes` in
candidate help. This release probe requires the composed runtime to expose
that flag as a byte limit for uncovered WAL frames. At the restored tail
limit, Bog must reject a whole two-row batch with HTTP 503, preserve the WAL
and commit marker, and serve the exact acknowledged rows before and after
restart.

The small replacement probe runs on the full legacy WAL before the
isolated v1 restore test. The full WAL supplies the prefix needed to
publish a new v1 checkpoint. The probe checks the held cursor and fresh
ordinary and framed HTTP queries after replacement and restart. The
schema v1 report identifies the store in its existing `live_replacement`
object.

Candidate help gates the writable restore probe. The short Slipway suite
probes `BOG_CAPACITY_CONTROL=1` on loopback and falls back to the advertised
legacy flag after HTTP 404. Candidates exposing neither capability skip the
suite. The suite checks the disabled default, verifies HTTP 404 or startup
refusal with wildcard opt-in, and verifies the exact generation and cutoff
after SIGKILL. It also compares held and fresh HTTP walks with an uncovered
tail and checks ordinary query parity after restart. The manually dispatched release gate requires the
composed revision and passing evidence on both native architectures.

Current cutover qualification also requires the corrupt v1 suffix to exit
with status 1 and unchanged suffix, checkpoint manifest, and backup metadata.
It also requires unchanged backup metadata after writable restart and exact
replay of a byte-framed continuation across an acknowledged append. The
short loopback fixture seeds a predecessor checkpoint before holding its
cursor. It checks exact continuation replay after replacement, then retries
the terminal page before retiring the capture with its continuation token.
The default and wildcard listeners must hide the retirement action.
Qualification requires rejection of a malformed token, a positive predecessor
pin count after terminal retry, and an empty HTTP 204 for the issued token
followed by an observed zero. Native qualification also requires a clean
HTTP 410 when the retired terminal cursor is resumed. Slipway allows the
retirement subprobe to skip on older controls.
The release gate also checks the small fixture's process exits and removal.

Both native jobs require the replacement and restart proof in `control.json`.
The fixture holds a cursor at a fixed work budget across checkpoint replacement.
The replacement and sparse fixed-budget probes each read a continuation
token from the response headers, close the connection with the body unread,
and use the delivered token on a new connection. Both check exact terminal
replay after resuming the walk.
Fresh ordinary and paged requests must match the full append-ledger order,
including the duplicate rows and uncovered committed suffix, before and after
reopening the same directory. The verifier checks framing and records ordered
row digests and the raw terminal response and retry digests. A separate sparse,
byte-trimmed fixture verifies exhaustion with a smaller continuation limit at
the issuing budget. The low-budget opening may cleanly refuse the request
before issuing a cursor. The higher-budget walk must issue and exhaust.
Qualification also requires the architecture and lifecycle tests to pass.
Historical report validation remains available without
`--require-replacement-restart` and `--require-control-scope`.

Both native jobs require passing `TestReleaseCapacityControlScope` and
`TestReleaseCapacityControlScope/loopback_with_opt_in` events in
`capacity-control-scope-events.jsonl`. The pinned Go test verifies that
each listener belongs to the candidate and is bound to the requested
address. It checks HTTP 404 and health on default loopback and opted-in
wildcard. On opted-in loopback it commits a seed row, requests cutoff 1,
and polls for a newer generation covering exactly that row. An HTTP 404
on the positive capability probe skips that subtest outside strict
qualification.

Both native jobs also require a passing `control_scope` case in `control.json`.
The probe checks that the environment opt-in exposes status on the IPv4
loopback listener. It then requires HTTP 404 for status, start at a valid
committed cutoff, and retirement with an issued cursor on default and
explicitly disabled loopback listeners, as well as on the wildcard listener.
Wildcard opt-in can either hide all three operations or refuse startup with
exit status 1. An older binary that returns HTTP 404 to the enabled loopback
probe records a skip, which is insufficient for native qualification.

The release gate checks the binary's ELF machine against the native runner
and binds each mandatory report to that runner's binary digest, revision,
and fixture ID. Each runner passes its build-time SHA-256 directly to
validation. The control report carries the architecture explicitly. The
joint verdict binds both architectures to the same verifier commit. Each
runner records its filesystem, delegated cgroup settings, and explicit parity
test events alongside the per-case reports and cleanup evidence.
