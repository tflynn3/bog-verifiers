"""Produce the small capacity control report and validate Linux release evidence."""
import argparse
import json
import platform
import signal
from pathlib import Path
import re
import tempfile

from verify import (PROCESS_LOGS, Rejected, SuiteSkipped, capacity_control_suite, check,
                    file_sha256, unique_fields)


FIXTURE = "linux-release-v1"
MEMORY_LIMIT = 128 * 1024**2
CAPACITY_WORK_BUDGET = 134_217_728
SEED_ROWS = {196_608, 393_216}
TAIL_ROWS = 2_048
BATCH_ROWS = 64
PRODUCERS = {"admission", "durability", "capacity", "parity"}
FIXTURE_ROOT_CLEANUP = "fixture_root_cleanup"


def identity(binary, revision, fixture):
    check(re.fullmatch(r"[0-9a-f]{40}", revision) and fixture == FIXTURE, "invalid release identity")
    return {"schema_version": 1, "revision": revision, "binary_sha256": file_sha256(binary),
            "fixture": fixture}


def read_report(directory, producer, expected):
    with (directory / f"{producer}.json").open() as stream:
        report = json.load(stream, object_pairs_hook=unique_fields)
    for key, value in expected.items():
        if key == "arch" and producer != "control" and key not in report:
            continue  # The digest binds schema-v1 reports to the verified ELF.
        check(type(report.get(key)) is type(value) and report[key] == value,
              f"{producer}: mismatched {key}")
    if producer == "capacity":
        check(report.get("mode") == "live", "capacity: live mode is required")
    return report


def passing_case(report, producer, name):
    check(name in report["cases"], f"{producer}: missing required case {name}")
    case = report["cases"][name]
    check(case["status"] == "pass", f"{producer}: {name} did not pass")
    return case


def case_evidence(directory, producer, name, expected):
    return passing_case(read_report(directory, producer, expected), producer, name)["evidence"]


def integer(value, low, high=None):
    return type(value) is int and value >= low and (high is None or value <= high)


def validate_backfill_timelines(timelines, seed, published, *, require_pin_retirement=False):
    label = f"capacity ({seed} rows)"
    check(isinstance(timelines, list) and len(timelines) == 2,
          f"{label}: expected clustered and scattered backfill timelines")
    by_pattern = {trial["pattern"]: trial for trial in timelines}
    bounds = {
        "clustered": (seed - 2 * BATCH_ROWS, seed - BATCH_ROWS, seed, 9),
        "scattered": (seed, seed + BATCH_ROWS, seed + TAIL_ROWS, 9 * seed // 16 - 3),
    }
    check(by_pattern.keys() == bounds.keys(), f"{label}: missing or repeated backfill pattern")
    generations = []
    for pattern, (held, cutoff, final, rows) in bounds.items():
        trial = by_pattern[pattern]
        name = f"{label}, {pattern}"
        check(trial["status"] == "pass" and "failure" not in trial and
              trial["held_cursor_exhausted"] is True and trial["fresh_backfill_visible"] is True and
              all(integer(trial.get(key), want, want) for key, want in {
                  "held_cutoff": held, "requested_cutoff": cutoff, "expected_committed_rows": final,
                  "held_rows_checked": rows}.items()), f"{name}: incomplete backfill walk")
        acks = trial["acknowledged_backfill"]
        check(integer(acks.get("rows"), final - held, final - held) and
              integer(acks.get("batches"), (final - held) // BATCH_ROWS, (final - held) // BATCH_ROWS) and
              integer(acks.get("first_ack_ns"), 0) and integer(acks.get("last_ack_ns"), acks["first_ack_ns"]),
              f"{name}: incomplete append acknowledgements")
        publication = trial["publication"]
        generations.append(publication["generation"])
        lower = publication["observed_lag_lower_bound_ns"]
        check(integer(lower, 0) and integer(publication.get("observed_lag_upper_bound_ns"), lower),
              f"{name}: invalid publication timing")
        samples = trial["samples"]
        current = require_pin_retirement or "terminal_page_retried" in trial
        events = ("held_capture", "compaction_start", "overlap", "publication", "held_exhausted")
        events += (("terminal_retried", "before_retirement", "capture_retired", "after_retirement",
                    "fresh_visible", "fresh_walk_complete") if current else ("after_exhaustion", "fresh_visible"))
        boundaries = [sample for sample in samples if sample["event"] in events]
        check(tuple(sample["event"] for sample in boundaries) == events,
              f"{name}: missing or out-of-order timeline boundaries")
        opening, overlap, complete = (boundaries[i]["status"] for i in (1, 2, 3))
        check(opening["state"] == overlap["state"] == "running" and
              integer(opening.get("generation"), 1) and overlap["generation"] == opening["generation"] and
              opening["covered_rows"] == overlap["covered_rows"] == held and opening["committed_rows"] == cutoff and
              integer(overlap.get("committed_rows"), cutoff + BATCH_ROWS, final) and
              complete["state"] == "complete" and integer(complete.get("generation"), opening["generation"] + 1) and
              complete["generation"] == publication["generation"] and complete["covered_rows"] == cutoff and
              integer(complete.get("committed_rows"), overlap["committed_rows"], final),
              f"{name}: invalid overlap or publication cutoff")
        for sample in boundaries:
            storage = sample["filesystem"]
            stage_bytes = storage.get("checkpoint_staging_apparent_bytes")
            check(integer(stage_bytes, 0) or
                  (not require_pin_retirement and stage_bytes is None and storage.get("unavailable")),
                  f"{name}: missing staging observation at {sample['event']}")
        drain = trial["pin_drain"]
        if require_pin_retirement and drain["status"] == "pending":
            raise Rejected(f"{name}: pin retirement pending: {drain.get('reason') or 'awaiting a measured zero'}")
        observed = (drain["status"] == "observed" and integer(drain.get("retired_pins_while_held"), 1) and
                    integer(drain.get("retired_pins_after_exhaustion"), 0, 0))
        unavailable = drain["status"] == "unavailable" and isinstance(drain.get("reason"), str) and drain["reason"]
        check(observed or (not require_pin_retirement and unavailable),
              f"{name}: incomplete pin-drain evidence")
        if current:
            check(trial.get("terminal_page_retried") is True and trial.get("capture_retired") is True and
                  trial.get("fresh_walk_exact") is True and
                  integer(trial.get("fresh_rows_checked"), final if pattern == "scattered" else rows + 1, final),
                  f"{name}: missing terminal retry, capture retirement, or exact fresh walk evidence")
            validate_retirement_samples(name, samples, boundaries, drain, publication["generation"], cutoff, final)
    check(generations[0] < generations[1] == published["generation"],
          f"{label}: inconsistent replacement generations")


def validate_retirement_samples(label, samples, boundaries, drain, generation, cutoff, final):
    retry, held, retired, after, fresh = boundaries[5:10]

    def pins(sample):
        return (sample.get("candidate_status_metrics") or {}).get("retired_generation_pins")

    def measured_at_final(sample):
        state = sample.get("status") or {}
        return (not sample.get("status_error") and state.get("state") == "complete" and
                state.get("generation") == generation and state.get("covered_rows") == cutoff and
                state.get("committed_rows") == final)

    check(all(integer(sample.get("elapsed_ns"), 0) for sample in samples) and
          [sample["elapsed_ns"] for sample in samples] == sorted(sample["elapsed_ns"] for sample in samples),
          f"{label}: invalid retirement timeline order")
    check(not drain.get("reason") and measured_at_final(held) and integer(pins(held), 1) and
          pins(held) == drain["retired_pins_while_held"] and
          integer(held.get("request_sent_ns"), retry["elapsed_ns"], held["elapsed_ns"]),
          f"{label}: missing positive predecessor pin measurement after terminal retry")
    polling = [sample for sample in samples[samples.index(after):samples.index(fresh)]
               if sample["event"] in ("after_retirement", "drain_poll")]
    check(polling and all(integer(sample.get("request_sent_ns"), retired["elapsed_ns"], sample["elapsed_ns"])
                          for sample in polling) and
          measured_at_final(polling[-1]) and integer(pins(polling[-1]), 0, 0),
          f"{label}: missing measured zero predecessor pins after capture retirement")


def validate_capacity_observations(run, seed, label, cgroups):
    fixture = run["fixture"]
    check(integer(fixture.get("query_work_budget"), CAPACITY_WORK_BUDGET, CAPACITY_WORK_BUDGET),
          f"{label}: expected explicit query work budget {CAPACITY_WORK_BUDGET}")
    group = run.get("cgroup")
    check(isinstance(group, dict), f"{label}: missing fixture cgroup observations")
    raw_path = group.get("path")
    check(isinstance(raw_path, str) and raw_path, f"{label}: missing fixture cgroup path")
    path = Path(raw_path)
    root = Path("/sys/fs/cgroup")
    check(path.is_relative_to(root) and path != root and ".." not in path.parts and path not in cgroups and
          all(path.parent == previous.parent for previous in cgroups),
          f"{label}: missing or reused fixture cgroup")
    cgroups.add(path)
    check(integer(group.get("memory_max_bytes"), MEMORY_LIMIT, MEMORY_LIMIT) and
          integer(group.get("memory_swap_max_bytes"), 0, 0), f"{label}: expected 128 MiB with swap disabled")

    diagnostics = run["diagnostics"]
    validate_no_oom_kills(diagnostics, label)
    progress = diagnostics.get("seed_progress")
    check(isinstance(progress, dict) and integer(progress.get("acknowledged_rows"), seed, seed) and
          integer(progress.get("published_rows"), seed, seed) and
          integer(progress.get("generation"), 1, run["compaction"]["generation"] - 1),
          f"{label}: incomplete acknowledged seed or seed checkpoint")

    candidates = diagnostics.get("candidates")
    check(isinstance(candidates, list) and all(isinstance(candidate, dict) for candidate in candidates) and
          [candidate.get("lifetime") for candidate in candidates] == ["startup", "restart"],
          f"{label}: missing startup or restart teardown evidence")
    for candidate in candidates:
        lifetime = candidate["lifetime"]
        check(candidate.get("reaped") is True and candidate.get("exited_before_cleanup") is False,
              f"{label}: {lifetime} exited before verifier teardown or was not reaped")
        signal = candidate.get("exit_signal", "")
        if signal == "killed":
            check(integer(candidate.get("exit_code"), -1, -1) and candidate.get("teardown_sigkill_sent") is True,
                  f"{label}: {lifetime} SIGKILL lacks verifier attribution")
        else:
            check(signal == "" and integer(candidate.get("exit_code"), 0, 0) and
                  not candidate.get("wait_error"), f"{label}: unexpected {lifetime} exit")


def validate_no_oom_kills(diagnostics, label):
    events = diagnostics.get("cgroup_memory_events")
    check(isinstance(events, dict) and {"oom", "oom_kill"} <= events.keys() and
          all(integer(count, 0) for count in events.values()) and events["oom_kill"] == 0 and
          events.get("oom_group_kill", 0) == 0, f"{label}: missing memory.events or recorded OOM kill")


def validate_memory_peak(timeline, peak, label, *, required=False):
    observed_overlap = False
    for sample in timeline["samples"]:
        if "cgroup_memory_current" not in sample:
            continue
        memory = sample["cgroup_memory_current"]
        check(isinstance(memory, dict) and not memory.get("error") and integer(memory.get("bytes"), 1, peak),
              f"{label}: memory.current sample outside the fixture cgroup peak or unavailable")
        observed_overlap |= sample["event"] == "overlap"
    check(not required or observed_overlap, f"{label}: missing memory.current overlap sample")


def validate_capacity(evidence, *, require_backfill_timelines=False, require_capacity_observations=False):
    check(isinstance(evidence, list) and len(evidence) == len(SEED_ROWS),
          "capacity: expected two fixture results")
    seen = set()
    cgroups = set()
    for run in evidence:
        fixture = run["fixture"]
        seed = fixture["seed_rows"]
        check(integer(seed, 1) and seed in SEED_ROWS - seen,
              f"capacity: unexpected or repeated size {seed!r}")
        seen.add(seed)
        label = f"capacity ({seed} rows)"
        for key, want in {"tail_rows": TAIL_ROWS, "batch_rows": BATCH_ROWS, "line_bytes": 1024,
                          "memory_limit_bytes": MEMORY_LIMIT}.items():
            check(integer(fixture.get(key), want, want), f"{label}: invalid {key}")
        check(run["status"] == "pass" and run["workload_status"] == "pass" and
              run["phase"] == "complete" and run["timed_out"] is False and
              ("unavailable" not in run or run["unavailable"] == {}),
              f"{label}: incomplete run or unavailable measurement")
        for key in ("start_to_ready_ns", "restart_to_ready_ns", "ingest_p99_ns", "backfill_query_p99_ns",
                    "peak_rss_bytes", "peak_descriptors", "initial_disk_free_bytes",
                    "minimum_disk_headroom_bytes"):
            check(integer(run.get(key), 1), f"{label}: missing or invalid {key}")
        check(run["minimum_disk_headroom_bytes"] <= run["initial_disk_free_bytes"], f"{label}: invalid disk samples")
        check(integer(run.get("cgroup_peak_memory_bytes"), 1, MEMORY_LIMIT), f"{label}: invalid cgroup memory peak")
        devices = run["device_io"]
        check(isinstance(devices, dict) and devices and
              all(re.fullmatch(r"[0-9]+:[0-9]+", dev) and isinstance(counters, dict) and
                  {"rbytes", "wbytes"} <= counters.keys() and
                  all(integer(value, 0) for value in counters.values()) for dev, counters in devices.items()),
              f"{label}: missing or invalid device I/O counters")
        # The broad walk sees three matching rows per four-row timestamp group.
        # The mixed walk leaves at least one continuation for after the overlap.
        broad_rows = 9 * seed // 16 - 3
        min_queries = (broad_rows - 510 + 508) // 509
        check(integer(run.get("backfill_query_samples"), min_queries, broad_rows - 1) and
              integer(run.get("ingest_samples"), TAIL_ROWS // BATCH_ROWS, TAIL_ROWS // BATCH_ROWS),
              f"{label}: incomplete latency samples")
        total = seed + TAIL_ROWS
        check(integer(run.get("recovered_rows"), total, total), f"{label}: incomplete restart walk")
        compaction = run["compaction"]
        check(compaction["state"] == "complete" and integer(compaction.get("generation"), seed // 8192 + 1) and
              integer(compaction.get("covered_rows"), seed + BATCH_ROWS, seed + BATCH_ROWS) and
              integer(compaction.get("committed_rows"), total, total), f"{label}: invalid compaction evidence")
        diagnostics = run["diagnostics"]
        current = "cgroup_memory_limit_bytes" in run
        if require_capacity_observations:
            if current:
                validate_no_oom_kills(diagnostics, label)
                check(integer(run.get("cgroup_memory_limit_bytes"), MEMORY_LIMIT, MEMORY_LIMIT) and
                      integer(run.get("cgroup_swap_max_bytes"), 0, 0) and
                      integer(run.get("cgroup_oom_kill_count"), 0, 0) and
                      run["cleanup"].get("store_removed") is True,
                      f"{label}: incomplete kernel readbacks or fixture store cleanup")
            else:
                validate_capacity_observations(run, seed, label, cgroups)
        if require_backfill_timelines:
            check(current or integer(fixture.get("query_work_budget"), 1), f"{label}: missing explicit query work budget")
            check(integer(diagnostics.get("peak_sampled_checkpoint_staging_bytes"), 0),
                  f"{label}: missing peak checkpoint staging bytes")
        for timeline in diagnostics.get("backfill_timelines", ()):
            validate_memory_peak(timeline, run["cgroup_peak_memory_bytes"], label,
                                 required=current and require_capacity_observations)
        if require_backfill_timelines or "backfill_timelines" in diagnostics:
            validate_backfill_timelines(diagnostics.get("backfill_timelines"), seed, compaction,
                                        require_pin_retirement=require_backfill_timelines)
        for phase in ("after_publication_continuation", "fresh_backfill", "restart_walk"):
            query = diagnostics["queries"][phase]
            last = query["last"]
            check(integer(query.get("attempts"), 1) and "first_failure" not in query and
                  last.get("phase") == "complete" and integer(last.get("http_status"), 200, 200) and
                  last.get("has_cursor_header") is False,
                  f"{label}: incomplete {phase} evidence")
        for snapshot in ("opening_compaction", "overlap_compaction"):
            running = diagnostics[snapshot]
            check(running["state"] == "running" and integer(running.get("generation"), 1, compaction["generation"] - 1),
                  f"{label}: missing {snapshot} generation evidence")
        cleanup = run["cleanup"]
        check(cleanup["status"] == "pass" and cleanup["candidate_reaped"] is True and
              cleanup["subtree_empty"] is True and cleanup["subtree_removed"] is True and
              cleanup.get("detail", "") == "", f"{label}: incomplete process or cgroup cleanup")


def validate_budget_trials(walk, name, rows, budget):
    probes = walk["probes"]
    check(isinstance(probes, list) and probes and integer(walk.get("exact_threshold_budget"), budget, budget),
          f"admission: missing {name} exact budget threshold")
    observed = {}
    for probe in probes:
        trial = probe.get("budget")
        check(integer(trial, 1, 2048) and trial not in observed and "failure" not in probe,
              f"admission: invalid {name} budget trial")
        observed[trial] = probe.get("outcome")
        outcome, pages, count = ("clean_rejection", 0, 0) if trial < budget else ("exhausted", 3, rows)
        check(observed[trial] == outcome and integer(probe.get("pages"), pages, pages) and
              integer(probe.get("rows"), count, count), f"admission: incomplete {name} walk at budget {trial}")
    check(observed.get(budget) == "exhausted" and (budget == 1 or observed.get(budget - 1) == "clean_rejection") and
          sum(trial < budget for trial in observed) == walk["rejected_budgets"],
          f"admission: unproven {name} budget boundary")


def validate_budget(evidence, *, require_fixed_boundaries=False, require_tied_byte_walk=False):
    check(integer(evidence.get("http_status"), 503, 503) and
          integer(evidence.get("ndjson_rows"), 0, 0) and evidence.get("next_cursor") is False and
          integer(evidence.get("elapsed_ms"), 0, 1999), "admission: incomplete work budget rejection")
    tied = evidence["fixed_budget_walk"]
    sparse = tied["sparse_walk"]
    trial_report = "probes" in tied or "probes" in sparse
    check(evidence.get("framed_budget_rejection", trial_report) is True,
          "admission: missing framed work budget rejection")
    for name, walk, rows, boundary in (("tied", tied, 3, 11), ("sparse", sparse, 4, 314)):
        budget = walk.get("first_cursor_budget")
        check(integer(budget, 2, 2048) and integer(walk.get("rejected_budgets"), 1, budget - 1) and
              integer(walk.get("rows"), rows, rows) and integer(walk.get("pages"), 3, 3) and not
              {"issuance_failure", "continuation_failure", "first_failure", "first_broken_continuation"} & walk.keys(),
              f"admission: incomplete {name} fixed-budget walk")
        if trial_report:
            validate_budget_trials(walk, name, rows, budget)
        else:
            check(integer(walk.get("continuation_pages"), 2, 2) and walk.get("terminal") is True,
                  f"admission: incomplete {name} continuation evidence")
        if require_fixed_boundaries:
            check(budget == boundary and trial_report, f"admission: expected {name} boundary at budget {boundary}")
            exact = next(probe for probe in walk["probes"] if probe["budget"] == boundary)
            check(integer(exact.get("post_issuance_append_rows"), 2, 2) and integer(exact.get("resume_limit"), 1, 1),
                  f"admission: missing {name} post-issuance appends or resume limit 1")
    if require_fixed_boundaries:
        duplicate = tied.get("duplicate_walk", {})
        check(duplicate.get("outcome") == "exhausted" and "failure" not in duplicate and
              all(integer(duplicate.get(key), value, value) for key, value in
                  {"budget": 11, "pages": 3, "rows": 3, "post_issuance_append_rows": 2, "resume_limit": 1}.items()),
              "admission: incomplete duplicate-row walk")
    if require_tied_byte_walk or "tied_byte_walk" in tied:
        trimmed = tied.get("tied_byte_walk", {})
        check(trimmed.get("outcome") == "exhausted" and "failure" not in trimmed and
              all(integer(trimmed.get(key), value, value) for key, value in
                  {"budget": 4096, "pages": 3, "rows": 4, "post_issuance_append_rows": 2, "resume_limit": 1,
                   "response_byte_cap": 96, "first_limit": 4, "first_rows": 2}.items()),
              "admission: incomplete tied byte-trimmed walk")
    check((require_fixed_boundaries or tied["rejected_budgets"] == tied["first_cursor_budget"] - 1) and
          all(integer(sparse.get(key), value, value) for key, value in
              {"response_byte_cap": 96, "first_limit": 4, "first_rows": 2, "resume_limit": 1}.items()),
          "admission: missing budget boundary or sparse byte-trim evidence")


def validate_parity(evidence, *, require_writable_restore=False):
    if require_writable_restore or "restore_status" in evidence:
        check(evidence.get("restore_status") == "pass", "parity: writable restore did not pass")
    if require_writable_restore or "restored_control_404_checks" in evidence:
        hidden = evidence.get("restored_control_404_checks")
        check(integer(hidden, 4, 4) or integer(hidden, 6, 6),
              "parity: capacity control was not proven absent on restore and restart")
    point = evidence["verified_point"]
    generation = point["Generation"]
    check(isinstance(generation, list) and len(generation) == 32 and
          all(integer(byte, 0, 255) for byte in generation) and any(generation) and
          integer(point["NextOrdinal"], 3, 3) and integer(point["CoveredOffset"], 1) and
          integer(point["CommittedEnd"], point["CoveredOffset"] + 1),
          "parity: expected a verified checkpoint and nonempty WAL suffix")
    check(integer(evidence["legacy_rows"], 6, 6) and integer(evidence["captured_rows"], 6, 6) and
          evidence["post_restore_204"] is True and integer(evidence["post_append_rows"], 7, 7) and
          integer(evidence["restart_rows"], 7, 7), "parity: incomplete restore, ingest or restart evidence")

    check(integer(evidence.get("unpaged_checks"), 4, 4) and evidence.get("stale_cursor_rejected") is True,
          "parity: missing unpaged or prior-process cursor evidence")
    if "legacy_restart_rows" in evidence:
        check(integer(evidence["legacy_restart_rows"], 7, 7), "parity: incomplete legacy WAL restart")
    if "backup_compare" in evidence:
        compare = evidence["backup_compare"]
        check(integer(compare.get("default_rows"), 6, 6) and type(compare.get("page_ceiling_advertised")) is bool,
              "parity: incomplete default backup comparison")
        if compare["page_ceiling_advertised"]:
            check(integer(compare.get("bounded_rows"), 6, 6) and integer(compare.get("low_cap_exit"), 4, 4),
                  "parity: incomplete bounded backup comparison")
    resource = evidence["retained_resource_admission"]
    check(resource["status"] == "pass" and integer(resource.get("limit_bytes"), 1) and
          integer(resource.get("rejected_http_status"), 503, 503) and
          resource.get("unchanged_wal") is True and integer(resource.get("restart_rows"), 7, 7),
          "parity: incomplete retained tail admission or restart evidence")
    replacement = evidence["live_replacement"]
    initial, published = replacement["initial"], replacement["published"]
    if require_writable_restore or "store" in replacement:
        check(replacement.get("store") == "legacy_wal", "parity: replacement requires a full WAL")
    before = evidence["legacy_restart_rows"] if "store" in replacement else evidence["post_append_rows"]
    after = before + 2
    check(replacement["status"] == "pass" and integer(initial.get("generation"), 0) and
          integer(initial.get("covered_rows"), 0, before) and
          integer(initial.get("committed_rows"), before, before) and published["state"] == "complete" and
          integer(published.get("generation"), initial["generation"] + 1) and
          all(integer(published.get(key), after, after) for key in ("covered_rows", "committed_rows")) and
          integer(replacement.get("append_http_status"), 204, 204) and
          integer(replacement.get("snapshot_rows"), before, before) and
          all(integer(replacement.get(key), after, after) for key in ("fresh_rows", "restart_rows")),
          "parity: incomplete generation replacement or snapshot evidence")


def validate_durability(directory, expected, *, require_fixture_root_cleanup=False):
    report = read_report(directory, "durability", expected)
    if require_fixture_root_cleanup or FIXTURE_ROOT_CLEANUP in report["cases"]:
        passing_case(report, "durability", FIXTURE_ROOT_CLEANUP)
    for name in ("sigkill", "recovery", "enospc"):
        proof = passing_case(report, "durability", name)["evidence"]
        check(integer(proof.get("stale_cursors_rejected"), 1), f"durability: {name} lacks prior-process cursor evidence")
    healthy = proof["healthy_to_full"]
    full = proof["full_to_healthy"]
    check(integer(healthy.get("readiness_status"), 200, 200) and healthy.get("readiness_reason") == "ready" and
          integer(healthy.get("ingest_status"), 204, 204) and healthy.get("replayed_after_restart") is True and
          integer(full.get("readiness_status"), 503, 503) and full.get("readiness_reason") == "low_disk_headroom" and
          integer(full.get("ingest_status"), 503, 503) and full.get("post_ingest_reason") == "wal_rollback" and
          full.get("post_ingest_category") == "enospc", "durability: incomplete active-filesystem retarget evidence")


def record_fixture_root_cleanup(directory, expected, parent):
    report = read_report(directory, "durability", expected)
    cases = report["cases"]
    if FIXTURE_ROOT_CLEANUP in cases:
        passing_case(report, "durability", FIXTURE_ROOT_CLEANUP)
    # rmdir checks that the producer removed its fixture tree without traversing
    # a leftover mount or erasing evidence of a leak.
    try:
        parent.rmdir()
    except OSError as exc:
        cases[FIXTURE_ROOT_CLEANUP] = {"status": "fail", "detail": str(exc)}
    else:
        cases.setdefault(FIXTURE_ROOT_CLEANUP, {"status": "pass"})
    (directory / "durability.json").write_text(json.dumps(report, indent=2) + "\n")
    passing_case(report, "durability", FIXTURE_ROOT_CLEANUP)


def validate_cutover_parity(report, evidence):
    ordinary = passing_case(report, "parity", "ordinary_wal_reopen")["evidence"]
    check(integer(ordinary.get("append_status"), 204, 204) and
          integer(evidence.get("legacy_append_status"), 204, 204) and
          integer(ordinary.get("reopened_rows"), 6, 6) and integer(ordinary.get("restart_rows"), 7, 7) and
          ordinary["reopened_rows"] == evidence.get("legacy_rows") and
          ordinary["restart_rows"] == evidence.get("legacy_restart_rows"),
          "parity: incomplete ordinary WAL reopen, append, or exact restart evidence")
    check(evidence.get("legacy_restart_unpaged") is True and
          integer(evidence.get("restored_control_404_checks"), 6, 6),
          "parity: missing ordinary legacy restart or default-off restored control evidence")
    check(evidence.get("fixture_removed") is True, "parity: fixture cleanup did not complete")
    check(integer(evidence.get("corrupt_restore_exit"), 1, 1) and
          evidence.get("restore_metadata_preserved") is True,
          "parity: missing fail-closed startup or immutable v1 backup metadata evidence")
    check(integer(evidence.get("held_restore_rows"), 6, 6) and evidence.get("replayed_restore_page") is True,
          "parity: missing framed restored continuation replay across append")
    check(integer(evidence.get("reopened_restore_append_status"), 204, 204) and
          integer(evidence.get("reopened_restore_restart_rows"), 8, 8),
          "parity: missing durable append after writable restore reopen")


def validate_cutover_control(case):
    control = case["evidence"]
    retirement = control.get("retirement") or {}
    check(retirement.get("status") == "pass" and retirement.get("terminal_page_retried") is True and
          integer(retirement.get("retire_http_status"), 204, 204) and
          integer(retirement.get("invalid_cursor_http_status"), 400, 499) and
          integer(retirement.get("pins_while_held"), 1) and
          integer(retirement.get("pins_after_release"), 0, 0),
          "control: missing terminal retry, authenticated retirement, or positive-to-zero predecessor pin evidence")
    check(control.get("continuation_replayed") is True and control.get("fixture_removed") is True and
          integer(control.get("retire_hidden_checks"), 2, 2),
          "control: missing continuation replay, disabled retirement, or fixture cleanup evidence")
    published, reopened = control.get("published") or {}, control.get("reopened") or {}
    check(control.get("environment_opt_in") is True and
          published.get("state") == reopened.get("state") == "complete" and
          all(type(reopened.get(key)) is int and type(published.get(key)) is int and reopened[key] == published[key]
              for key in ("generation", "covered_rows", "committed_rows")),
          "control: missing environment opt-in or exact generation after SIGKILL reopen")
    wildcard_checks, wildcard_exit = control.get("wildcard_control_404_checks"), control.get("wildcard_opt_in_exit")
    check(integer(wildcard_checks, 3, 3) and integer(wildcard_exit, 0, 0) or
          integer(wildcard_checks, 0, 0) and integer(wildcard_exit, 1, 1),
          "control: wildcard must hide the route or reject opt-in at startup")
    launches = ((True, 0), (True, -signal.SIGKILL), (True, -signal.SIGKILL), (True, 0),
                (None, wildcard_exit), (True, 0))
    processes = case.get("processes")
    check(isinstance(processes, list) and len(processes) == len(launches) and
          all(proc.get("expected_ready") is ready and integer(proc.get("exit_code"), code, code)
              for proc, (ready, code) in zip(processes, launches)),
          "control: missing process teardown or unexpected candidate exit")


def validate(directory, expected, *, require_fixture_root_cleanup=False, require_fixed_boundaries=False,
             require_backfill_timelines=False, require_capacity_observations=False, cutover_arch=None):
    if cutover_arch:
        expected = {**expected, "arch": cutover_arch}
    statuses = (directory / "producers.txt").read_text().splitlines()
    check(len(statuses) == len(PRODUCERS) and
          set(statuses) == {f"{name} revision={expected['revision']} exit=0" for name in PRODUCERS},
          "missing, repeated or failing release producer status")
    validate_budget(case_evidence(directory, "admission", "work_budget", expected),
                    require_fixed_boundaries=require_fixed_boundaries, require_tied_byte_walk=bool(cutover_arch))
    validate_durability(directory, expected, require_fixture_root_cleanup=require_fixture_root_cleanup)
    validate_capacity(case_evidence(directory, "capacity", "retained_history_capacity", expected),
                      require_backfill_timelines=require_backfill_timelines,
                      require_capacity_observations=require_capacity_observations)
    parity_report = read_report(directory, "parity", expected)
    parity = passing_case(parity_report, "parity", "restored_parity")["evidence"]
    validate_parity(parity, require_writable_restore=require_backfill_timelines)
    control_report = read_report(directory, "control", expected)
    control_case = passing_case(control_report, "control", "capacity_control")
    control = control_case["evidence"]
    if cutover_arch:
        validate_cutover_parity(parity_report, parity)
        check(parity.get("corrupt_restore_preserved") is True,
              "parity: missing corrupt restore file preservation evidence")
        validate_cutover_control(control_case)
    published = control["published"]
    expanded = "fresh_rows" in control
    covered, committed = (4, 5) if expanded else (3, 3)
    if require_capacity_observations:
        check(integer(control.get("default_control_404_checks"), 4, 4),
              "control: missing default-off status and start probes")
    if expanded or require_backfill_timelines:
        check(integer(control.get("fresh_rows"), 5, 5), "control: incomplete fresh visibility evidence")
    check(integer(control["default_http_status"], 404, 404) and
          (integer(control.get("wildcard_opt_in_exit"), 1, 1) or
           integer(control.get("wildcard_opt_in_exit"), 0, 0) and
           integer(control.get("wildcard_control_404_checks"), 3, 3)) and
          integer(control["initial_generation"], 0) and published["state"] == "complete" and
          integer(published["generation"], control["initial_generation"] + 1) and
          integer(published["covered_rows"], covered, covered) and
          integer(published["committed_rows"], committed, committed) and
          integer(control["restart_rows"], committed, committed), "control: incomplete loopback or restart evidence")
    if expanded or "snapshot_rows" in control or "stale_cursor_rejected" in control:
        check(integer(control.get("snapshot_rows"), 3, 3) and control.get("stale_cursor_rejected") is True,
              "control: incomplete cursor evidence across compaction and restart")


def produce_control(binary, directory, expected):
    processes = []
    token = PROCESS_LOGS.set((directory, processes))
    case = {"status": "fail", "processes": processes}
    try:
        with tempfile.TemporaryDirectory(prefix="bog-release-control-") as workspace:
            metrics = capacity_control_suite(binary, Path(workspace) / "control")
        if isinstance(metrics, SuiteSkipped):
            case.update(status="skip", detail=metrics.reason)
        else:
            metrics["fixture_removed"] = not Path(workspace).exists()
            check(metrics["fixture_removed"], "control: fixture cleanup did not complete")
            case.update(status="pass", evidence=metrics)
    except Exception as exc:
        case["detail"] = str(exc)
        raise
    finally:
        PROCESS_LOGS.reset(token)
        report = {**expected, "cases": {"capacity_control": case}}
        (directory / "control.json").write_text(json.dumps(report, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("control", "record-cleanup", "validate"))
    parser.add_argument("binary", type=Path)
    parser.add_argument("revision")
    parser.add_argument("fixture")
    parser.add_argument("directory", type=Path)
    parser.add_argument("--arch", choices=("amd64", "arm64"))
    parser.add_argument("--fixture-parent", type=Path)
    parser.add_argument("--require-fixture-root-cleanup", action="store_true")
    parser.add_argument("--require-fixed-boundaries", action="store_true")
    parser.add_argument("--require-backfill-timelines", action="store_true")
    parser.add_argument("--require-capacity-observations", action="store_true")
    args = parser.parse_args()
    try:
        directory = args.directory.resolve()
        binary = args.binary.resolve()
        expected = identity(binary, args.revision, args.fixture)
        native_arch = {"x86_64": "amd64", "aarch64": "arm64"}.get(platform.machine())
        if args.action == "control":
            produce_control(binary, directory, {**expected, "arch": native_arch})
        elif args.action == "record-cleanup":
            check(args.fixture_parent is not None, "durability fixture parent is required")
            record_fixture_root_cleanup(directory, expected, args.fixture_parent)
        else:
            verdict = directory / "qualified.json"
            verdict.unlink(missing_ok=True)
            check(args.arch is not None, "native architecture is required")
            # Check the ELF machine independently of the runner label and reports.
            with binary.open("rb") as stream:
                header = stream.read(20)
            machine = {"amd64": 62, "arm64": 183}[args.arch]
            check(header[:6] == b"\x7fELF\x02\x01" and int.from_bytes(header[18:20], "little") == machine,
                  f"candidate binary is not Linux {args.arch}")
            cutover = all((args.require_fixture_root_cleanup, args.require_fixed_boundaries,
                           args.require_backfill_timelines, args.require_capacity_observations))
            if cutover:
                check(platform.system() == "Linux" and native_arch == args.arch,
                      f"cutover must be validated on native Linux {args.arch}")
            validate(directory, expected, require_fixture_root_cleanup=args.require_fixture_root_cleanup,
                     require_fixed_boundaries=args.require_fixed_boundaries,
                     require_backfill_timelines=args.require_backfill_timelines,
                     require_capacity_observations=args.require_capacity_observations,
                     cutover_arch=args.arch if cutover else None)
            qualification = {**expected, "arch": args.arch}
            if cutover:
                qualification["current_observations"] = True
            verdict.write_text(json.dumps(qualification) + "\n")
    except (Rejected, OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        parser.exit(1, f"release evidence: {exc}\n")


if __name__ == "__main__":
    main()
