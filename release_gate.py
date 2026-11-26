"""Produce the small capacity control report and validate Linux release evidence."""
import argparse
import json
from pathlib import Path
import re
import tempfile

from verify import (PROCESS_LOGS, Rejected, SuiteSkipped, capacity_control_suite, check,
                    file_sha256, unique_fields)


FIXTURE = "linux-release-v1"
MEMORY_LIMIT = 128 * 1024**2
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


def validate_capacity(evidence):
    check(isinstance(evidence, list) and len(evidence) == len(SEED_ROWS),
          "capacity: expected two fixture results")
    seen = set()
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
        # Only continuations that precede publication count toward the p99.
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


def validate_budget(evidence, *, require_fixed_boundaries=False):
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
            check(integer(exact.get("post_issuance_append_rows"), 2, 2),
                  f"admission: missing {name} post-issuance appends")
    if require_fixed_boundaries:
        duplicate = tied.get("duplicate_walk", {})
        check(duplicate.get("outcome") == "exhausted" and "failure" not in duplicate and
              all(integer(duplicate.get(key), value, value) for key, value in
                  {"budget": 11, "pages": 3, "rows": 3, "post_issuance_append_rows": 2}.items()),
              "admission: incomplete duplicate-row walk")
    check((require_fixed_boundaries or tied["rejected_budgets"] == tied["first_cursor_budget"] - 1) and
          all(integer(sparse.get(key), value, value) for key, value in
              {"response_byte_cap": 96, "first_limit": 4, "first_rows": 2, "resume_limit": 1}.items()),
          "admission: missing budget boundary or sparse byte-trim evidence")


def validate_parity(evidence):
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
    before, after = evidence["post_append_rows"], evidence["post_append_rows"] + 2
    check(replacement["status"] == "pass" and integer(initial.get("generation"), 0) and
          integer(initial.get("covered_rows"), 0, before) and
          integer(initial.get("committed_rows"), before, before) and published["state"] == "complete" and
          integer(published.get("generation"), initial["generation"] + 1) and
          all(integer(published.get(key), after, after) for key in ("covered_rows", "committed_rows")) and
          integer(replacement.get("append_http_status"), 204, 204) and
          integer(replacement.get("snapshot_rows"), before, before) and
          all(integer(replacement.get(key), after, after) for key in ("fresh_rows", "restart_rows")),
          "parity: incomplete restored generation replacement or snapshot evidence")


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


def validate(directory, expected, *, require_fixture_root_cleanup=False, require_fixed_boundaries=False):
    statuses = (directory / "producers.txt").read_text().splitlines()
    check(len(statuses) == len(PRODUCERS) and
          set(statuses) == {f"{name} revision={expected['revision']} exit=0" for name in PRODUCERS},
          "missing, repeated or failing release producer status")
    validate_budget(case_evidence(directory, "admission", "work_budget", expected),
                    require_fixed_boundaries=require_fixed_boundaries)
    validate_durability(directory, expected, require_fixture_root_cleanup=require_fixture_root_cleanup)
    validate_capacity(case_evidence(directory, "capacity", "retained_history_capacity", expected))
    validate_parity(case_evidence(directory, "parity", "restored_parity", expected))
    control = case_evidence(directory, "control", "capacity_control", expected)
    published = control["published"]
    check(integer(control["default_http_status"], 404, 404) and integer(control["wildcard_opt_in_exit"], 1) and
          integer(control["initial_generation"], 0) and published["state"] == "complete" and
          integer(published["generation"], control["initial_generation"] + 1) and
          integer(published["covered_rows"], 3, 3) and integer(published["committed_rows"], 3, 3) and
          integer(control["restart_rows"], 3, 3), "control: incomplete loopback or restart evidence")
    if "snapshot_rows" in control or "stale_cursor_rejected" in control:
        check(integer(control.get("snapshot_rows"), 3, 3) and control.get("stale_cursor_rejected") is True,
              "control: incomplete cursor evidence across compaction and restart")


def produce_control(binary, directory, expected):
    processes = []
    token = PROCESS_LOGS.set((directory, processes))
    case = {"status": "fail", "processes": processes}
    try:
        with tempfile.TemporaryDirectory(prefix="bog-release-control-") as workspace:
            metrics = capacity_control_suite(binary, Path(workspace) / "control")
        check(not isinstance(metrics, SuiteSkipped), f"release requires capacity control: {getattr(metrics, 'reason', '')}")
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
    args = parser.parse_args()
    try:
        directory = args.directory.resolve()
        binary = args.binary.resolve()
        expected = identity(binary, args.revision, args.fixture)
        if args.action == "control":
            produce_control(binary, directory, expected)
        elif args.action == "record-cleanup":
            check(args.fixture_parent is not None, "durability fixture parent is required")
            record_fixture_root_cleanup(directory, expected, args.fixture_parent)
        else:
            check(args.arch is not None, "native architecture is required")
            # Check the ELF machine independently of the runner label and reports.
            with binary.open("rb") as stream:
                header = stream.read(20)
            machine = {"amd64": 62, "arm64": 183}[args.arch]
            check(header[:6] == b"\x7fELF\x02\x01" and int.from_bytes(header[18:20], "little") == machine,
                  f"candidate binary is not Linux {args.arch}")
            validate(directory, expected, require_fixture_root_cleanup=args.require_fixture_root_cleanup,
                     require_fixed_boundaries=args.require_fixed_boundaries)
            (directory / "qualified.json").write_text(json.dumps({**expected, "arch": args.arch}) + "\n")
    except (Rejected, OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        parser.exit(1, f"release evidence: {exc}\n")


if __name__ == "__main__":
    main()
