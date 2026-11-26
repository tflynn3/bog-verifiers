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


def identity(binary, revision, fixture):
    check(re.fullmatch(r"[0-9a-f]{40}", revision) and fixture == FIXTURE, "invalid release identity")
    return {"schema_version": 1, "revision": revision, "binary_sha256": file_sha256(binary),
            "fixture": fixture}


def case_evidence(directory, producer, name, expected):
    with (directory / f"{producer}.json").open() as stream:
        report = json.load(stream, object_pairs_hook=unique_fields)
    for key, value in expected.items():
        check(type(report.get(key)) is type(value) and report[key] == value,
              f"{producer}: mismatched {key}")
    if producer == "capacity":
        check(report.get("mode") == "live", "capacity: live mode is required")
    case = report["cases"][name]
    check(case["status"] == "pass", f"{producer}: {name} did not pass")
    return case["evidence"]


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
        cleanup = run["cleanup"]
        check(cleanup["status"] == "pass" and cleanup["candidate_reaped"] is True and
              cleanup["subtree_empty"] is True and cleanup["subtree_removed"] is True and
              cleanup.get("detail", "") == "", f"{label}: incomplete process or cgroup cleanup")


def validate_budget(evidence):
    check(integer(evidence.get("http_status"), 503, 503) and
          integer(evidence.get("ndjson_rows"), 0, 0) and evidence.get("next_cursor") is False and
          integer(evidence.get("elapsed_ms"), 0, 1999), "admission: incomplete work budget rejection")
    fixed = evidence["fixed_budget_pagination"]
    budget = fixed.get("budget")
    check(integer(budget, 2, 16_384) and integer(fixed.get("rejected_budget"), budget - 1, budget - 1) and
          integer(fixed.get("rejected_http_status"), 503, 503) and integer(fixed.get("first_rows"), 1, 1) and
          integer(fixed.get("resumed_rows"), 1, 1) and fixed.get("terminal") is True,
          "admission: missing measured cursor budget or terminal continuation")


def validate_parity(evidence):
    point = evidence["verified_point"]
    generation = point["Generation"]
    check(isinstance(generation, list) and len(generation) == 32 and
          all(integer(byte, 0, 255) for byte in generation) and any(generation) and
          integer(point["NextOrdinal"], 3, 3) and integer(point["CoveredOffset"], 1) and
          integer(point["CommittedEnd"], point["CoveredOffset"] + 1),
          "parity: expected a verified checkpoint and nonempty WAL suffix")
    check(integer(evidence["legacy_rows"], 6, 6) and integer(evidence["captured_rows"], 6, 6) and
          evidence["post_restore_204"] is True and integer(evidence["appended_rows"], 7, 7) and
          integer(evidence["restart_rows"], 7, 7), "parity: incomplete restore, ingest or restart evidence")

    terminal = evidence["terminal_walks"]
    check(all(integer(terminal.get(stage), 9, 9) for stage in ("legacy", "restored", "appended", "restart")),
          "parity: incomplete terminal walks")


def validate(directory, expected):
    statuses = (directory / "producers.txt").read_text().splitlines()
    check(len(statuses) == len(PRODUCERS) and
          set(statuses) == {f"{name} revision={expected['revision']} exit=0" for name in PRODUCERS},
          "missing, repeated or failing release producer status")
    validate_budget(case_evidence(directory, "admission", "work_budget", expected))
    validate_capacity(case_evidence(directory, "capacity", "retained_history_capacity", expected))
    validate_parity(case_evidence(directory, "parity", "restored_parity", expected))
    control = case_evidence(directory, "control", "capacity_control", expected)
    published = control["published"]
    check(integer(control["default_http_status"], 404, 404) and integer(control["wildcard_opt_in_exit"], 1) and
          integer(control["initial_generation"], 0) and published["state"] == "complete" and
          integer(published["generation"], control["initial_generation"] + 1) and
          integer(published["covered_rows"], 3, 3) and integer(published["committed_rows"], 3, 3) and
          integer(control["restart_rows"], 3, 3), "control: incomplete loopback or restart evidence")


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
    parser.add_argument("action", choices=("control", "validate"))
    parser.add_argument("binary", type=Path)
    parser.add_argument("revision")
    parser.add_argument("fixture")
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    try:
        directory = args.directory.resolve()
        binary = args.binary.resolve()
        expected = identity(binary, args.revision, args.fixture)
        if args.action == "control":
            produce_control(binary, directory, expected)
        else:
            validate(directory, expected)
    except (Rejected, OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        parser.exit(1, f"release evidence: {exc}\n")


if __name__ == "__main__":
    main()
