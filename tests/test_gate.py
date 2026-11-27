"""Regressions for the Slipway entrypoint and required-suite runner."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import verify
from release_gate import (CAPACITY_WORK_BUDGET, FIXTURE_ROOT_CLEANUP, MEMORY_LIMIT, record_fixture_root_cleanup,
                          validate_backfill_timelines, validate_budget, validate_budget_trials,
                          validate_capacity_observations, validate_cutover_control,
                          validate_cutover_parity, validate_durability)

README_ONLY = "7655ed627bccad30700b8de4b6f47c8d7d5d8579"


def entrypoint(*args, **inputs):
    env = {key: value for key, value in os.environ.items() if not key.startswith("SLIPWAY_")}
    env.update(inputs)
    return subprocess.run(
        [str(ROOT / "verify.sh"), *args], env=env, capture_output=True, text=True, timeout=30
    )


def readme_candidate(sha):
    return dict(
        SLIPWAY_REPOSITORY=str(ROOT / "tests/fixtures/readme-only.bundle"),
        SLIPWAY_CANDIDATE_BRANCH="main",
        SLIPWAY_CANDIDATE_COMMIT=sha,
    )


def buildable_candidate(root):
    source, work = root / "source", root / "work"
    (source / "cmd/bog").mkdir(parents=True)
    work.mkdir()
    (source / "go.mod").write_text("module gate.invalid/regression\n\ngo 1.20\n")
    (source / "cmd/bog/main.go").write_text("package main\nfunc main() {}\n")
    return source, work


class GateTest(unittest.TestCase):
    def test_cutover_requires_retirement_exit_and_cleanup_evidence(self):
        retirement = dict(status="pass", release_http_status=204, pins_while_held=1, pins_after_release=0)
        evidence = dict(retirement=retirement, continuation_replayed=True, fixture_removed=True,
                        release_hidden_checks=2)
        processes = [dict(expected_ready=ready, exit_code=code)
                     for ready, code in ((True, 0), (True, -9), (False, 1), (True, 0))]
        case = dict(evidence=evidence, processes=processes)
        validate_cutover_control(case)
        for item, changes, reason in (
            (retirement, {"status": "skip"}, "successful release"),
            (retirement, {"pins_after_release": None}, "positive-to-zero"),
            (processes[1], {"exit_code": 0}, "unexpected candidate exit"),
            (evidence, {"fixture_removed": False}, "fixture cleanup"),
        ):
            with self.subTest(changes=changes), patch.dict(item, changes):
                with self.assertRaisesRegex(verify.Rejected, reason):
                    validate_cutover_control(case)

        parity = dict(fixture_removed=True, corrupt_restore_exit=1, restore_metadata_preserved=True,
                      held_restore_rows=6, replayed_restore_page=True)
        validate_cutover_parity(parity)
        del parity["replayed_restore_page"]
        with self.assertRaisesRegex(verify.Rejected, "continuation replay"):
            validate_cutover_parity(parity)

    def test_capacity_observations_require_distinct_groups_and_attributed_teardown(self):
        seed = 196_608
        candidate = dict(lifetime="startup", reaped=True, exited_before_cleanup=False, exit_code=0)
        restart = dict(candidate, lifetime="restart", exit_code=-1, exit_signal="killed", teardown_sigkill_sent=True)
        group = dict(path="/sys/fs/cgroup/release/capacity-first", memory_max_bytes=MEMORY_LIMIT,
                     memory_swap_max_bytes=0)
        progress = dict(acknowledged_rows=seed, published_rows=seed, generation=25)
        events = dict(oom=0, oom_kill=0)
        run = dict(fixture=dict(query_work_budget=CAPACITY_WORK_BUDGET), cgroup=group,
                   compaction=dict(generation=26), diagnostics=dict(
                       seed_progress=progress, cgroup_memory_events=events, candidates=[candidate, restart]))
        seen = set()
        validate_capacity_observations(run, seed, "fixture", seen)
        with self.assertRaisesRegex(verify.Rejected, "reused fixture cgroup"):
            validate_capacity_observations(run, seed, "fixture", seen)

        for target, changes, reason in (
            (run["fixture"], {"query_work_budget": 1}, "explicit query work budget"),
            (group, {"memory_swap_max_bytes": 1}, "swap disabled"),
            (events, {"oom_kill": 1}, "recorded OOM kill"),
            (progress, {"published_rows": seed - 64}, "incomplete acknowledged seed"),
            (restart, {"teardown_sigkill_sent": False}, "SIGKILL lacks verifier attribution"),
            (restart, {"exited_before_cleanup": True}, "exited before verifier teardown"),
        ):
            with self.subTest(reason=reason), patch.dict(target, changes):
                with self.assertRaisesRegex(verify.Rejected, reason):
                    validate_capacity_observations(run, seed, "fixture", set())

    def test_backfill_timeline_requires_handoff_and_drain_evidence(self):
        def timeline(pattern, held, cutoff, final, rows, generation):
            opening = dict(state="running", generation=generation - 1, covered_rows=held, committed_rows=cutoff)
            overlap = dict(opening, committed_rows=cutoff + 64)
            complete = dict(state="complete", generation=generation, covered_rows=cutoff, committed_rows=final)
            samples = [dict(event=event, status=status, filesystem=dict(checkpoint_staging_apparent_bytes=0))
                       for event, status in (("held_capture", None), ("compaction_start", opening),
                                             ("overlap", overlap), ("publication", complete),
                                             ("held_exhausted", None), ("after_exhaustion", complete),
                                             ("fresh_visible", None))]
            samples[3]["candidate_status_metrics"] = {"retired_generation_pins": 1}
            samples[5]["candidate_status_metrics"] = {"retired_generation_pins": 0}
            return dict(pattern=pattern, status="pass", held_cutoff=held, requested_cutoff=cutoff,
                        expected_committed_rows=final, held_rows_checked=rows, held_cursor_exhausted=True,
                        fresh_backfill_visible=True, acknowledged_backfill=dict(
                            rows=final - held, batches=(final - held) // 64, first_ack_ns=1, last_ack_ns=3),
                        publication=dict(generation=generation, observed_lag_lower_bound_ns=2,
                                         observed_lag_upper_bound_ns=4), samples=samples,
                        pin_drain=dict(status="observed", retired_pins_while_held=1,
                                       retired_pins_after_exhaustion=0, release_http_status=204, reclaimed_bytes=4096))

        seed = 196_608
        clustered = timeline("clustered", seed - 128, seed - 64, seed, 9, 25)
        scattered = timeline("scattered", seed, seed + 64, seed + 2048, 9 * seed // 16 - 3, 27)
        published = {"generation": 27}
        validate_backfill_timelines([scattered, clustered], seed, published)
        validate_backfill_timelines([clustered, scattered], seed, published, require_pin_retirement=True)
        drain_samples = scattered["samples"]
        drain_samples.insert(5, dict(drain_samples[5], candidate_status_metrics=None))
        drain_samples[6]["event"] = "drain_poll"
        validate_backfill_timelines([clustered, scattered], seed, published, require_pin_retirement=True)
        drain_samples.pop(5)
        drain_samples[5]["event"] = "after_exhaustion"
        for changes, diagnostic in (
            ({"status": "unavailable", "reason": "old producer"}, "incomplete pin-drain evidence"),
            ({"status": "pending", "reason": "observation window ended"}, "pin retirement pending"),
            ({"release_http_status": 404}, "missing release or reclamation evidence"),
            ({"reclaimed_bytes": 0}, "missing release or reclamation evidence"),
        ):
            with self.subTest(changes=changes), patch.dict(scattered["pin_drain"], changes):
                with self.assertRaisesRegex(verify.Rejected, diagnostic):
                    validate_backfill_timelines([clustered, scattered], seed, published, require_pin_retirement=True)
        with patch.dict(scattered["samples"][5]["candidate_status_metrics"], retired_generation_pins=1):
            with self.assertRaisesRegex(verify.Rejected, "missing measured positive-to-zero predecessor pins"):
                validate_backfill_timelines([clustered, scattered], seed, published, require_pin_retirement=True)
        with patch.dict(clustered["samples"][3]["status"], covered_rows=seed):
            with self.assertRaisesRegex(verify.Rejected, "invalid overlap or publication cutoff"):
                validate_backfill_timelines([clustered, scattered], seed, published)
        with patch.dict(scattered["pin_drain"], retired_pins_after_exhaustion=1):
            with self.assertRaisesRegex(verify.Rejected, "incomplete pin-drain evidence"):
                validate_backfill_timelines([clustered, scattered], seed, published)

    def test_native_release_requires_fixed_boundaries_and_snapshot_walks(self):
        def walk(budget, rows):
            return dict(first_cursor_budget=budget, exact_threshold_budget=budget, rejected_budgets=1,
                        pages=3, rows=rows, probes=[
                            dict(budget=budget - 1, outcome="clean_rejection", pages=0, rows=0),
                            dict(budget=budget, outcome="exhausted", pages=3, rows=rows,
                                 post_issuance_append_rows=2, resume_limit=1)])

        tied = walk(11, 3)
        tied["sparse_walk"] = dict(walk(314, 4), response_byte_cap=96, first_limit=4, first_rows=2, resume_limit=1)
        tied["duplicate_walk"] = dict(tied["probes"][1])
        report = dict(http_status=503, ndjson_rows=0, next_cursor=False, elapsed_ms=1, fixed_budget_walk=tied)
        validate_budget(report, require_fixed_boundaries=True)

        for target, changes, reason in (
            (tied["sparse_walk"], walk(315, 4), "expected sparse boundary at budget 314"),
            (tied["probes"][1], {"post_issuance_append_rows": 0}, "missing tied post-issuance appends"),
            (tied["duplicate_walk"], {"outcome": "issued_cursor"}, "incomplete duplicate-row walk"),
        ):
            with self.subTest(reason=reason), patch.dict(target, changes):
                with self.assertRaisesRegex(verify.Rejected, reason):
                    validate_budget(report, require_fixed_boundaries=True)

    def test_fixed_budget_trials_require_each_issued_cursor_to_exhaust(self):
        trials = [dict(budget=3, outcome="exhausted", pages=3, rows=4),
                  dict(budget=1, outcome="clean_rejection", pages=0, rows=0),
                  dict(budget=2, outcome="exhausted", pages=3, rows=4)]
        report = {"exact_threshold_budget": 2, "rejected_budgets": 1, "probes": trials}
        validate_budget_trials(report, "sparse", 4, 2)
        trials[0].update(outcome="issued_cursor", pages=1, rows=2)
        with self.assertRaisesRegex(verify.Rejected, "incomplete sparse walk at budget 3"):
            validate_budget_trials(report, "sparse", 4, 2)

    def test_release_cleanup_is_additive_but_required_for_a_new_run(self):
        healthy = {"readiness_status": 200, "readiness_reason": "ready", "ingest_status": 204,
                   "replayed_after_restart": True}
        full = {"readiness_status": 503, "readiness_reason": "low_disk_headroom", "ingest_status": 503,
                "post_ingest_reason": "wal_rollback", "post_ingest_category": "enospc"}
        identity = {"schema_version": 1, "revision": "a" * 40, "binary_sha256": "b" * 64,
                    "fixture": "linux-release-v1"}
        cases = {name: {"status": "pass", "evidence": {"stale_cursors_rejected": 1}}
                 for name in ("sigkill", "recovery", "enospc")}
        cases["enospc"]["evidence"].update(healthy_to_full=healthy, full_to_healthy=full)
        with tempfile.TemporaryDirectory() as work:
            directory = Path(work)
            report = directory / "durability.json"
            parent = directory / "fixtures"
            report.write_text(json.dumps({**identity, "cases": cases}))
            validate_durability(directory, identity)
            with self.assertRaisesRegex(verify.Rejected, "missing required case fixture_root_cleanup"):
                validate_durability(directory, identity, require_fixture_root_cleanup=True)

            parent.mkdir()
            record_fixture_root_cleanup(directory, identity, parent)
            self.assertFalse(parent.exists())
            validate_durability(directory, identity, require_fixture_root_cleanup=True)

            parent.mkdir()
            (parent / "leaked-root").mkdir()
            with self.assertRaisesRegex(verify.Rejected, "fixture_root_cleanup did not pass"):
                record_fixture_root_cleanup(directory, identity, parent)
            self.assertEqual(json.loads(report.read_text())["cases"][FIXTURE_ROOT_CLEANUP]["status"], "fail")
            with self.assertRaisesRegex(verify.Rejected, "fixture_root_cleanup did not pass"):
                validate_durability(directory, identity)

    def test_missing_bounded_filesystem_blocks_both_enospc_suites(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = str(Path(directory) / "missing-mount")
            with patch.dict(os.environ, {"SLIPWAY_PARAM_ENOSPC_MOUNT": missing}), \
                 patch.object(verify.sys, "platform", "linux"), patch.object(os, "geteuid", return_value=65532):
                for suite in (verify.enospc_suite, verify.full_disk_restart_suite):
                    with self.subTest(suite=suite.__name__):
                        with self.assertRaisesRegex(verify.InfrastructureError, "private 1–128 MiB mount"):
                            suite(None, None)

    def test_apache_fixture_preserves_raw_lines_and_rejects_a_digest_mismatch(self):
        rows = verify.load_apache()
        self.assertEqual([row.line.encode() for row in rows], verify.APACHE_PATH.read_bytes().split(b"\n")[:-1])
        self.assertGreater(len({row.ns for row in rows}), 1)
        self.assertLess(len({row.ns for row in rows}), len(rows))
        with patch.object(verify, "APACHE_SHA256", "0" * 64):
            with self.assertRaisesRegex(verify.InfrastructureError, "Apache fixture digest mismatch"):
                verify.load_apache()

    def test_ndjson_splits_only_on_lf_bytes(self):
        expected = [verify.Row(-1, "first\n\r\t\u0085\u2028\u2029still first"), verify.Row(1, "second")]
        wire = verify.encode_rows(expected)
        self.assertEqual(wire.count(b"\n"), 2)
        self.assertEqual(verify.decode_rows(wire), expected)
        with self.assertRaisesRegex(verify.Rejected, "duplicate JSON field"):
            verify.decode_rows(wire.replace(b'"line": "second"', b'"line": "a", "line": "second"'))

    def test_readme_only_revision_fails_bootstrap_and_full_entrypoints(self):
        cases = [((), {}, "pr"), (("--full",), {}, "full"), (("--compare",), {}, "full"),
                 ((), {"SLIPWAY_PARAM_MODE": "compare"}, "full"),
                 ((), {"SLIPWAY_PARAM_MODE": "post-cycle"}, "post-cycle")]
        for args, params, profile in cases:
            with self.subTest(args=args):
                result = entrypoint(*args, **readme_candidate(README_ONLY), **params)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn(f"candidate_sha={README_ONLY}", result.stdout)
                self.assertIn("rejected in build (suites=0): missing ./cmd/bog", result.stderr)
                self.assertNotIn("verified_sha=", result.stdout)
                report = json.loads(next(line.removeprefix("BOG_RESULT ") for line in result.stdout.splitlines()
                                         if line.startswith("BOG_RESULT ")))
                self.assertEqual(report["tested_sha"], README_ONLY)
                self.assertEqual(report["exit_code"], 1)
                self.assertEqual(report["profile"], profile)
                if profile != "pr":
                    self.assertEqual(report["baseline_sha"], verify.COMPARISON_BASELINE_SHA)
                    self.assertEqual(report["baseline_build"]["status"], "blocked")
                self.assertEqual(report["cycle7_baseline_build"],
                                 {"sha": verify.CYCLE7_BASELINE_SHA, "status": "blocked"})
                self.assertIn("snapshot-pagination", {suite["name"] for suite in report["suites"]})
                self.assertTrue(all(suite["status"] == "blocked" for suite in report["suites"]))

    def test_post_land_mode_wires_parameter_inputs_to_the_pr_profile(self):
        # bog-conductor's post-land QA probe is a parameter-only verify step: no repository
        # lease, mode=post-land, the landed commit as a param and/or the QA step's testedCommit.
        # Before this mode existed every probe failed with "missing Bog candidate inputs".
        bundle = str(ROOT / "tests/fixtures/readme-only.bundle")
        cases = [
            {"SLIPWAY_PARAM_COMMIT": README_ONLY},
            {"SLIPWAY_INPUT_TESTEDCOMMIT": README_ONLY},
            {"SLIPWAY_PARAM_COMMIT": README_ONLY, "SLIPWAY_INPUT_TESTEDCOMMIT": "0" * 40},
        ]
        for inputs in cases:
            with self.subTest(inputs=sorted(inputs)):
                result = entrypoint(SLIPWAY_PARAM_MODE="post-land", SLIPWAY_PARAM_REPOSITORY=bundle, **inputs)
                self.assertNotIn("missing Bog candidate inputs", result.stderr)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn(f"candidate_sha={README_ONLY} profile=pr", result.stdout)
                self.assertIn("rejected in build (suites=0): missing ./cmd/bog", result.stderr)

    def test_build_timeout_is_an_infrastructure_error_not_a_rejection(self):
        with tempfile.TemporaryDirectory() as directory:
            source, work = buildable_candidate(Path(directory))
            timeout = subprocess.TimeoutExpired(["go", "build"], verify.BUILD_TIMEOUT_SECONDS)
            with patch.object(verify.subprocess, "run", side_effect=timeout):
                with self.assertRaisesRegex(verify.InfrastructureError, "timed out after"):
                    verify.build(source, work, work / "build.log")

    def test_default_gate_and_comparisons_have_distinct_suite_plans(self):
        def plan(profile):
            result = verify.new_result("0" * 40, None, profile)
            return result["baseline_sha"], [suite["name"] for suite in result["suites"]]

        baseline, default = plan("pr")
        self.assertEqual(baseline, verify.CYCLE7_BASELINE_SHA)
        core = list(verify.REQUIRED_SUITES)
        cycle7 = ["cycle7-wal-handoff", "log-replay-paired-smoke"]
        self.assertEqual(default, core + cycle7)
        extended = ["graceful-shutdown", "full-disk-restart", "wal-handoff"]
        self.assertEqual(plan("full"), (verify.COMPARISON_BASELINE_SHA,
                                       core + extended + ["small-batch-performance"] + cycle7))
        self.assertIn("log-replay", default)
        full_baseline, full_suites = plan("full")
        self.assertEqual(plan("post-cycle"), (full_baseline, full_suites + ["log-replay-performance"]))
        self.assertEqual(plan("indexed"), (verify.BASELINE_SHA, core + extended + ["indexed-performance"]))
        self.assertEqual(plan("legacy"), (verify.BASELINE_SHA,
                                          [name for name in core
                                           if name not in ("snapshot-pagination", "log-replay")]))

    def test_query_admission_and_work_budget_gate_independently(self):
        budget = "  -query-work-budget int"
        concurrency = "  -query-concurrency int"
        helper_only = "73bf45334ec7067f9ed8fcd06c8ccdef8dca72ef"
        unrelated = "0" * 40
        missing = "Bog -help does not list -query-concurrency"
        for options, help_status, sha, required, limits, admission, diagnostic in (
            ("  -addr string", 0, unrelated, "", "skipped", "skipped", missing),
            (f"{budget}\n  -query-concurrency-extra int", 0, unrelated, "", "run", "skipped", missing),
            (concurrency, 0, unrelated, "1", "rejected", "run", None),
            (f"{budget}\n{concurrency}", 0, unrelated, "", "run", "run", None),
            ("  -addr string", 0, helper_only, "", "skipped", "skipped", missing),
            ("  -addr string", 0, verify.CYCLE7_BASELINE_SHA, "", "skipped", "skipped", missing),
            ("  -addr string", 0, helper_only, "1", "rejected", "rejected", "required for #19 verification"),
            (budget, 0, unrelated, "1", "run", "rejected", "required for #19 verification"),
            ("  -addr string", 2, unrelated, "", "rejected", "rejected", "Bog -help exited with status 2"),
        ):
            with self.subTest(options=options, sha=sha, required=required, help_status=help_status), \
                 tempfile.TemporaryDirectory() as directory:
                work = Path(directory)
                binary = work / "bog"
                binary.write_text(f"#!/bin/sh\n[ \"$1\" = -help ] || exit 3\n"
                                  f"cat >&2 <<'HELP'\nUsage of bog:\n{options}\nHELP\nexit {help_status}\n")
                binary.chmod(0o755)

                def following_suite(*_):
                    verify.PROCESS_LOGS.get()[1].append({"ready_ms": 1})

                suites = (("query-limits", verify.query_limits_suite),
                          ("query-admission", verify.query_admission_suite),
                          ("kill-durability", following_suite), ("wal-recovery", following_suite))
                with patch.dict(os.environ, {"SLIPWAY_PARAM_REQUIRE_QUERY_ADMISSION": required}), \
                     patch.object(verify, "SUITES", suites), \
                     patch.object(verify, "REQUIRED_SUITES", tuple(name for name, _ in suites)), \
                     patch.object(verify, "CYCLE7_PROFILES", ()), \
                     patch.object(verify, "build", return_value=binary), \
                     patch.object(verify, "run_bog", side_effect=verify.Rejected("query assertions reached")) as run:
                    rejected = limits in ("run", "rejected") or admission in ("run", "rejected")
                    self.assertEqual(verify.main(work, work, sha), int(rejected))
                report = json.loads((work / "artifacts/result.json").read_text())
                outcomes = {suite["name"]: suite for suite in report["suites"]}
                self.assertEqual(outcomes["query-limits"]["status"], "rejected" if limits == "run" else limits)
                if limits == "skipped":
                    self.assertEqual(outcomes["query-limits"]["coverage"], "unavailable")
                if limits == "rejected" and required:
                    self.assertIn("-query-work-budget", outcomes["query-limits"]["diagnostic"])
                admission_result = outcomes["query-admission"]
                self.assertEqual(admission_result["status"], "rejected" if admission == "run" else admission)
                if admission == "skipped":
                    self.assertEqual(admission_result["coverage"], "unavailable")
                self.assertIn("query assertions reached" if admission == "run" else diagnostic,
                              admission_result["diagnostic"])
                self.assertEqual(outcomes["kill-durability"]["status"], "passed")
                self.assertEqual(outcomes["wal-recovery"]["status"], "passed")
                self.assertEqual((work / "passed").exists(), not rejected)
                expected_flags = []
                if limits == "run":
                    expected_flags.append(("-query-work-budget=32",))
                if admission == "run":
                    expected_flags.append(("-query-concurrency=1",))
                self.assertEqual([call.kwargs["flags"] for call in run.call_args_list], expected_flags)

    def test_release_gate_requires_complete_query_admission_evidence(self):
        sha = "a" * 40
        for defect in (None, "skipped", "missing", "wrong_status", "rows", "cursor"):
            with self.subTest(defect=defect), tempfile.TemporaryDirectory() as directory:
                work = Path(directory)
                binary = work / "bog"
                binary.touch()

                def run(*_):
                    verify.PROCESS_LOGS.get()[1].append({"ready_ms": 1})

                def report(flag, value):
                    return {
                        "flag": flag, "flag_value": value,
                        "rejections": {probe: {"status": 503, "ndjson_rows": 0, "next_cursor": False}
                                       for probe in ("ordinary", "first_page", "continuation")},
                    }

                def budget(*args):
                    run(*args)
                    return report("-query-work-budget", 32)

                def admission(*args):
                    run(*args)
                    if defect == "skipped":
                        return verify.SuiteSkipped("probe did not run")
                    if defect == "missing":
                        return None
                    result = report("-query-concurrency", 1)
                    result.update(ingest_during_saturation="passed", snapshot_after_disconnect="passed",
                                  backfill_after_restart="passed")
                    mutation = {"wrong_status": ("status", 422), "rows": ("ndjson_rows", 1),
                                "cursor": ("next_cursor", True)}.get(defect)
                    if mutation:
                        key, value = mutation
                        result["rejections"]["continuation"][key] = value
                    return result

                suites = (("query-limits", budget), ("query-admission", admission), ("wal-recovery", run))
                path = work / "artifacts/result.json"
                with patch.dict(os.environ, {"SLIPWAY_PARAM_REQUIRE_QUERY_ADMISSION": "1"}), \
                     patch.object(verify, "SUITES", suites), \
                     patch.object(verify, "REQUIRED_SUITES", tuple(name for name, _ in suites)), \
                     patch.object(verify, "CYCLE7_PROFILES", ()), \
                     patch.object(verify, "build", return_value=binary):
                    self.assertEqual(verify.main(work, work, sha), int(defect is not None))
                    result = json.loads(path.read_text())
                    self.assertEqual(result["suites"][-1]["status"], "passed")
                    if defect:
                        self.assertFalse((work / "passed").exists())
                    else:
                        verify.publish_result(work, 0, "", sha, sha)
                        with self.assertRaisesRegex(verify.InfrastructureError, "tested revision"):
                            verify.publish_result(work, 0, "", sha, "b" * 40)
                        completion = work / "passed"
                        original = completion.read_text()
                        completion.write_text(f"{sha} {'0' * 64} 3\n")
                        with self.assertRaisesRegex(verify.InfrastructureError, "completion record"):
                            verify.publish_result(work, 0, "", sha, sha)
                        completion.write_text(original)
                        result["suites"].pop(1)
                        path.write_text(json.dumps(result))
                        with self.assertRaisesRegex(verify.Rejected, "passing query-admission report"):
                            verify.publish_result(work, 0, "", sha, sha)
                        path.unlink()
                        with self.assertRaisesRegex(verify.InfrastructureError, "passing suite result is missing"):
                            verify.publish_result(work, 0, "", sha, sha)

    def test_response_byte_suite_requires_the_capability_for_issue_seven(self):
        for flags, required, diagnostic in (
            ({"-query-max-response-bytes-extra"}, "", None),
            (set(), "1", "Bog -help does not list -query-max-response-bytes"),
            ({"-query-max-response-bytes"}, "", "response byte assertions reached"),
            ({"-query-max-response-bytes"}, "1", "response byte assertions reached"),
        ):
            with self.subTest(flags=flags, required=required), tempfile.TemporaryDirectory() as directory:
                work = Path(directory)
                binary = work / "bog"
                binary.touch()

                def following(*_):
                    verify.PROCESS_LOGS.get()[1].append({"ready_ms": 1})

                suites = (("query-response-bytes", verify.query_response_bytes_suite), ("following", following))
                with patch.dict(os.environ, {"SLIPWAY_PARAM_REQUIRE_QUERY_RESPONSE_BYTES": required}), \
                     patch.object(verify, "SUITES", suites), \
                     patch.object(verify, "REQUIRED_SUITES", tuple(name for name, _ in suites)), \
                     patch.object(verify, "CYCLE7_PROFILES", ()), \
                     patch.object(verify, "build", return_value=binary), \
                     patch.object(verify, "advertised_flags", return_value=flags), \
                     patch.object(verify, "run_bog", side_effect=verify.Rejected("response byte assertions reached")):
                    self.assertEqual(verify.main(work, work, "0" * 40), int(diagnostic is not None))
                response_bytes, other = json.loads((work / "artifacts/result.json").read_text())["suites"]
                self.assertEqual(other["status"], "passed")
                self.assertEqual(response_bytes["status"], "rejected" if diagnostic else "skipped")
                if diagnostic:
                    self.assertIn(diagnostic, (work / "rejection").read_text())
                self.assertEqual((work / "passed").exists(), diagnostic is None)

    def test_timing_sample_cap_preserves_quantiles_from_all_requests(self):
        times = [0.001] * 97 + [0.010] * 2 + [0.100]
        metrics = verify.latency_metrics(times, sample_limit=4)
        self.assertEqual(metrics["sample_count"], 100)
        self.assertEqual(metrics["samples_ms"], [1.0, 1.0, 1.0, 100.0])
        self.assertEqual(metrics["p99_ms"], 10.0)

    def test_legacy_mode_cannot_bypass_pagination_for_an_unpinned_revision(self):
        for args, params in [(("--legacy",), {}), ((), {"SLIPWAY_PARAM_MODE": "legacy"})]:
            with self.subTest(args=args, params=params):
                result = entrypoint(*args, **readme_candidate(README_ONLY), **params)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn(f"legacy mode requires pinned Cycle 1 SHA {verify.BASELINE_SHA}", result.stderr)

    def test_cursor_walk_changes_limits_and_requires_exact_termination(self):
        args = verify.query_args(0, 3)
        rows = [verify.Row(i, f"Log/{i}") for i in range(3)]
        requests = []
        responses = iter([(rows[:1], "opaque"), (rows[1:], None)])

        class Service:
            def query_page(self, params):
                requests.append(params)
                return next(responses)

        verify.expect_walk(Service(), args, rows, (1, 2), "changed page size")
        self.assertEqual(requests, [{**args, "page": "1", "limit": 1},
                                    {**args, "cursor": "opaque", "limit": 2}])
        for response, expected in [((rows[:1], None), rows), ((rows[:1], "extra"), rows[:1])]:
            with self.subTest(response=response):
                responses = iter([response])
                with self.assertRaisesRegex(verify.Rejected, "present exactly when rows remain"):
                    verify.expect_walk(Service(), args, expected, (1,), "termination")

    def test_indexed_targets_apply_to_paired_median_and_require_all_pairs(self):
        count = len(verify.BENCH_SEEDS) * verify.BENCH_REPEATS
        pair = {"wide_query_p95/live": 0.5, "wide_query_p95/restart": 0.51,
                "narrow_query_p95/live": 1.25, "durable_rows_per_second": 0.79,
                "restart_ready_ms": 1.25, "peak_rss_kib": 1.26, "rare_or_absent_query_p95/live": 1.5}
        targets = verify.indexed_targets([pair] * (count - 1) + [{**pair, "wide_query_p95/live": 9}])
        self.assertEqual({key for key, result in targets.items() if not result["passed"]},
                         {"wide_query_p95/restart", "durable_rows_per_second", "peak_rss_kib"})
        with self.assertRaisesRegex(verify.InfrastructureError, "every configured benchmark pair"):
            verify.indexed_targets([pair] * (count - 1))

    def test_log_replay_gates_each_metric_on_paired_medians(self):
        count = len(verify.LOG_REPLAY_SEEDS) * verify.CONTROLLED_REPLAY_REPEATS
        pair = {f"{name}/{phase}": 1.15 for name in verify.LOG_QUERY_METRICS for phase in ("live", "restart")}
        pair.update({"rare_query_p95/live": 1.16, "absent_page_p95/restart": 1.16, "post_p99": 1.15,
                     "durable_rows_per_second": 0.89, "ingest_peak_rss_kib": 1.05, "replay_peak_rss_kib": 1.06,
                     "restart_ready_ms": 1.05, "fixed_dense_query_p95/restart": 1.15})
        outlier = {**pair, "dense_query_p95/live": 20, "rare_query_p95/live": 0.01}
        targets = verify.log_replay_targets([pair] * (count - 1) + [outlier], "steady", verify.CYCLE7_BASELINE_SHA)
        self.assertEqual({key for key, target in targets.items() if not target["passed"]},
                         {"rare_query_p95/live", "absent_page_p95/restart",
                          "durable_rows_per_second", "restart_ready_ms", "replay_peak_rss_kib"})
        shuffled = {key: value for key, value in pair.items() if key != "fixed_dense_query_p95/restart"}
        targets = verify.log_replay_targets([shuffled] * count, "shuffled", verify.CYCLE7_BASELINE_SHA)
        self.assertTrue(targets["restart_ready_ms"]["passed"])
        pre_bloom = verify.log_replay_targets([pair] * count, "steady", verify.COMPARISON_BASELINE_SHA)
        self.assertEqual(pre_bloom["absent_page_p95/restart"]["target"], 0.25)
        self.assertEqual(pre_bloom["dense_query_p95/restart"]["target"], 1.15)
        with self.assertRaisesRegex(verify.InfrastructureError, "every configured pair and measurement"):
            verify.log_replay_targets([pair] * (count - 1), "steady", verify.CYCLE7_BASELINE_SHA)
        missing = {key: value for key, value in pair.items() if key != "rare_query_p95/live"}
        with self.assertRaisesRegex(verify.InfrastructureError, "every configured pair and measurement"):
            verify.log_replay_targets([pair] * (count - 1) + [missing], "steady", verify.CYCLE7_BASELINE_SHA)

    def test_log_replay_exercises_dense_and_sparse_ranges_and_block_edges(self):
        sources = verify.log_replay_sources()
        self.assertEqual([line.encode() for line in sources[-1]], verify.SYSLOG_PATH.read_bytes().splitlines())
        for order in verify.LOG_REPLAY_ORDERS:
            with self.subTest(order=order):
                replay = verify.LogReplay(sources, verify.LOG_REPLAY_SEEDS[0], order)
                cases = {name: rows for name, _, rows in replay.queries(replay.rows)}
                self.assertEqual(len(cases["dense"]) - len(cases["sparse-after-prefix"]),
                                 verify.LOG_DENSE_PREFIX_ROWS)
                self.assertTrue(0 < len(cases["sparse-after-prefix"]) < 10)
                for case in ("escaped-text", "unicode", "decomposed-unicode", "large-line", "final-partial-block"):
                    self.assertEqual(len(cases[case]), 1)
                self.assertFalse(cases["split-grams"])
                self.assertFalse(cases["absent"])
                self.assertEqual(len(cases["ties-across-posts"]), 4)
                self.assertEqual(replay.rows[-1], cases["final-partial-block"][0])
                self.assertGreater(len(cases["large-line"][0].line.encode()), verify.LOG_BLOCK_TEXT_BUDGET)
                self.assertEqual((len(replay.rows) + len(replay.backfill)) % verify.LOG_BLOCK_ROWS, 0)

    def test_historical_wal_fixture_uses_castagnoli_crc_and_little_endian_marker(self):
        self.assertEqual(verify.crc32c(b"123456789"), 0xe3069283)
        self.assertEqual(verify.commit_marker(8), b"BOGCMT01\x08" + b"\x00" * 7 + b"\xf7" + b"\xff" * 7)

    def test_fetched_tip_must_match_full_candidate_sha(self):
        result = entrypoint(**readme_candidate("0" * 40))
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(f"revision mismatch: fetched {README_ONLY}", result.stderr)
        self.assertNotIn("candidate_sha=", result.stdout)

    def test_comparison_with_missing_candidate_ref_reports_both_shas(self):
        inputs = {**readme_candidate(README_ONLY), "SLIPWAY_CANDIDATE_BRANCH": "missing"}
        result = entrypoint("--compare", **inputs)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(f"Bog revision {README_ONLY} is unavailable", result.stderr)
        report = json.loads(next(line.removeprefix("BOG_RESULT ") for line in result.stdout.splitlines()
                                 if line.startswith("BOG_RESULT ")))
        self.assertEqual(report["requested_sha"], README_ONLY)
        self.assertIsNone(report["tested_sha"])
        self.assertEqual(report["baseline_sha"], verify.COMPARISON_BASELINE_SHA)

    def test_comparison_baseline_requires_a_present_buildable_revision(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            source = work / "source"
            bundle = readme_candidate(README_ONLY)["SLIPWAY_REPOSITORY"]
            subprocess.run(["git", "clone", "-q", "-b", "main", bundle, str(source)], check=True)
            with self.assertRaisesRegex(verify.InfrastructureError, f"{verify.COMPARISON_BASELINE_SHA} is missing"):
                verify.build_baseline(source, work, work, verify.COMPARISON_BASELINE_SHA)
            with self.assertRaisesRegex(verify.InfrastructureError, f"{README_ONLY} build failed: missing ./cmd/bog"):
                verify.build_baseline(source, work, work, README_ONLY)

    def test_missing_candidate_inputs_fail(self):
        result = entrypoint()
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("missing Bog candidate inputs", result.stderr)

    def test_executable_with_zero_registered_suites_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            source, work = buildable_candidate(Path(directory))
            with patch.object(verify, "SUITES", ()):
                self.assertEqual(verify.main(source, work, "0" * 40), 1)
            self.assertTrue(os.access(work / "bog", os.X_OK))
            self.assertIn("zero verification suites", (work / "rejection").read_text())
            self.assertFalse((work / "passed").exists())

    def test_buildable_executable_that_never_starts_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, work = buildable_candidate(root)
            with patch.object(verify, "bounded_mount", return_value=(root, 64 * 1024**2)), \
                 patch.object(verify.sys, "platform", "linux"), \
                 patch.object(verify, "build_baseline", return_value=work / "bog"):
                self.assertEqual(verify.main(source, work, "0" * 40), 1)
            self.assertIn("Bog exited during startup (status 0)", (work / "rejection").read_text())
            self.assertFalse((work / "passed").exists())

    def test_successful_build_without_an_executable_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            source, work = buildable_candidate(Path(directory))
            with patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 0)):
                self.assertEqual(verify.main(source, work, "0" * 40), 1)
            self.assertIn("did not produce an executable Bog binary", (work / "rejection").read_text())

    def test_registered_noop_cannot_pass_a_required_suite(self):
        with tempfile.TemporaryDirectory() as directory:
            source, work = buildable_candidate(Path(directory))
            suites = tuple((name, lambda *_, **__: None) for name in verify.REQUIRED_SUITES)
            with patch.object(verify, "SUITES", suites), \
                 patch.object(verify, "build_baseline", return_value=work / "bog"):
                self.assertEqual(verify.main(source, work, "0" * 40), 2)
            report = json.loads((work / "artifacts/result.json").read_text())
            self.assertEqual(report["suites"][0]["diagnostic"], "required suite ran without a ready Bog subprocess")
            self.assertFalse((work / "passed").exists())


if __name__ == "__main__":
    unittest.main()
