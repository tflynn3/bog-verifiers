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
        for args in ((), ("--full",)):
            with self.subTest(args=args):
                result = entrypoint(*args, **readme_candidate(README_ONLY))
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn(f"candidate_sha={README_ONLY}", result.stdout)
                self.assertIn("rejected in build (suites=0): missing ./cmd/bog", result.stderr)
                self.assertNotIn("verified_sha=", result.stdout)
                report = json.loads(next(line.removeprefix("BOG_RESULT ") for line in result.stdout.splitlines()
                                         if line.startswith("BOG_RESULT ")))
                self.assertEqual(report["tested_sha"], README_ONLY)
                self.assertEqual(report["exit_code"], 1)
                self.assertTrue(all(suite["status"] == "blocked" for suite in report["suites"]))

    def test_fetched_tip_must_match_full_candidate_sha(self):
        result = entrypoint(**readme_candidate("0" * 40))
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(f"revision mismatch: fetched {README_ONLY}", result.stderr)
        self.assertNotIn("candidate_sha=", result.stdout)

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
            with patch.object(verify, "bounded_mount", return_value=(root, 64 * 1024**2)):
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
            suites = tuple((name, lambda *_: None) for name in verify.REQUIRED_SUITES)
            with patch.object(verify, "SUITES", suites):
                self.assertEqual(verify.main(source, work, "0" * 40), 2)
            report = json.loads((work / "artifacts/result.json").read_text())
            self.assertEqual(report["suites"][0]["diagnostic"], "required suite ran without a ready Bog subprocess")
            self.assertFalse((work / "passed").exists())


if __name__ == "__main__":
    unittest.main()
