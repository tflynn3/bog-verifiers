"""Regressions for the Slipway entrypoint and required-suite runner."""
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


class GateTest(unittest.TestCase):
    def test_readme_only_revision_fails_bootstrap_and_full_entrypoints(self):
        for args in ((), ("--full",)):
            with self.subTest(args=args):
                result = entrypoint(*args, **readme_candidate(README_ONLY))
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn(f"candidate_sha={README_ONLY}", result.stdout)
                self.assertIn("rejected in build (suites=0): missing ./cmd/bog", result.stderr)
                self.assertNotIn("verified_sha=", result.stdout)

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
            root = Path(directory)
            source, work = root / "source", root / "work"
            (source / "cmd/bog").mkdir(parents=True)
            work.mkdir()
            (source / "go.mod").write_text("module gate.invalid/regression\n\ngo 1.20\n")
            (source / "cmd/bog/main.go").write_text("package main\nfunc main() {}\n")
            with patch.object(verify, "SUITES", ()):
                self.assertEqual(verify.main(source, work, "0" * 40), 1)
            self.assertTrue(os.access(work / "bog", os.X_OK))
            self.assertIn("zero verification suites", (work / "rejection").read_text())
            self.assertFalse((work / "passed").exists())


if __name__ == "__main__":
    unittest.main()
