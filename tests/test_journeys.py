"""Regressions for the release acceptance journeys profile."""
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import journeys
import verify


def script(body):
    return "import sys\n" + body + "\n"


class JourneysTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name) / "journeys"
        (self.dir / "0.1").mkdir(parents=True)
        files = {
            "pass.py": script("print('passed'); sys.exit(0)"),
            "fail.py": script("print('expected 204; observed 500'); sys.exit(1)"),
            "broken.py": script("print('harness error: boom'); sys.exit(2)"),
            "slow.py": script("import time; time.sleep(5)"),
        }
        for name, body in files.items():
            (self.dir / "0.1" / name).write_text(body)
        self.registry = {
            "bog/0.1/O1/J1": "0.1/pass.py",
            "bog/0.1/O1/J2": "0.1/fail.py",
            "bog/0.1/O2/J1": "0.1/broken.py",
            "bog/0.1/O2/J2": "0.1/slow.py",
            "bog/0.1/O3/J1": "../escape.py",
        }
        (self.dir / "index.json").write_text(json.dumps(self.registry))
        self.binary = Path(self.tmp.name) / "bog"
        self.binary.write_text("")

    def tearDown(self):
        self.tmp.cleanup()

    def run_ids(self, ids, timeout=3):
        return journeys.run_journeys(ids, self.registry, self.binary, timeout=timeout, directory=self.dir)

    def test_requested_journeys_parses_and_rejects_malformed_ids(self):
        ids, bad = journeys.requested_journeys(" bog/0.1/O1/J1, bog/0.1/O1/J1,,bog/O1/J1 ")
        self.assertEqual(ids, ["bog/0.1/O1/J1", "bog/O1/J1"])
        self.assertEqual(bad, ["bog/O1/J1"])

    def test_pass_fail_and_harness_errors_are_distinguished(self):
        results = {r["name"]: r for r in self.run_ids(
            ["bog/0.1/O1/J1", "bog/0.1/O1/J2", "bog/0.1/O2/J1", "bog/0.1/O2/J2", "bog/0.1/O3/J1", "bog/0.1/O9/J1"],
            timeout=2)}
        self.assertEqual(results["bog/0.1/O1/J1"]["status"], "passed")
        self.assertEqual(results["bog/0.1/O1/J2"]["status"], "rejected")
        self.assertEqual(results["bog/0.1/O1/J2"]["diagnostic"], "expected 204; observed 500")
        self.assertEqual(results["bog/0.1/O2/J1"]["status"], "infra_error")
        self.assertIn("timed out", results["bog/0.1/O2/J2"]["diagnostic"])
        self.assertIn("missing", results["bog/0.1/O3/J1"]["diagnostic"])
        self.assertIn("not implemented", results["bog/0.1/O9/J1"]["diagnostic"])

    def test_summarize_prefers_product_failures_over_harness_errors(self):
        code, reason = journeys.summarize(self.run_ids(["bog/0.1/O1/J2", "bog/0.1/O2/J1"]))
        self.assertEqual(code, 1)
        self.assertIn("bog/0.1/O1/J2: expected 204; observed 500", reason)
        self.assertIn("1 journey(s) could not run", reason)
        self.assertEqual(journeys.summarize(self.run_ids(["bog/0.1/O2/J1"]))[0], 2)
        self.assertEqual(journeys.summarize(self.run_ids(["bog/0.1/O1/J1"])), (0, ""))
        self.assertEqual(journeys.summarize([])[0], 2)

    def test_main_writes_passed_record_and_rejection(self):
        fake = types.SimpleNamespace(
            new_result=verify.new_result, build=lambda source, work, log: self.binary,
            Rejected=verify.Rejected, InfrastructureError=verify.InfrastructureError,
            diagnostic=verify.diagnostic, file_sha256=lambda path: "f" * 64, reject=verify.reject)
        sha = "a" * 40
        with patch.object(journeys, "JOURNEY_DIR", self.dir):
            with tempfile.TemporaryDirectory() as work:
                with patch.dict(os.environ, {"SLIPWAY_PARAM_JOURNEYS": "bog/0.1/O1/J1"}):
                    self.assertEqual(journeys.main(Path(work), Path(work), sha, fake), 0)
                self.assertEqual((Path(work) / "passed").read_text().split(), [sha, "f" * 64, "1"])
                result = json.loads((Path(work) / "artifacts" / "result.json").read_text())
                self.assertEqual(result["profile"], "journeys")
                self.assertEqual(result["status"], "passed")
            with tempfile.TemporaryDirectory() as work:
                with patch.dict(os.environ, {"SLIPWAY_PARAM_JOURNEYS": "bog/0.1/O1/J1,bog/0.1/O1/J2"}):
                    self.assertEqual(journeys.main(Path(work), Path(work), sha, fake), 1)
                rejection = (Path(work) / "rejection").read_text()
                self.assertIn("rejected in journeys (suites=1)", rejection)
                self.assertNotIn("print(", rejection)
            with tempfile.TemporaryDirectory() as work:
                with patch.dict(os.environ, {"SLIPWAY_PARAM_JOURNEYS": ""}):
                    self.assertEqual(journeys.main(Path(work), Path(work), sha, fake), 2)


if __name__ == "__main__":
    unittest.main()
