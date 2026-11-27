"""Release acceptance journeys for bog (verifier profile `journeys`).

verify.sh runs this profile for SLIPWAY_PARAM_MODE=journeys. bog-conductor passes the journeys to
run as SLIPWAY_PARAM_JOURNEYS, a comma-separated list of journey IDs such as `bog/0.1/O1/J1`.
journeys/index.json maps each journey ID to a script under journeys/. A script exits 0 when the
journey passes, 1 when the observed behavior differs from the journey's spec (printing one line
that names the expected and observed behavior), and any other status for a harness problem.

The release's journeys are frozen with the release: they are written once at G1 and the verifier
image digest is pinned for the release. Builders never see these scripts. A failure reports only
the journey ID and the script's one-line expected/observed message.
"""

import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
JOURNEY_DIR = Path(os.environ.get("BOG_JOURNEYS_DIR", str(HERE / "journeys")))
CORPUS_DIR = HERE / "corpus"
JOURNEY_ID = re.compile(r"^[a-z][a-z0-9-]{2,19}/[0-9]+[.][0-9]+/O[0-9]+/J[0-9]+$")
DEFAULT_TIMEOUT = int(os.environ.get("SLIPWAY_PARAM_JOURNEY_TIMEOUT", "180"))
MESSAGE_LIMIT = 400


def requested_journeys(raw):
    """Parse the comma-separated journey list. Returns (ids, malformed ids)."""
    ids = []
    for part in (raw or "").split(","):
        part = part.strip()
        if part and part not in ids:
            ids.append(part)
    return ids, [i for i in ids if not JOURNEY_ID.match(i)]


def load_registry(directory=None):
    path = Path(directory or JOURNEY_DIR) / "index.json"
    if not path.is_file():
        return {}
    data = json.loads(path.read_text())
    if not isinstance(data, dict) or not all(isinstance(v, str) for v in data.values()):
        raise ValueError("journeys/index.json must map journey IDs to script paths")
    return dict(data)


def last_line(text):
    lines = [line.strip() for line in (text or "").splitlines() if line.strip()]
    return (lines[-1] if lines else "")[:MESSAGE_LIMIT]


def run_journey(journey_id, script, binary, corpus, timeout):
    with tempfile.TemporaryDirectory(prefix="bog-journey-") as tmp:
        command = [sys.executable, "-B", str(script), "--bog", str(binary), "--workdir", tmp,
                   "--corpus", str(corpus), "--journey", journey_id]
        started = time.monotonic()
        try:
            proc = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                                  timeout=timeout, cwd=tmp)
        except subprocess.TimeoutExpired:
            return {"name": journey_id, "status": "infra_error",
                    "diagnostic": f"journey timed out after {timeout}s",
                    "seconds": round(time.monotonic() - started, 1)}
        seconds = round(time.monotonic() - started, 1)
        message = last_line(proc.stdout) or last_line(proc.stderr)
        if proc.returncode == 0:
            return {"name": journey_id, "status": "passed", "seconds": seconds}
        if proc.returncode == 1:
            return {"name": journey_id, "status": "rejected", "seconds": seconds,
                    "diagnostic": message or "journey failed without an expected/observed message"}
        return {"name": journey_id, "status": "infra_error", "seconds": seconds,
                "diagnostic": f"journey harness exited {proc.returncode}: {message}"}


def run_journeys(ids, registry, binary, corpus=CORPUS_DIR, timeout=DEFAULT_TIMEOUT, directory=None):
    base = Path(directory or JOURNEY_DIR).resolve()
    results = []
    for journey_id in ids:
        relative = registry.get(journey_id)
        if not relative:
            results.append({"name": journey_id, "status": "infra_error",
                            "diagnostic": "journey is not implemented in bog-verifiers"})
            continue
        script = (base / relative).resolve()
        if base not in script.parents or not script.is_file():
            results.append({"name": journey_id, "status": "infra_error",
                            "diagnostic": f"journey script {relative} is missing"})
            continue
        results.append(run_journey(journey_id, script, binary, corpus, timeout))
    return results


def summarize(results):
    """Return (exit code, diagnostic): 0 all passed, 1 a journey failed, 2 harness problems only."""
    failed = [r for r in results if r["status"] == "rejected"]
    broken = [r for r in results if r["status"] == "infra_error"]
    if failed:
        parts = [f"{r['name']}: {r['diagnostic']}" for r in failed]
        if broken:
            parts.append(f"{len(broken)} journey(s) could not run: " + ", ".join(r["name"] for r in broken))
        return 1, "; ".join(parts)
    if broken:
        return 2, "; ".join(f"{r['name']}: {r['diagnostic']}" for r in broken)
    if not results:
        return 2, "no journeys were run"
    return 0, ""


def main(source, work, sha, verify):
    """Entry point from verify.main for profile `journeys`; `verify` is the verify module."""
    evidence = work / "artifacts"
    evidence.mkdir(exist_ok=True)
    ids, malformed = requested_journeys(os.environ.get("SLIPWAY_PARAM_JOURNEYS"))
    result = verify.new_result(sha, sha, "journeys")
    result["suites"] = [{"name": journey_id, "status": "pending"} for journey_id in ids]

    def checkpoint():
        temporary = evidence / "result.tmp"
        temporary.write_text(json.dumps(result, sort_keys=True) + "\n")
        temporary.replace(evidence / "result.json")

    def infra(reason):
        result.update(status="infra_error", diagnostic=reason)
        checkpoint()
        print(f"Bog journeys infrastructure error: {reason}", file=sys.stderr)
        return 2

    checkpoint()
    if not ids:
        return infra("SLIPWAY_PARAM_JOURNEYS lists no journey IDs")
    if malformed:
        return infra("malformed journey IDs: " + ", ".join(malformed))
    (work / "stage").write_text("build")
    try:
        binary = verify.build(source, work, evidence / "build.log")
    except verify.Rejected as exc:
        reason = verify.diagnostic(exc)
        result["build"].update(status="rejected", diagnostic=reason)
        result.update(status="rejected", diagnostic=f"build: {reason}")
        checkpoint()
        return verify.reject(work, sha, "build", 0, reason)
    except verify.InfrastructureError as exc:
        result["build"].update(status="infra_error", diagnostic=verify.diagnostic(exc))
        return infra("build: " + verify.diagnostic(exc))
    digest = verify.file_sha256(binary)
    result["build"].update(status="passed", binary_sha256=digest)
    try:
        registry = load_registry()
    except (ValueError, json.JSONDecodeError) as exc:
        return infra(str(exc))
    (work / "stage").write_text(f"journeys ({len(ids)})")
    results = run_journeys(ids, registry, binary)
    for entry in results:
        print(f"JOURNEY {entry['name']} {entry['status']} {entry.get('seconds', 0)}s {entry.get('diagnostic', '')}")
    result["suites"] = results
    code, reason = summarize(results)
    if code == 0:
        result["status"] = "passed"
        checkpoint()
        (work / "passed").write_text(f"{sha} {digest} {len(results)}\n")
        return 0
    if code == 1:
        result.update(status="rejected", diagnostic=reason)
        checkpoint()
        passed = sum(1 for r in results if r["status"] == "passed")
        return verify.reject(work, sha, "journeys", passed, reason)
    return infra(reason)
