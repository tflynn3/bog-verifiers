"""Recover acknowledged raw logs after SIGKILL."""

import signal
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lib import Bog, expect, run


def journey(args, bog: Bog):
    start = "2025-01-01T00:00:00Z"
    end = "2025-01-02T00:00:00Z"
    a = {"ts": "2025-01-01T05:30:01.123456789+05:30", "line": ' café "quoted"\npath\\tail '}
    boot = {"ts": start, "line": "boot"}

    bog.start(timeout=10)
    status = bog.ingest([a], timeout=3)
    expect(status == 204, "the single-record batch to return HTTP 204", f"HTTP {status}")

    status = bog.ingest([{"ts": start, "line": "rejected"}, {"ts": "bad", "line": "invalid"}], timeout=3)
    expect(status == 400, "the batch with an invalid timestamp to return HTTP 400", f"HTTP {status}")

    status = bog.ingest([boot, a], timeout=3)
    expect(status == 204, "the boot and duplicate batch to return HTTP 204", f"HTTP {status}")
    code = bog.kill(timeout=5)
    expect(code == -signal.SIGKILL, "termination by SIGKILL", f"process wait result {code!r}")

    bog.start(timeout=10)
    recovered_a = {"ts": "2025-01-01T00:00:01.123456789Z", "line": a["line"]}
    bog.expect_query(start, end, [boot, recovered_a, recovered_a], limit=10)

    code = bog.stop(timeout=35)
    expect(code == 0, "exit 0 after SIGTERM", f"process wait result {code!r}")


if __name__ == "__main__":
    run(journey, timeout=90)
