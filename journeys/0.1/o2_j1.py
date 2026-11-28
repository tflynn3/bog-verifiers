"""Search recovered raw logs after an orderly restart."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lib import Bog, expect, run


def journey(args, bog: Bog):
    t0, t1, t2, t3 = (f"2025-01-01T00:00:0{second}Z" for second in range(4))
    batch = [
        {"ts": t3, "line": "ERR.[1] end"},
        {"ts": t2, "line": "ERR.[1] later"},
        {"ts": t0, "line": "ERR.[1] early"},
        {"ts": t1, "line": "ERR.[1] start"},
        {"ts": t2, "line": "err.[1] lower"},
        {"ts": t2, "line": "ERRx1 decoy"},
        {"ts": t2, "line": "ERR.[1] tie"},
    ]

    bog.start(timeout=10)
    status = bog.ingest(batch, timeout=3)
    expect(status == 204, "the seven-record batch to return HTTP 204", f"HTTP {status}")
    code = bog.stop(timeout=35)
    expect(code == 0, "exit 0 after SIGTERM before restart", f"process wait result {code!r}")

    bog.start(timeout=10)
    matches = [
        {"ts": t1, "line": "ERR.[1] start"},
        {"ts": t2, "line": "ERR.[1] later"},
        {"ts": t2, "line": "ERR.[1] tie"},
    ]
    bog.expect_query(t1, t3, matches, contains="ERR.[1]", limit=10)
    bog.expect_query(t1, t3, matches[:1], contains="ERR.[1]", limit=1)
    bog.expect_query(t1, t3, [], contains="absent", limit=10)

    code = bog.stop(timeout=35)
    expect(code == 0, "exit 0 after SIGTERM following restart", f"process wait result {code!r}")


if __name__ == "__main__":
    run(journey, timeout=115)
