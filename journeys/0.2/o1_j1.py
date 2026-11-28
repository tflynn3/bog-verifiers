"""Search growing raw history before and after restarting under a 256 MiB cap."""

import multiprocessing
import os
import sys
import tempfile
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lib import Bog, expect, run
from support import budget, require_linux, serving

T = datetime(2025, 1, 1, tzinfo=timezone.utc)
PADDING = "x" * 10240
BATCH_SIZE = 256
BATCH_COUNT = 128
WINDOWS = (0, 16384, 32764)
MAX_RSS_BYTES = 268_435_456  # 256 MiB


def timestamp(i):
    return (T + timedelta(minutes=i)).isoformat().replace("+00:00", "Z")


def row(i):
    tag = "NEEDLE" if i % 4 == 1 else "needle"
    return {"ts": timestamp(i), "line": f"{tag}-{i}-{PADDING}"}


def query(bog, k, deadline):
    bog.expect_query(timestamp(k), timestamp(k + 3), [row(k), row(k + 2)], contains="needle", limit=10,
                     timeout=budget(deadline, 2, f"the query for row {k} to finish before teardown"))


def query_worker(bog, deadline, sender):
    try:
        query(bog, 0, deadline)
    except Exception as exc:
        sender.send(exc)
    else:
        sender.send(None)


@contextmanager
def live_query(bog, deadline):
    # A separate process gives the query its own connection and request alarm.
    context = multiprocessing.get_context("fork")
    receiver, sender = context.Pipe(duplex=False)
    with receiver, sender:
        worker = context.Process(target=query_worker, args=(bog, deadline, sender))
        worker.start()
        sender.close()
        try:
            yield
            expected = "the concurrent query to finish during ingest"
            expect(receiver.poll(0) or receiver.poll(budget(deadline, 2, expected)), expected,
                   "no query result before the deadline")
            error = receiver.recv()
            if error is not None:
                raise error
        finally:
            if worker.is_alive():
                worker.kill()
            worker.join(timeout=2)
            if worker.is_alive():
                raise RuntimeError("could not reap the query client")
            worker.close()


def proc_peak_rss_bytes(pid):
    """Read kernel-tracked peak (VmHWM) and current (VmRSS) resident set size from /proc/<pid>/status.
    Works unprivileged as UID 65532 inside Slipway verifier pods without cgroup delegation."""
    status_path = Path(f"/proc/{pid}/status")
    peak_kib = 0
    try:
        for line in status_path.read_text().splitlines():
            if line.startswith(("VmHWM:", "VmRSS:")):
                parts = line.split()
                if len(parts) >= 2:
                    peak_kib = max(peak_kib, int(parts[1]))
    except OSError:
        return 0
    return peak_kib * 1024


def check_memory_budget(bog, stage):
    if bog.proc is None:
        return
    if bog.proc.poll() is not None:
        expect(False, f"Bog to remain running within 256 MiB during {stage}",
               f"process exited with status {bog.proc.returncode} ({bog.log_tail()})")
    peak = proc_peak_rss_bytes(bog.proc.pid)
    expect(peak <= MAX_RSS_BYTES,
           "Bog peak resident memory (VmHWM) <= 268435456 bytes (256 MiB)",
           f"VmHWM={peak} bytes ({peak / (1024 * 1024):.1f} MiB) during {stage}")


def ingest_batch(bog, batch, deadline):
    first = batch * BATCH_SIZE
    rows = [row(i) for i in range(first, first + BATCH_SIZE)]
    expected = f"batch {batch + 1} to return HTTP 204 within the 60s ingest window"
    status = bog.ingest(rows, timeout=budget(deadline, 2, expected))
    expect(status == 204 and time.monotonic() <= deadline, expected,
           f"HTTP {status}" if status != 204 else "HTTP 204 after the ingest deadline")
    # Enforce the 256 MiB cap continuously so an unbounded binary fails cleanly at 256 MiB
    # instead of growing to the verifier container's 1 GiB pod limit.
    check_memory_budget(bog, f"batch {batch + 1}")


def optional_delegated_cgroup():
    """Use delegated cgroup v2 when explicitly supplied; otherwise run unprivileged via /proc VmHWM."""
    supplied = os.environ.get("SLIPWAY_PARAM_JOURNEY_CGROUP_PARENT")
    if not supplied:
        return None
    parent = Path(supplied)
    try:
        if "memory" in (parent / "cgroup.subtree_control").read_text().split():
            return Path(tempfile.mkdtemp(prefix="bog-journey-", dir=parent))
    except OSError:
        return None
    return None


def oom_counts(group):
    events = dict(line.split() for line in (group / "memory.events").read_text().splitlines())
    return {name: int(events[name]) for name in ("oom", "oom_kill")}


def journey(args, bog: Bog):
    active_deadline = args.deadline - 10
    require_linux()
    group = optional_delegated_cgroup()
    initial = None
    enter_cgroup = None
    try:
        if group is not None:
            (group / "memory.max").write_text(f"{MAX_RSS_BYTES}\n")
            (group / "memory.swap.max").write_text("0\n")
            initial = oom_counts(group)

            def enter_cgroup():
                (group / "cgroup.procs").write_text("0\n")

        try:
            with serving(bog, active_deadline, 15, preexec_fn=enter_cgroup):
                ingest_deadline = min(active_deadline, time.monotonic() + 60)
                for batch in range(32):
                    ingest_batch(bog, batch, ingest_deadline)
                with live_query(bog, ingest_deadline):
                    for batch in range(32, BATCH_COUNT):
                        ingest_batch(bog, batch, ingest_deadline)
                for k in WINDOWS:
                    query(bog, k, active_deadline)
                check_memory_budget(bog, "post-ingest queries")
            with serving(bog, active_deadline, 15, preexec_fn=enter_cgroup):
                check_memory_budget(bog, "restart startup")
                for k in WINDOWS:
                    query(bog, k, active_deadline)
                check_memory_budget(bog, "post-restart queries")
        finally:
            if group is not None and initial is not None:
                final = oom_counts(group)
                expect(final == initial, "zero increases in cgroup oom and oom_kill counters",
                       ", ".join(f"{name} increased by {final[name] - initial[name]}" for name in initial))
    finally:
        if group is not None:
            try:
                group.rmdir()
            except OSError:
                pass


if __name__ == "__main__":
    run(journey, timeout=120, cleanup=False)
