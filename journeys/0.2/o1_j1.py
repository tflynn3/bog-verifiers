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


def ingest_batch(bog, batch, deadline):
    first = batch * BATCH_SIZE
    rows = [row(i) for i in range(first, first + BATCH_SIZE)]
    expected = f"batch {batch + 1} to return HTTP 204 within the 60s ingest window"
    status = bog.ingest(rows, timeout=budget(deadline, 2, expected))
    expect(status == 204 and time.monotonic() <= deadline, expected,
           f"HTTP {status}" if status != 204 else "HTTP 204 after the ingest deadline")


def new_cgroup():
    supplied = os.environ.get("SLIPWAY_PARAM_JOURNEY_CGROUP_PARENT")
    if supplied:
        parents = [Path(supplied)]
    else:
        root = Path("/sys/fs/cgroup")
        membership = next((line[3:] for line in Path("/proc/self/cgroup").read_text().splitlines()
                           if line.startswith("0::/")), None)
        if membership is None:
            raise RuntimeError("no cgroup v2 membership")
        current = (root / membership.lstrip("/")).resolve()
        parents = [p for p in (current, *current.parents) if p.is_relative_to(root)]
    for parent in parents:
        try:
            controllers = (parent / "cgroup.subtree_control").read_text().split()
            if "memory" in controllers:
                return Path(tempfile.mkdtemp(prefix="bog-journey-", dir=parent))
        except OSError:
            continue
    raise RuntimeError("no writable cgroup v2 delegation with memory enabled; "
                       "set SLIPWAY_PARAM_JOURNEY_CGROUP_PARENT")


def oom_counts(group):
    events = dict(line.split() for line in (group / "memory.events").read_text().splitlines())
    return {name: int(events[name]) for name in ("oom", "oom_kill")}


def journey(args, bog: Bog):
    active_deadline = args.deadline - 10
    require_linux()
    group = new_cgroup()
    try:
        (group / "memory.max").write_text("268435456\n")
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
            with serving(bog, active_deadline, 15, preexec_fn=enter_cgroup):
                for k in WINDOWS:
                    query(bog, k, active_deadline)
        finally:
            final = oom_counts(group)
            expect(final == initial, "zero increases in cgroup oom and oom_kill counters",
                   ", ".join(f"{name} increased by {final[name] - initial[name]}" for name in initial))
    finally:
        group.rmdir()


if __name__ == "__main__":
    run(journey, timeout=120, cleanup=False)
