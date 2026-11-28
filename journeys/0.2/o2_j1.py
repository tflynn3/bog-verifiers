"""Refuse ingest on a full disk, then recover all acknowledged rows."""

import errno
import json
import os
import subprocess
import sys
import time
from contextlib import contextmanager
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lib import Bog, JourneyFailed, expect, run
from support import budget, require_linux, serving

T0, T1, T2, T3 = (f"2025-01-01T00:00:0{second}Z" for second in range(4))

# Use the kernel calls directly so a non-root runner with mount privileges can
# set up the filesystem. The helper process allows each operation to time out.
MOUNT_HELPER = """
import ctypes
import os
import sys

libc = ctypes.CDLL(None, use_errno=True)
operation, target = sys.argv[1:]
target = os.fsencode(target)
if operation == "mount":
    options = f"size=8m,mode=0700,uid={os.geteuid()},gid={os.getegid()}".encode()
    result = libc.mount(b"tmpfs", target, b"tmpfs", ctypes.c_ulong(0), options)
    if result == 0:
        MS_PRIVATE = 1 << 18
        result = libc.mount(None, target, None, ctypes.c_ulong(MS_PRIVATE), None)
else:
    result = libc.umount2(target, 0)
if result != 0:
    sys.exit(os.strerror(ctypes.get_errno()))
"""


def mount_operation(operation, path, timeout):
    result = subprocess.run([sys.executable, "-B", "-c", MOUNT_HELPER, operation, str(path)],
                            capture_output=True, text=True, timeout=timeout)
    if result.returncode != 0:
        raise RuntimeError(f"cannot {operation} private tmpfs: {result.stderr.strip()}")


@contextmanager
def private_tmpfs(path, deadline):
    path.mkdir(mode=0o700)
    try:
        mount_operation("mount", path, budget(deadline, 5, "tmpfs to mount before teardown"))
        yield
    finally:
        if os.path.ismount(path):
            mount_operation("unmount", path, 5)


def fill_disk(filler):
    with filler.open("xb") as handle:
        block_info = os.statvfs(filler)
        length = block_info.f_bavail * block_info.f_frsize
        if length:
            os.posix_fallocate(handle.fileno(), 0, length)
        try:
            os.pwrite(handle.fileno(), b"x", length)
        except OSError as exc:
            if exc.errno == errno.ENOSPC:
                return
            raise
    raise RuntimeError("the filler file could still grow after allocating all available blocks")


def wait_ready(bog, deadline, *, disk_full=False):
    expected = ("GET /ready to return HTTP 503 with ready=false and reason=low_disk_headroom within 5s"
                if disk_full else "GET /ready to return HTTP 200 within the 10s startup window")
    observed = "no response before the deadline"
    while (remaining := deadline - time.monotonic()) > 0:
        try:
            status, _, body = bog.request("GET", "/ready", timeout=min(2, remaining))
            observed = f"HTTP {status}"
            if not disk_full and status == 200 and time.monotonic() <= deadline:
                return
            if disk_full and status == 503:
                observed = f"HTTP 503 with body {body[:120]!r}"
                try:
                    ready = json.loads(body.decode("utf-8"))
                except (ValueError, RecursionError):
                    ready = None
                if (isinstance(ready, dict) and ready.get("ready") is False
                        and ready.get("reason") == "low_disk_headroom" and time.monotonic() <= deadline):
                    return
        except JourneyFailed as exc:
            observed = str(exc).partition("; observed ")[2]
        time.sleep(min(0.05, max(0, deadline - time.monotonic())))
    expect(False, expected, observed)


def ingest(bog, rows, deadline, expected_status, description):
    expected = f"{description} to return HTTP {expected_status}"
    status, _, response = bog.ingest_response(rows, timeout=budget(deadline, 2, expected))
    expect(status == expected_status, expected, f"HTTP {status} with body {response[:120]!r}")
    return response


def query(bog, rows, deadline):
    bog.expect_query(T0, T3, rows, limit=10, timeout=budget(deadline, 2, "query to finish before teardown"))


def journey(args, bog: Bog):
    active_deadline = args.deadline - 15
    require_linux()
    mount = Path(args.workdir) / "disk"
    bog.data_dir = mount / "data"
    filler = mount / "filler"
    before = {"ts": T1, "line": "before α"}
    after = {"ts": T0, "line": "after"}

    with private_tmpfs(mount, active_deadline):
        with serving(bog, active_deadline, 10, crash=True) as startup_deadline:
            wait_ready(bog, startup_deadline)
            ingest(bog, [before, before], active_deadline, 204, "the two original rows")
            fill_disk(filler)
            wait_ready(bog, min(active_deadline, time.monotonic() + 5), disk_full=True)

            rejected = [{"ts": T0, "line": "rejected"}, {"ts": T2, "line": "x" * 32768}]
            body = ingest(bog, rejected, active_deadline, 503, "the batch while the disk is full")
            expect(body == b"disk full\n", "the refusal body to be exactly 'disk full\\n'", repr(body[:120]))
            expected = "GET /healthz to return HTTP 200 while the disk is full"
            health, _, _ = bog.request("GET", "/healthz", timeout=budget(active_deadline, 2, expected))
            expect(health == 200, expected, f"HTTP {health}")
            query(bog, [before, before], active_deadline)

            filler.unlink()
            ingest(bog, [after], active_deadline, 204, "ingest after freeing disk space")

        with serving(bog, active_deadline, 10) as startup_deadline:
            wait_ready(bog, startup_deadline)
            query(bog, [after, before, before], active_deadline)


if __name__ == "__main__":
    run(journey, timeout=120, cleanup=False)
