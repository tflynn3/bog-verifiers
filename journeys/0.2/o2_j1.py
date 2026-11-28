"""Refuse ingest on a full disk, then recover all acknowledged rows."""

import errno
import json
import os
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lib import Bog, JourneyFailed, expect, run
from support import budget, require_linux, serving

T0, T1, T2, T3 = (f"2025-01-01T00:00:0{second}Z" for second in range(4))


def bounded_tmpfs_mount():
    """Locate an unprivileged writable bounded tmpfs (SLIPWAY_PARAM_ENOSPC_MOUNT or /dev/shm).
    Slipway verifier pods run as non-root UID 65532 with Capabilities.Drop=['ALL'] and provide
    /dev/shm as a private 64 MiB tmpfs."""
    supplied = os.environ.get("SLIPWAY_PARAM_ENOSPC_MOUNT")
    mount = Path(supplied or "/dev/shm").resolve()
    mountinfo = Path("/proc/self/mountinfo")
    if mountinfo.is_file() and mount.is_dir() and mount != Path("/"):
        for line in mountinfo.read_text().splitlines():
            left, _, right = line.partition(" - ")
            fields = left.split()
            if len(fields) < 5 or fields[4].replace(r"\040", " ") != str(mount):
                continue
            if not supplied and (not right or right.split()[0] != "tmpfs"):
                continue
            stats = os.statvfs(mount)
            capacity = stats.f_blocks * stats.f_frsize
            free = stats.f_bavail * stats.f_frsize
            if 1024**2 <= capacity <= 256 * 1024**2 and free >= capacity * 0.5 and os.access(mount, os.W_OK | os.X_OK):
                return mount, capacity
    raise RuntimeError(f"ENOSPC journey requires {mount} to be a writable 1-256 MiB tmpfs mount")


def fill_disk(filler, capacity):
    """Allocate all remaining blocks on the bounded tmpfs until a write returns kernel ENOSPC."""
    with filler.open("wb", buffering=0) as stream:
        for chunk_size in (1024 * 1024, 4096, 1):
            chunk = b"x" * chunk_size
            while stream.tell() <= capacity + 1024 * 1024:
                try:
                    written = stream.write(chunk)
                    if not written:
                        break
                except OSError as exc:
                    if exc.errno == errno.ENOSPC:
                        break
                    raise
        try:
            stream.write(b"x")
        except OSError as exc:
            if exc.errno == errno.ENOSPC:
                os.fsync(stream.fileno())
                return
            raise
    raise RuntimeError("bounded tmpfs did not return kernel ENOSPC after filling")


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
    mount_root, capacity = bounded_tmpfs_mount()
    before = {"ts": T1, "line": "before α"}
    after = {"ts": T0, "line": "after"}

    with tempfile.TemporaryDirectory(prefix="bog-j02-", dir=mount_root) as tmp_mount:
        mount = Path(tmp_mount)
        os.chmod(mount, 0o700)
        bog.data_dir = mount / "data"
        filler = mount / "filler"

        with serving(bog, active_deadline, 10, crash=True) as startup_deadline:
            wait_ready(bog, startup_deadline)
            ingest(bog, [before, before], active_deadline, 204, "the two original rows")
            fill_disk(filler, capacity)
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
