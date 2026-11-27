"""Helpers for bog acceptance journeys. Standard library only.

A journey script imports this module, defines `journey(args, bog)` and calls `run(journey)`:

    import sys, pathlib
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
    from lib import Bog, expect, run

    def journey(args, bog):
        bog.start()
        expect(bog.ingest([{"ts": "2025-01-01T00:00:00Z", "line": "hello"}]) == 204,
               "ingest returns 204", "a different status")
        ...

    run(journey)

`run` exits 0 when the journey passes, 1 with one "expected ...; observed ..." line when it fails,
and 2 for a harness error. The data directory lives under the per-journey work directory.
"""

import argparse
import json
import os
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


class JourneyFailed(Exception):
    """The observed behavior differs from the journey spec."""


def expect(condition, expected, observed):
    if not condition:
        raise JourneyFailed(f"expected {expected}; observed {observed}")


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class Bog:
    """One bog server process with a private data directory."""

    def __init__(self, binary, workdir, name="data", extra_args=()):
        self.binary = str(binary)
        self.data_dir = Path(workdir) / name
        self.port = free_port()
        self.extra_args = list(extra_args)
        self.proc = None
        self.log_path = Path(workdir) / f"{name}.log"

    @property
    def base(self):
        return f"http://127.0.0.1:{self.port}"

    def start(self, timeout=30):
        self.data_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.data_dir, 0o700)
        log = self.log_path.open("ab")
        self.proc = subprocess.Popen(
            [self.binary, "-data-dir", str(self.data_dir), "-addr", f"127.0.0.1:{self.port}", *self.extra_args],
            stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise JourneyFailed(f"expected bog to start and serve /healthz; observed exit {self.proc.returncode}: "
                                    f"{self.log_tail()}")
            try:
                status, _, _ = self.request("GET", "/healthz", timeout=2)
                if status == 200:
                    return self
            except OSError:
                pass
            time.sleep(0.2)
        raise JourneyFailed(f"expected /healthz to return 200 within {timeout}s; observed no healthy response")

    def log_tail(self, size=400):
        try:
            return " ".join(self.log_path.read_text(errors="replace")[-size:].split())
        except OSError:
            return ""

    def stop(self, sig=signal.SIGTERM, timeout=20):
        if self.proc is None or self.proc.poll() is not None:
            return None
        self.proc.send_signal(sig)
        try:
            return self.proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            return self.proc.wait(timeout=10)

    def kill(self):
        """Crash the server (SIGKILL), as a power loss or OOM kill would."""
        return self.stop(signal.SIGKILL)

    def restart(self, timeout=30):
        self.stop()
        self.port = free_port()
        return self.start(timeout=timeout)

    def request(self, method, path, body=None, headers=None, timeout=30):
        data = body.encode() if isinstance(body, str) else body
        req = urllib.request.Request(self.base + path, data=data, method=method, headers=headers or {})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.status, dict(resp.headers), resp.read()
        except urllib.error.HTTPError as err:
            return err.code, dict(err.headers or {}), err.read()

    def ingest(self, rows):
        """POST NDJSON rows ({"ts": ..., "line": ...}); returns the HTTP status."""
        body = "".join(json.dumps(row) + "\n" for row in rows)
        status, _, _ = self.request("POST", "/ingest", body, {"Content-Type": "application/x-ndjson"})
        return status

    def query(self, start, end, contains=None, limit=None, page=None, cursor=None):
        """GET /query; returns (status, rows, headers)."""
        params = {"start": start, "end": end}
        if contains is not None:
            params["contains"] = contains
        if limit is not None:
            params["limit"] = str(limit)
        if page is not None:
            params["page"] = str(page)
        if cursor is not None:
            params["cursor"] = cursor
        status, headers, body = self.request("GET", "/query?" + urllib.parse.urlencode(params))
        rows = []
        if status == 200:
            rows = [json.loads(line) for line in body.decode().splitlines() if line.strip()]
        return status, rows, headers

    def query_all(self, start, end, contains=None, limit=500, max_pages=10000):
        """Walk a stable snapshot with page=1 and Bog-Next-Cursor; returns every row."""
        status, rows, headers = self.query(start, end, contains, limit, page=1)
        expect(status == 200, "the first page to return 200", f"status {status}")
        out = list(rows)
        pages = 1
        while headers.get("Bog-Next-Cursor") and pages < max_pages:
            status, rows, headers = self.query(start, end, contains, limit, cursor=headers["Bog-Next-Cursor"])
            expect(status == 200, "each continuation page to return 200", f"status {status}")
            out.extend(rows)
            pages += 1
        return out


def parse_args(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--bog", required=True)
    parser.add_argument("--workdir", required=True)
    parser.add_argument("--corpus", default="")
    parser.add_argument("--journey", default="")
    return parser.parse_args(argv)


def run(journey, argv=None):
    args = parse_args(argv)
    bog = Bog(args.bog, args.workdir)
    code = 0
    try:
        journey(args, bog)
        print("passed")
    except JourneyFailed as exc:
        print(str(exc))
        code = 1
    except Exception as exc:  # harness problem, not a product failure
        print(f"harness error: {exc!r}")
        code = 2
    finally:
        try:
            bog.stop()
        except Exception:
            pass
    sys.exit(code)
