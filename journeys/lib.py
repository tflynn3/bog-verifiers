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
import http.client
import json
import os
import signal
import socket
import subprocess
import sys
import time
import urllib.parse
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

    def start(self, timeout=30, *, request_timeout=3, preexec_fn=None):
        if self.proc is None:
            self.data_dir.mkdir(mode=0o700, parents=True)
            os.chmod(self.data_dir, 0o700)
        deadline = time.monotonic() + timeout
        with self.log_path.open("ab") as log:
            self.proc = subprocess.Popen(
                [self.binary, "-data-dir", str(self.data_dir), "-addr", f"127.0.0.1:{self.port}", *self.extra_args],
                stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, preexec_fn=preexec_fn)
        expected = f"GET /healthz to return 200 within {timeout:g}s of launch"
        observed = "no healthy response"
        while (remaining := deadline - time.monotonic()) > 0:
            if self.proc.poll() is not None:
                expect(False, expected, f"process exit {self.proc.returncode} ({self.log_tail()})")
            try:
                status, _, _ = self.request("GET", "/healthz", timeout=min(request_timeout, remaining))
                if status == 200 and time.monotonic() <= deadline:
                    return self
                observed = f"last response HTTP {status} with no timely 200"
            except JourneyFailed as exc:
                observed = str(exc).partition("; observed ")[2]
            time.sleep(min(0.2, max(0, deadline - time.monotonic())))
        expect(False, expected, observed)

    def log_tail(self, size=400):
        try:
            return " ".join(self.log_path.read_text(errors="replace")[-size:].split())
        except OSError:
            return ""

    def stop(self, sig=signal.SIGTERM, timeout=20):
        if self.proc is None or self.proc.poll() is not None:
            return None
        deadline = time.monotonic() + timeout
        expected = f"process to exit and be reaped within {timeout}s of {sig.name}"
        self.proc.send_signal(sig)
        try:
            code = self.proc.wait(timeout=max(0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            expect(False, expected, "process still running at the deadline")
        expect(time.monotonic() <= deadline, expected, f"process reaped after the deadline with status {code}")
        return code

    def kill(self, timeout=5):
        """Crash the server with SIGKILL and reap it."""
        return self.stop(signal.SIGKILL, timeout)

    def restart(self, timeout=30):
        self.stop()
        self.port = free_port()
        return self.start(timeout=timeout)

    def request(self, method, path, body=None, headers=None, timeout=30):
        data = body.encode() if isinstance(body, str) else body
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=timeout)
        expected = f"{method} {path} to complete within {timeout:g}s"

        def expire(signum, frame):
            raise TimeoutError("request deadline expired")

        # Socket timeouts bound individual reads. The alarm bounds the entire exchange.
        previous_handler = signal.signal(signal.SIGALRM, expire)
        signal.setitimer(signal.ITIMER_REAL, timeout)
        try:
            connection.request(method, path, body=data, headers=headers or {})
            with connection.getresponse() as response:
                return response.status, dict(response.getheaders()), response.read()
        except (OSError, http.client.HTTPException, OverflowError) as exc:
            expect(False, expected, repr(exc))
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous_handler)
            connection.close()

    def ingest(self, rows, timeout=30):
        """POST NDJSON rows ({"ts": ..., "line": ...}); returns the HTTP status."""
        status, _, _ = self.ingest_response(rows, timeout)
        return status

    def ingest_response(self, rows, timeout=30):
        """POST NDJSON rows; returns (status, headers, raw body)."""
        body = "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows)
        return self.request("POST", "/ingest", body, {"Content-Type": "application/x-ndjson"}, timeout)

    def query_response(self, start, end, contains=None, limit=None, page=None, cursor=None, timeout=30):
        """GET /query; returns (status, headers, raw body)."""
        params = {"start": start, "end": end}
        if contains is not None:
            params["contains"] = contains
        if limit is not None:
            params["limit"] = str(limit)
        if page is not None:
            params["page"] = str(page)
        if cursor is not None:
            params["cursor"] = cursor
        return self.request("GET", "/query?" + urllib.parse.urlencode(params, safe=":"), timeout=timeout)

    def query(self, start, end, contains=None, limit=None, page=None, cursor=None):
        """GET /query; returns (status, rows, headers)."""
        status, headers, body = self.query_response(start, end, contains, limit, page, cursor)
        rows = []
        if status == 200:
            rows = [json.loads(line) for line in body.decode().splitlines() if line.strip()]
        return status, rows, headers

    def expect_query(self, start, end, rows, *, limit, contains=None, timeout=3):
        """Check the status, media type and ordered NDJSON records of a release query."""
        query = f"query from {start} to {end} (contains={contains!r}, limit={limit})"
        status, headers, body = self.query_response(start, end, contains, limit, timeout=timeout)
        expect(status == 200, f"{query} to return HTTP 200", f"HTTP {status}")
        content_type = next((value for name, value in headers.items() if name.lower() == "content-type"), "")
        expect(content_type.partition(";")[0].strip().lower() == "application/x-ndjson",
               f"{query} to return application/x-ndjson", f"Content-Type {content_type!r}")
        if not rows:
            expect(body == b"", f"{query} to return an empty body", repr(body[:200]))
            return
        try:
            actual = [json.loads(line.decode("utf-8")) for line in body.splitlines()]
        except (ValueError, RecursionError) as exc:
            expect(False, f"{query} to return UTF-8 NDJSON records", repr(exc))
        expect(len(actual) == len(rows), f"{query} to return {len(rows)} rows", f"{len(actual)} rows")
        for index, (wanted, got) in enumerate(zip(rows, actual), 1):
            if wanted != got:
                expected = f"{query} row {index} to match the original timestamp and line"
                expect(False, expected, query_difference(wanted, got))

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


def query_difference(wanted, got):
    if not isinstance(got, dict) or got.keys() != wanted.keys():
        return f"invalid row {repr(got)[:100]}"
    if wanted["ts"] != got["ts"]:
        return f"timestamp {repr(got['ts'])[:75]} instead of {wanted['ts']!r}"
    if not isinstance(got["line"], str):
        return f"line of type {type(got['line']).__name__} instead of a string"
    line, original = got["line"], wanted["line"]
    if len(line) != len(original):
        return f"line with {len(line)} characters instead of {len(original)}"
    offset = next(i for i, (left, right) in enumerate(zip(line, original)) if left != right)
    return f"character {line[offset]!r} at offset {offset} instead of {original[offset]!r}"


def parse_args(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--bog", required=True)
    parser.add_argument("--workdir", required=True)
    parser.add_argument("--corpus", default="")
    parser.add_argument("--journey", default="")
    return parser.parse_args(argv)


def run(journey, argv=None, *, timeout=None, cleanup=True):
    started = time.monotonic()
    args = parse_args(argv)
    args.deadline = None if timeout is None else started + timeout
    bog = Bog(args.bog, args.workdir)
    code = 0
    try:
        journey(args, bog)
        elapsed = time.monotonic() - started
        if timeout is not None:
            expect(elapsed <= timeout, f"journey to finish within {timeout}s", f"{elapsed:.3f}s elapsed")
        message = "passed"
    except JourneyFailed as exc:
        message = str(exc)
        code = 1
    except Exception as exc:  # harness problem, not a product failure
        message = f"harness error: {exc!r}"
        code = 2
    finally:
        try:
            if cleanup:
                bog.kill()
        except Exception as exc:
            if code == 0:
                message = f"harness error during cleanup: {exc!r}"
                code = 2
            else:
                message += f" (cleanup failed: {exc!r})"
    print(message)
    sys.exit(code)
