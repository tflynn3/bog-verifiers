"""Black-box Bog verifier. Run through verify.sh."""
import bisect
import contextlib
import contextvars
import dataclasses
import datetime as dt
import errno
import hashlib
import http.client
import itertools
import json
import math
import os
import random
import re
import select
import signal
import socket
import statistics
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path


SECOND = 1_000_000_000
EPOCH = dt.datetime(2025, 3, 14, 12, tzinfo=dt.timezone.utc)
STAMP = re.compile(
    r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?"
    r"(Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)",
    re.ASCII,
)
WAL_MAGIC = b"BOGWAL01"
COMMIT_MAGIC = b"BOGCMT01"
BASELINE_SHA = "25d0c0acc103bd73f0552a8f10240c8d8c1d023d"
COMPARISON_BASELINE_SHA = "4ff49aae9672cf5aec8e3fbd20ffe0a84ae15bc0"
CYCLE7_BASELINE_SHA = "be7f937a1025a57166d15888727012ed4989a6b4"
NEXT_CURSOR = "Bog-Next-Cursor"
MAX_FRAME = 4 * 1024 * 1024
DEFAULT_QUERY_LIMIT = 500
MAX_QUERY_LIMIT = 1000
HTTP_TIMEOUT = 5
START_TIMEOUT = 12
CORPUS_DIR = Path(__file__).resolve().parent / "corpus"
CORPUS_PATH = CORPUS_DIR / "replay.ndjson"
CORPUS_SHA256 = "7b79f2ac83692126019934e6a7738524aaa55f3e2151237d8421cae0539aff72"
CORPUS_SOURCES = {"access": 513, "error": 36, "app": 1009, "seed": 1000}
APACHE_PATH = CORPUS_DIR / "apache-access.log"
APACHE_SHA256 = "29e286fd748b06450152c4efcfe9c4f2a668a8b3223720f7fba052ffd902b14e"
APACHE_STAMP = re.compile(r"^\S+ \S+ \S+ \[([^\]]+)\] ")
GIT_DAEMON_PATH = CORPUS_DIR / "git-daemon.log"
GIT_DAEMON_SHA256 = "8dcd8aba73ae74db1bc3adb9c32b2a06feee7aa92386ec61005b0d3dd3c07704"
SYSLOG_PATH = CORPUS_DIR / "syslog.log"
SYSLOG_SHA256 = "3a6f469ccce6be28541837f59aca53997a83aac061dcb0f03310e60bcaf7d717"
SEEDS = {
    "query-oracle": 0xB061, "kill-durability": 0xB067, "performance-smoke": 0xB070,
    "apache-replay": 0xB091, "snapshot-pagination": 0xB102, "git-daemon-replay": 0xB119,
    "log-replay": 0xB120,
}
PROCESS_LOGS = contextvars.ContextVar("process_logs")


class Rejected(Exception):
    pass


class InfrastructureError(Exception):
    pass


@dataclasses.dataclass(frozen=True)
class SuiteSkipped:
    reason: str


def check(condition, reason):
    if not condition:
        raise Rejected(reason)


@dataclasses.dataclass(frozen=True)
class Row:
    ns: int
    line: str
    offset: int = dataclasses.field(default=0, compare=False)


def stamp(ns, offset=0):
    seconds, fraction = divmod(ns, SECOND)
    zone = dt.timezone(dt.timedelta(minutes=offset))
    local = (EPOCH + dt.timedelta(seconds=seconds)).astimezone(zone)
    suffix = local.strftime("%z")
    zone_text = f"{suffix[:3]}:{suffix[3:]}" if offset else "Z"
    return f"{local.year:04d}-{local:%m-%dT%H:%M:%S}.{fraction:09}{zone_text}"


def parse_stamp(value):
    if not isinstance(value, str) or not (match := STAMP.fullmatch(value)):
        raise ValueError(f"invalid timestamp {value!r}")
    wall, fraction, zone = match.groups()
    delta = dt.datetime.fromisoformat(wall + ("+00:00" if zone == "Z" else zone)) - EPOCH
    return (delta.days * 86400 + delta.seconds) * SECOND + int((fraction or "").ljust(9, "0"))


def encode_rows(rows):
    return b"".join(
        json.dumps({"ts": stamp(row.ns, row.offset), "line": row.line}, ensure_ascii=False).encode()
        + b"\n"
        for row in rows
    )


def unique_fields(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON field {key!r}")
        result[key] = value
    return result


def decode_rows(body):
    try:
        result = []
        for line in body.split(b"\n"):
            if not line.strip():
                continue
            value = json.loads(line.decode("utf-8"), object_pairs_hook=unique_fields)
            if not isinstance(value, dict) or not isinstance(value.get("line"), str):
                raise ValueError("expected an object with a string line")
            if set(value) != {"ts", "line"}:
                raise ValueError("expected exactly ts and line")
            if not isinstance(value["ts"], str) or not value["ts"].endswith("Z"):
                raise ValueError("expected UTC timestamps")
            result.append(Row(parse_stamp(value["ts"]), value["line"]))
        return result
    except (KeyError, ValueError) as exc:
        raise Rejected(f"invalid NDJSON response: {str(exc)[:200]}") from exc


class Bog:
    """Public CLI and HTTP binding used by every workload."""

    def __init__(self, binary, directory, log_path, *, flags=()):
        directory.mkdir(exist_ok=True)
        self.directory_name = directory.name
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            self.port = probe.getsockname()[1]
        self.log_path = log_path
        self.started = time.monotonic()
        with log_path.open("wb") as log:
            try:
                self.process = subprocess.Popen(
                    [str(binary), "-addr", f"127.0.0.1:{self.port}", "-data-dir", str(directory), *flags],
                    cwd=directory, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                )
            except (FileNotFoundError, PermissionError) as exc:
                raise Rejected(f"unable to launch Bog: {exc}") from exc

    def exchange(self, method, target, body=None, timeout=HTTP_TIMEOUT, *, connection=None):
        request_connection = (contextlib.nullcontext(connection) if connection is not None
                              else contextlib.closing(
                                  http.client.HTTPConnection("127.0.0.1", self.port, timeout=timeout)))
        with request_connection as conn:
            if body is None:
                conn.request(method, target)
            else:
                conn.putrequest(method, target)
                conn.putheader("Content-Type", "application/x-ndjson")
                conn.putheader("Content-Length", str(len(body)))
                conn.endheaders()
                try:
                    conn.send(body)
                except (BrokenPipeError, ConnectionResetError):
                    # A server can reject Content-Length before reading the body.
                    pass
            with conn.getresponse() as response:
                data = response.read(16 * 1024 * 1024 + 1)
                check(len(data) <= 16 * 1024 * 1024, f"{method} {target} exceeded response read cap")
                if response.status == 200 and target.startswith("/query?"):
                    media_type = response.headers.get_content_type()
                    check(media_type == "application/x-ndjson", f"query media type was {media_type}")
                return response.status, data, response.headers

    def request(self, method, target, body=None):
        status, data, _ = self.checked_exchange(method, target, body)
        return status, data

    def checked_exchange(self, method, target, body=None, *, connection=None, timeout=HTTP_TIMEOUT):
        try:
            return self.exchange(method, target, body, timeout=timeout, connection=connection)
        except (OSError, http.client.HTTPException) as exc:
            raise Rejected(f"{method} {target} failed: {exc}; {self.log_tail()}") from exc

    def log_tail(self):
        tail = " ".join(log_tail(self.log_path, 1200).split())
        return tail or "(empty process log)"

    def ready(self):
        return self.exchange("GET", "/healthz", timeout=0.2)[0] == 200

    def wait_startup(self, should_start):
        deadline = self.started + START_TIMEOUT
        while time.monotonic() < deadline:
            code = self.process.poll()
            if code is not None:
                check(not should_start and code > 0,
                      f"Bog exited during startup (status {code}): {self.log_tail()}")
                return None
            try:
                ready = self.ready()
            except (OSError, http.client.HTTPException):
                ready = False
            if ready:
                check(should_start, f"{self.directory_name}: Bog became ready when startup should have failed")
                check(self.process.poll() is None, f"Bog exited at readiness: {self.log_tail()}")
                return time.monotonic() - self.started
            time.sleep(0.005)
        expectation = "become ready" if should_start else "exit with a startup error"
        raise Rejected(f"Bog did not {expectation} in {START_TIMEOUT}s: {self.log_tail()}")

    def kill(self):
        check(self.process.poll() is None, f"Bog exited before SIGKILL: {self.log_tail()}")
        self.process.kill()
        check(self.process.wait(timeout=5) == -signal.SIGKILL, "Bog did not exit via SIGKILL")

    def graceful_stop(self, client, remainder):
        self.process.terminate()
        deadline = time.monotonic() + HTTP_TIMEOUT
        while time.monotonic() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=0.2):
                    pass
            except ConnectionRefusedError:
                break
            time.sleep(0.01)
        else:
            raise Rejected("SIGTERM did not close the HTTP listener")
        check(self.process.poll() is None, "SIGTERM exited before draining an active POST")
        client.send(remainder)
        with client.getresponse() as response:
            check(response.status == 204, f"active POST during SIGTERM returned HTTP {response.status}")
        self.wait_for_sigterm()

    def stop(self):
        self.process.terminate()
        self.wait_for_sigterm()

    def wait_for_sigterm(self):
        code = self.process.wait(timeout=HTTP_TIMEOUT)
        check(code == 0, f"SIGTERM did not produce a clean exit (status {code}): {self.log_tail()}")

    def close(self):
        if self.process.poll() is None:
            self.process.kill()
            self.process.wait(timeout=5)

    def ingest(self, rows):
        self.ingest_body(encode_rows(rows), len(rows))

    def ingest_body(self, payload, count, *, connection=None):
        status, body, _ = self.checked_exchange("POST", "/ingest", payload, connection=connection)
        check(status == 204, f"ingest of {count} rows returned {status}: {body[:200]!r}")

    @contextlib.contextmanager
    def open_ingest(self, length, expect_continue=False):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=HTTP_TIMEOUT)
        try:
            conn.putrequest("POST", "/ingest")
            conn.putheader("Content-Type", "application/x-ndjson")
            conn.putheader("Content-Length", str(length))
            if expect_continue:
                conn.putheader("Expect", "100-continue")
            conn.endheaders()
            if expect_continue:
                # The interim status is evidence the server began reading the body.
                header = bytearray()
                while not header.endswith(b"\r\n\r\n"):
                    chunk = conn.sock.recv(1)
                    check(chunk and len(header) < 4096, "no HTTP 100 Continue before request body")
                    header.extend(chunk)
                check(header.startswith(b"HTTP/1.1 100 "), f"unexpected interim status {header[:100]!r}")
            yield conn
        finally:
            conn.close()

    @contextlib.contextmanager
    def partial_ingest(self, rows):
        body = encode_rows(rows)
        with self.open_ingest(len(body), expect_continue=True) as conn:
            split = body.index(b"\n") + 1
            conn.send(body[:split])
            yield
            conn.send(body[split:])
            with conn.getresponse() as response:
                check(response.status == 204,
                      f"completed partial POST returned {response.status}")

    def query(self, start, end, contains="", limit=DEFAULT_QUERY_LIMIT, offset=0):
        rows, cursor = self.query_page(query_args(start, end, contains, limit, offset))
        check(cursor is None, f"legacy query returned {NEXT_CURSOR}")
        return rows

    def query_page(self, args):
        body, cursor = self.query_ndjson(args)
        return decode_rows(body), cursor

    def query_ndjson(self, args):
        status, body, headers = self.checked_exchange("GET", query_target(args))
        check(status == 200, f"query returned {status}: {body[:200]!r}")
        cursors = headers.get_all(NEXT_CURSOR)
        if cursors is not None:
            check(len(cursors) == 1 and bool(cursors[0].strip()),
                  f"expected a single nonempty {NEXT_CURSOR}")
        return body, cursors[0] if cursors else None


def query_args(start, end, contains="", limit=None, offset=0):
    args = {"start": stamp(start, offset), "end": stamp(end, offset)}
    if contains:
        args["contains"] = contains
    if limit is not None:
        args["limit"] = limit
    return args


def query_target(args):
    return "/query?" + urllib.parse.urlencode(args)


@contextlib.contextmanager
def run_bog(binary, directory, *, ready=True, flags=()):
    log_dir, cases = PROCESS_LOGS.get()
    path = log_dir / f"bog-{len(cases):02d}.log"
    case = {"store": directory.name, "log": str(path.relative_to(log_dir.parent)),
            "expected_ready": ready}
    cases.append(case)
    try:
        bog = Bog(binary, directory, path, flags=flags)
        try:
            bog.startup_seconds = bog.wait_startup(ready)
            case["ready_ms"] = milliseconds(bog.startup_seconds) if ready else None
            yield bog
        finally:
            bog.close()
            case["exit_code"] = bog.process.returncode
    finally:
        event = case.copy()
        if path.exists():
            event["log_tail"] = log_tail(path, 4096)
        print("BOG_PROCESS " + json.dumps(event, sort_keys=True))


def expect_rows(actual, expected, label):
    for index, (got, wanted) in enumerate(zip(actual, expected)):
        if got != wanted:
            # Raw lines can be large. Keep the termination message bounded.
            raise Rejected(f"{label}: row {index} differs, expected {repr(wanted)[:200]}, "
                           f"got {repr(got)[:200]}")
    check(len(actual) == len(expected), f"{label}: expected {len(expected)} rows, got {len(actual)}")


def oracle(rows, start, end, contains=""):
    # Callers flatten serially acknowledged batches, or use disjoint timestamp keys.
    # The stable sort retains batch order and then row order for equal instants.
    return sorted((row for row in rows if start <= row.ns < end and contains in row.line),
                  key=lambda row: row.ns)


def expect_query(bog, rows, start, end, *, contains="", limit=DEFAULT_QUERY_LIMIT, offset=0, label):
    expected = oracle(rows, start, end, contains)
    expect_rows(bog.query(start, end, contains, limit, offset),
                expected[:DEFAULT_QUERY_LIMIT if limit is None else limit], label)


def expect_page(bog, args, expected, position, limit, cursor, label):
    paging = {"page": "1"} if cursor is None else {"cursor": cursor}
    if limit is not None:
        paging["limit"] = limit
    page_label = f"{label}, row offset {position}, limit {limit}"
    try:
        actual, next_cursor = bog.query_page({**args, **paging})
    except Rejected as exc:
        raise Rejected(f"{page_label}: {exc}") from exc
    end = position + (DEFAULT_QUERY_LIMIT if limit is None else limit)
    expect_rows(actual, expected[position:end], page_label)
    check((next_cursor is not None) == (end < len(expected)),
          f"{page_label}: {NEXT_CURSOR} must be present exactly when rows remain")
    return next_cursor


def expect_walk(bog, args, expected, limits, label, *, position=0, cursor=None):
    for limit in itertools.cycle(limits):
        cursor = expect_page(bog, args, expected, position, limit, cursor, label)
        if cursor is None:
            return
        position += DEFAULT_QUERY_LIMIT if limit is None else limit


def expect_bad_query(bog, args, label):
    status, body, headers = bog.checked_exchange("GET", query_target(args))
    check(status == 400, f"{label}: expected HTTP 400, got {status}: {body[:150]!r}")
    check(headers.get_all(NEXT_CURSOR) is None, f"{label}: rejected query returned {NEXT_CURSOR}")


def expect_query_error(bog, args, expected, label, *, timeout=HTTP_TIMEOUT):
    started = time.monotonic()
    status, body, headers = bog.checked_exchange("GET", query_target(args), timeout=timeout)
    check(status == expected, f"{label}: expected HTTP {expected}, got {status}: {body[:150]!r}")
    if expected == 503:
        check(time.monotonic() - started < timeout, f"{label}: response took at least {timeout}s")
        check(headers.get_content_type() != "application/x-ndjson", f"{label}: error used NDJSON media type")
    check(headers.get_all(NEXT_CURSOR) is None, f"{label}: error returned {NEXT_CURSOR}")
    for line in body.split(b"\n"):
        try:
            value = json.loads(line)
        except ValueError:
            continue
        check(not (isinstance(value, dict) and {"ts", "line"} <= value.keys()),
              f"{label}: error returned an NDJSON row")


def load_corpus():
    raw = CORPUS_PATH.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != CORPUS_SHA256:
        raise InfrastructureError(f"replay corpus digest mismatch: {digest}")
    records = raw.split(b"\n")
    if records.pop() != b"":
        raise InfrastructureError("replay corpus is missing its final LF")
    rows = decode_rows(raw)
    ids = [row.line.split(" ", 1)[0] for row in rows]
    counts = Counter(record_id.split("-", 1)[0].removeprefix("id=") for record_id in ids)
    if len(records) != 2558 or len(ids) != 2558 or len(set(ids)) != 2558 or counts != CORPUS_SOURCES:
        raise InfrastructureError(f"replay corpus record count mismatch: {len(ids)} rows, {dict(counts)}")
    print(f"corpus records={len(rows)} sha256={digest} sources={dict(sorted(counts.items()))}")
    return records, rows


def load_apache():
    raw = APACHE_PATH.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != APACHE_SHA256:
        raise InfrastructureError(f"Apache fixture digest mismatch: {digest}")
    lines = raw.split(b"\n")
    if len(lines) != 257 or lines.pop() != b"" or len(set(lines)) != 256:
        raise InfrastructureError("expected 256 distinct LF-terminated Apache log lines")
    rows = []
    for record in lines:
        line = record.decode("utf-8")
        match = APACHE_STAMP.match(line)
        if not match:
            raise InfrastructureError(f"Apache log line has no timestamp: {line[:200]!r}")
        when = dt.datetime.strptime(match[1], "%d/%b/%Y:%H:%M:%S %z")
        delta = when - EPOCH
        rows.append(Row((delta.days * 86400 + delta.seconds) * SECOND, line))
    print(f"apache records={len(rows)} sha256={digest}")
    return rows


def replay_apache(binary, directory):
    rows = load_apache()
    random.Random(SEEDS["apache-replay"]).shuffle(rows)
    first = rows[0]
    start, end = min(row.ns for row in rows), max(row.ns for row in rows) + 1
    rows.extend([first, dataclasses.replace(first, offset=-450)])

    with run_bog(binary, directory) as bog:
        for index in range(0, len(rows), 32):
            bog.ingest(rows[index:index + 32])
        check_apache_queries(bog, rows, start, end, first.ns, "before restart")
        bog.kill()
    with run_bog(binary, directory) as bog:
        check_apache_queries(bog, rows, start, end, first.ns, "after restart")


def check_apache_queries(bog, rows, start, end, tied, phase):
    for left, right, literal, limit, offset in [
        (start, end, "", None, 0),
        (tied, tied + 1, "", 1000, 345),
        (start, end, "GET /Orders?", 9, -450),
        (start, end, "GET /orders?", 500, 0),
        (start, end, "q=a+b%26c&item=", 500, 0),
        (start, end, "[a.*]", 500, 0),
        (start, end, '" 404 ', 500, 0),
    ]:
        expect_query(bog, rows, left, right, contains=literal, limit=limit, offset=offset,
                     label=f"Apache {phase} [{left}, {right}), literal {literal!r}, limit {limit}")


def load_git_daemon():
    raw = GIT_DAEMON_PATH.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != GIT_DAEMON_SHA256:
        raise InfrastructureError(f"Git daemon fixture digest mismatch: {digest}")
    records = raw.split(b"\n")
    if records.pop() != b"" or len(records) != 203:
        raise InfrastructureError("expected 203 LF-terminated Git daemon log lines")
    rows = []
    for record in records:
        timestamp, line = record.decode("utf-8").split("\t", 1)
        rows.append(Row(parse_stamp(timestamp), line))
    return rows


def replay_git_daemon(binary, directory):
    rng = random.Random(SEEDS["git-daemon-replay"])
    capture = load_git_daemon()
    rare = "Request upload-pack for '/team/Missing-Catalog.git'"
    absent = "Request upload-pack for '/team/MISSING-CATALOG.git'"
    common = "upload-pack"
    if [sum(literal in row.line for row in capture) for literal in (rare, absent, common)] != [1, 0, 40]:
        raise InfrastructureError("Git daemon fixture does not cover the expected literal frequencies")
    start, end = min(row.ns for row in capture), max(row.ns for row in capture) + 1
    rows = capture.copy()
    rng.shuffle(rows)
    batches = [rows[index:index + 19] for index in range(0, len(rows), 19)]
    queries = [(start, end, text, limit, 0)
               for text in ("", rare, absent, common, "/", "'/team/") for limit in (7, 500)]
    for anchor in rng.sample(capture, 24):
        text = rng.choice(("", rare, absent, common, "/", "["))
        offset = rng.choice((0, -450, 345))
        # Include an actual record in a one-nanosecond window, then use it as the exclusive end.
        queries.append((anchor.ns, anchor.ns + 1, "", 3, offset))
        queries.append((anchor.ns - 1, anchor.ns, "", 3, offset))
        queries.append((max(start, anchor.ns - 20_000_000), min(end, anchor.ns + 20_000_000),
                        text, rng.choice((1, 17, 500)), offset))
    for replay in (False, True):
        with run_bog(binary, directory) as bog:
            if not replay:
                for batch in batches:
                    bog.ingest(batch)
            phase = "after restart" if replay else "before restart"
            for left, right, text, limit, offset in queries:
                expect_query(bog, rows, left, right, contains=text, limit=limit, offset=offset,
                             label=f"Git daemon {phase} [{left}, {right}), literal {text!r}, limit {limit}")
            bog.kill()


def reconcile_corpus(bog, rows, label, contains=""):
    expected = sorted(rows, key=lambda row: row.ns)
    # Adjacent windows share one endpoint and never split a timestamp group.
    bounds = [expected[0].ns - 1]
    for index in range(250, len(expected), 250):
        ns = expected[index].ns
        if ns > bounds[-1]:
            bounds.append(ns)
    bounds.append(expected[-1].ns + 1)
    results = []
    for start, end in zip(bounds, bounds[1:]):
        window = [row for row in expected if start <= row.ns < end and contains in row.line]
        if len(window) >= 500:
            raise InfrastructureError(f"corpus query window [{start}, {end}) exceeds its reconciliation budget")
        actual = bog.query(start, end, contains)
        expect_rows(actual, window, f"{label}, [{start}, {end})")
        results.extend(actual)
    expect_rows(results, [row for row in expected if contains in row.line], label)


def replay_corpus_suite(binary, directory):
    directory.mkdir()
    replay_apache(binary, directory / "apache")
    replay_git_daemon(binary, directory / "git-daemon")
    try:
        records, rows = load_corpus()
    except Rejected as exc:
        raise InfrastructureError(f"invalid archived corpus: {exc}") from exc
    start, end = min(row.ns for row in rows), max(row.ns for row in rows) + 1
    for replay in (False, True):
        with run_bog(binary, directory / "ndjson") as bog:
            if not replay:
                for index in range(0, len(records), 100):
                    batch = records[index:index + 100]
                    bog.ingest_body(b"\n".join(batch) + b"\n", len(batch))
            label = "archived corpus after restart" if replay else "archived corpus before restart"
            reconcile_corpus(bog, rows, label)
            for literal in ("Traceback (most recent call last):\n", "café", "東京", "🙂",
                            "q=a+b%26c", "level=ERROR", "level=error"):
                matches = sum(literal in row.line for row in rows)
                if matches == 0:
                    raise InfrastructureError(f"unexpected archived coverage for {literal!r}: {matches}")
                reconcile_corpus(bog, rows, f"{label}, literal {literal!r}", contains=literal)
            expect_query(bog, rows, start, end, limit=None, label=f"{label}, default limit")
            expect_query(bog, rows, start, end, limit=1000, label=f"{label}, maximum limit")
            bog.kill()


def corpus_suite(binary, directory):
    rng = random.Random(SEEDS["query-oracle"])
    access = [
        '192.0.2.{} - - [14/Mar/2025:12:00:00 +0000] "GET /v1/items?q=a+b&v=1 HTTP/1.1" 200 83',
        '198.51.100.{} - - [14/Mar/2025:12:00:00 +0000] "POST /login HTTP/1.1" 401 21',
    ]
    templates = access + [
        "level=ERROR service=orders trace={} café",
        "level=error service=orders trace={} café",
        'trace={} message="panic"\n\tat app.run()\r\nraw=C:\\logs [a.*] ☃\u0085\u2028\u2029tail',
    ]
    rows = [
        Row(rng.randrange(-20, 41), rng.choice(templates).format(i + 1),
            rng.choice([0, -450, 345]))
        for i in range(200)
    ]
    rows += [
        Row(7, "tie/z first", 345),
        Row(8, "exclusive endpoint"),
        Row(7, "tie/a second", -450),
        Row(6, "just before start"),
        Row(7, "tie/z first", 345),  # Identical wire record in another POST.
        Row(SECOND + 1, "next second"),
    ]
    # Put the first two ties in different POSTs and the duplicate in a third.
    batches = [rows[:202], rows[202:204], rows[204:]]
    far_past = Row(parse_stamp("0001-01-01T00:00:00.000000001Z"), "earliest supported year")
    far_future = Row(parse_stamp("9999-12-31T23:59:59.999999998Z"), "latest supported year")
    with run_bog(binary, directory) as bog:
        expect_query(bog, [], -100, 100, label="fresh database")
        for batch in batches:
            bog.ingest(batch)
        bog.ingest([far_future, far_past])
        expect_query(bog, rows + [far_past, far_future], far_past.ns, far_future.ns + 1,
                     label="nanosecond ordering beyond signed Unix nanoseconds")
        for start, end, substring, limit, offset, label in [
            (-21, SECOND + 2, "", 500, 0, "full seeded corpus"),
            (7, 8, "tie/", 500, 345, "one nanosecond, offsets, ties and duplicates"),
            (6, 8, "", 500, -450, "half-open endpoints"),
            (7, 8, "tie/", 2, 0, "limit inside equal timestamps"),
            (7, 7, "", 500, 0, "equal query bounds"),
            (-21, 41, "level=ERROR", 7, 0, "case-sensitive filter before limit"),
            (-21, 41, "level=error", 500, 0, "lowercase filter"),
            (-21, 41, "\n\tat", 500, 0, "decoded newline and tab"),
            (-21, 41, "\u0085\u2028\u2029", 500, 0, "Unicode separators inside NDJSON strings"),
            (-21, 41, "[a.*]", 500, 0, "literal punctuation"),
            (-21, 41, "q=a+b&v=1", 500, 0, "encoded query parameters"),
            (-21, 41, "MISSING-0447", 500, 0, "unmatched filter"),
            (41, SECOND + 1, "", 500, 0, "empty time window"),
        ]:
            expect_query(bog, rows, start, end, contains=substring, limit=limit,
                         offset=offset, label=label)
        for _ in range(24):
            start = rng.randrange(-24, 41)
            end = start + rng.randrange(1, 24)
            expect_query(bog, rows, start, end,
                         contains=rng.choice(["", "level=", "401", "trace=", "é", "tie/"]),
                         limit=rng.choice([1, 3, 17, 500]), offset=rng.choice([0, 345, -450]),
                         label=f"seeded window [{start}, {end})")
        bog.kill()
    with run_bog(binary, directory) as bog:
        expect_query(bog, rows, -21, SECOND + 2, label="full corpus after replay")
        expect_query(bog, rows, 7, 8, contains="tie/", limit=2, label="tied limit after replay")
        expect_query(bog, rows + [far_past, far_future], far_past.ns, far_future.ns + 1,
                     label="wide nanosecond ordering after replay")


def pagination_suite(binary, directory):
    rng = random.Random(SEEDS["snapshot-pagination"])
    unix = parse_stamp("1970-01-01T00:00:00Z")
    beginning = parse_stamp("0001-01-01T00:00:00Z")
    end_of_time = parse_stamp("9999-12-31T23:59:59.999999999Z")
    minute = 60 * SECOND
    snapshot_start = 36 * minute
    exact = "exact-page [a.*]"
    identifiers = list(range(2021))
    rng.shuffle(identifiers)
    tied = [Row(11, f"{exact if position < 2000 else 'EXACT-PAGE'} tied/{identifier:04d}",
                rng.choice([0, -450, 345])) for position, identifier in enumerate(identifiers)]
    # Identical rows straddle a full page and also cross a POST boundary.
    tied[999] = tied[1000] = Row(11, f"{exact} identical record", 345)

    logs = [
        Row(beginning, "minimum UTC instant"),
        Row(end_of_time - 1, "last ingestible UTC instant"),
        Row(unix - 1, "last pre-epoch nanosecond", 345),
        Row(unix, "Unix epoch", -450),
        Row(9, '192.0.2.7 - - [14/Mar/2025:12:00:00 +0000] "GET /v1?q=a+b%26c HTTP/1.1" 200 109'),
        Row(10, "<34>1 2025-03-14T12:00:00Z edge sshd 510 - - ERROR Café"),
        Row(10, "<34>1 2025-03-14T12:00:00Z edge sshd 511 - - error Café"),
        Row(12, '{"severity":"error","query":"a+b%26c","service":"orders"}'),
        Row(13, 'Traceback (most recent call last):\n\tat app.run()\r\nC:\\logs [a.*]'),
    ]
    logs += [Row(i * minute + ns, f"cutoff/{i}/{ns:+d}", -450)
             for i in (0, 30, 31, 32, 33) for ns in (-1, 0, 1)]
    logs += [Row(snapshot_start + i, f"original snapshot row {i}")
             for i in (40, 10, 70, 20, 60, 90)]
    rng.shuffle(logs)
    batches = [tied[:1000] + logs[:10], tied[1000:1513] + logs[10:], tied[1513:]]
    rows = list(itertools.chain.from_iterable(batches))
    cases = [
        (beginning, end_of_time, "", (1000,), "full UTC domain"),
        (11, 12, "", (1000, 1, 137), "more than 1000 rows at one instant"),
        (11, 12, exact, (1000,), "exactly two full pages of literal matches"),
        (9, 14, "a+b%26c", (1,), "literal URL punctuation with one row per page"),
        (9, 14, "ERROR Café", (1,), "exactly one full page of syslog matches"),
        (9, 14, "error Café", (1,), "lowercase syslog"),
        (9, 14, "ERROR CAFÉ", (1000,), "absent case-sensitive match"),
        (9, 14, '"severity":"error"', (1,), "structured JSON text"),
        (13, 14, "\n\tat app.run()", (1,), "decoded stack trace"),
        (11, 11, "", (1,), "equal time bounds"),
        (unix - 1, unix + 1, "", (1,), "pre-epoch nanoseconds"),
    ]
    for width in (31, 32, 33):
        for ns in (0, 1):
            cases.append((0, width * minute + ns, "cutoff/", (1, 3),
                          f"old cutoff at {width} minutes plus {ns}ns"))

    with run_bog(binary, directory) as bog:
        for batch in batches:
            bog.ingest(batch)
        for start, end, literal, limits, label in cases:
            expect_query(bog, rows, start, end, contains=literal, limit=limits[0], label=f"legacy {label}")
            expect_walk(bog, query_args(start, end, literal),
                        oracle(rows, start, end, literal), limits, label)

        args = query_args(11, 12)
        expected = oracle(rows, 11, 12)
        saved = expect_page(bog, args, expected, 0, None, None, "paged default limit")
        shifted = {**query_args(11, 12, offset=345), "contains": ""}
        expect_walk(bog, shifted, expected, (1000,), "equivalent UTC bounds with explicit empty filter",
                    position=DEFAULT_QUERY_LIMIT, cursor=saved)
        middle = len(saved) // 2
        tampered = saved[:middle] + ("B" if saved[middle] == "A" else "A") + saved[middle + 1:]
        continuation = {**args, "cursor": saved}
        for params, label in [
            ({**args, "page": "0"}, "invalid page selector"),
            ({**args, "page": ""}, "empty page selector"),
            ({**args, "cursor": ""}, "empty cursor"),
            ({**continuation, "page": "1"}, "page and cursor together"),
            ({**continuation, "cursor": "?malformed"}, "malformed cursor"),
            ({**continuation, "cursor": tampered}, "tampered cursor"),
            ({**continuation, "start": stamp(10)}, "cursor with changed start"),
            ({**continuation, "end": stamp(13)}, "cursor with changed end"),
            ({**continuation, "contains": "tied"}, "cursor with changed filter"),
            ({**continuation, "limit": 1001}, "cursor with invalid limit"),
            ({key: value for key, value in continuation.items() if key != "end"}, "cursor without end"),
        ]:
            expect_bad_query(bog, params, label)

        snapshot_end = snapshot_start + 101
        snapshot_args = query_args(snapshot_start, snapshot_end)
        snapshot_shifted = query_args(snapshot_start, snapshot_end, offset=-450)
        original = oracle(rows, snapshot_start, snapshot_end)
        active = expect_page(bog, snapshot_args, original, 0, 2, None, "first page before backfill")
        late = [Row(snapshot_start + i, f"backfilled snapshot row {i}") for i in (100, 60, 30, 5, 15, 20)]
        late.append(Row(11, "backfilled row at the cursor's timestamp"))
        pending = [Row(snapshot_start + i, f"concurrent backfill row {i}") for i in (55, 1, 95)]
        with bog.partial_ingest(pending):
            bog.ingest(late)
            expect_walk(bog, snapshot_shifted, original, (1, 3), "active walk during backfill",
                        position=2, cursor=active)
            expect_walk(bog, shifted, expected, (1, 1000), "active tied walk during backfill",
                        position=DEFAULT_QUERY_LIMIT, cursor=saved)
            interim = oracle(rows + late, snapshot_start, snapshot_end)
            second_cursor = expect_page(bog, snapshot_shifted, interim, 0, 3, None,
                                        "first page during unfinished backfill")
        expect_walk(bog, snapshot_args, interim, (1, 4), "walk across completion of backfill",
                    position=3, cursor=second_cursor)
        rows.extend(late)
        rows.extend(pending)
        expect_walk(bog, snapshot_args, oracle(rows, snapshot_start, snapshot_end),
                    (2, 1, 1000), "fresh walk after backfill")
        expect_walk(bog, args, oracle(rows, 11, 12), (1000,), "fresh tied walk after backfill")
        bog.kill()

    with run_bog(binary, directory) as bog:
        expect_bad_query(bog, continuation, "cursor from the previous process")
        expect_bad_query(bog, {**snapshot_args, "cursor": active}, "backfill cursor from the previous process")
        expect_bad_query(bog, {**snapshot_args, "cursor": second_cursor},
                         "cursor opened during backfill from the previous process")
        expect_walk(bog, query_args(beginning, end_of_time), oracle(rows, beginning, end_of_time),
                    (1000,), "fresh full walk after WAL replay")


def advertised_flags(binary, directory):
    help_result = subprocess.run(
        [str(binary), "-help"], cwd=directory.parent, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace", timeout=START_TIMEOUT,
    )
    check(help_result.returncode == 0,
          f"Bog -help exited with status {help_result.returncode}: {help_result.stdout[-200:]!r}")
    return set(re.findall(r"^[ \t]*(-[a-z0-9-]+)(?=[ \t=]|$)", help_result.stdout, re.MULTILINE))


def query_limits_suite(binary, directory):
    if "-query-work-budget" not in advertised_flags(binary, directory):
        return SuiteSkipped("Bog -help does not list -query-work-budget")

    directory.mkdir()
    budget = 32
    first = Row(1, "@ first match")
    second = Row(2, "@ second match")
    last = Row(4 * budget, "@ late match")
    # A one-character filter cannot use the four-byte Bloom summaries.
    gap = [Row(ns, "scan gap") for ns in range(3, last.ns)]
    args = query_args(0, last.ns + 1, "@")
    with run_bog(binary, directory / "work-budget", flags=(f"-query-work-budget={budget}",)) as bog:
        bog.ingest([first, second, *gap, last])
        expect_rows(bog.query(0, last.ns + 1, "@", limit=2), [first, second],
                    "ordinary query fits the work budget")
        cursor = expect_page(bog, args, [first, second, last], 0, 1, None, "first page fits budget")
        expect_query_error(bog, {**args, "limit": 3}, 422, "ordinary query exceeds work budget")
        expect_query_error(bog, {**args, "limit": 2, "page": "1"}, 422,
                           "first page exceeds work budget during lookahead")
        expect_query_error(bog, {**args, "limit": 1, "cursor": cursor}, 422,
                           "continuation exceeds work budget during lookahead")
        expect_rows(bog.query(last.ns, last.ns + 1, "@"), [last], "query after budget rejection")


def query_admission_suite(binary, directory):
    if "-query-concurrency" not in advertised_flags(binary, directory):
        reason = "Bog -help does not list -query-concurrency"
        check(os.environ.get("SLIPWAY_PARAM_REQUIRE_QUERY_ADMISSION") != "1",
              f"{reason}; required for #19 verification")
        return SuiteSkipped(reason)

    small = [Row(ns, f"original/{ns}") for ns in (10, 30, 50)]
    backfill = [Row(20, "backfill between pages"), Row(30, "backfill at original timestamp")]
    args = query_args(0, 100)
    # Each control byte takes six bytes in JSON. This fills the TCP send
    # buffer without exceeding the older 16 MiB estimated response limit.
    padding = "\x01" * (192 * 1024)
    wide = [Row(ns, padding) for ns in range(100, 112)]
    flags = ("-query-concurrency=1",)
    with run_bog(binary, directory, flags=flags) as bog:
        bog.ingest(small)
        for start in range(0, len(wide), 3):
            bog.ingest(wide[start:start + 3])
        cursor = expect_page(bog, args, small, 0, 1, None, "first page before saturation")
        with socket.socket() as peer, contextlib.closing(
                http.client.HTTPConnection("127.0.0.1", bog.port, timeout=HTTP_TIMEOUT)) as client:
            peer.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8192)
            peer.settimeout(HTTP_TIMEOUT)
            peer.connect(("127.0.0.1", bog.port))
            client.sock = peer
            client.request("GET", query_target(query_args(100, 112)))
            with client.getresponse() as held:
                check(held.status == 200 and held.read(1) == b"{",
                      f"query used to hold the slot did not start an NDJSON response (HTTP {held.status})")
                expect_query_error(bog, args, 503, "ordinary query during saturation", timeout=2)
                expect_query_error(bog, {**args, "page": "1", "limit": 1}, 503,
                                   "first page during saturation", timeout=2)
                check(bog.request("GET", "/healthz")[0] == 200, "health failed during query saturation")
                bog.ingest(backfill)
                expect_query_error(bog, {**args, "cursor": cursor, "limit": 1}, 503,
                                   "continuation during saturation after acknowledged backfill", timeout=2)

        deadline = time.monotonic() + HTTP_TIMEOUT
        expected = oracle(small + backfill, 0, 100)
        while True:
            remaining = deadline - time.monotonic()
            check(remaining > 0, "closed query did not release its slot")
            status, body, headers = bog.checked_exchange("GET", query_target(args), timeout=remaining)
            if status != 503:
                check(status == 200, f"query after slot release returned {status}: {body[:150]!r}")
                check(headers.get_all(NEXT_CURSOR) is None, f"ordinary retry returned {NEXT_CURSOR}")
                expect_rows(decode_rows(body), expected, "ordinary retry after slot release")
                break
            time.sleep(0.01)
        expect_walk(bog, args, small, (1,), "captured snapshot after saturated backfill",
                    position=1, cursor=cursor)
        expect_walk(bog, args, expected, (1,), "fresh snapshot after backfill")
        bog.kill()

    with run_bog(binary, directory, flags=flags) as bog:
        expect_rows(bog.query(0, 100), expected, "acknowledged backfill after SIGKILL and restart")


def query_response_bytes_suite(binary, directory):
    flag = "-query-max-response-bytes"
    if flag not in advertised_flags(binary, directory):
        reason = f"Bog -help does not list {flag}"
        check(os.environ.get("SLIPWAY_PARAM_REQUIRE_QUERY_RESPONSE_BYTES") != "1", reason)
        return SuiteSkipped(reason)

    directory.mkdir()
    escaped = '"\\\n\té' * 48
    first = Row(2, "hit/a " + escaped)
    duplicate = Row(2, "hit/b " + escaped)
    fourth = Row(2, "hit/c " + escaped)
    last = Row(3, "hit/end")
    original = [first, duplicate, duplicate, fourth, last]
    backfill = [Row(1, "hit/early backfill"), Row(2, "hit/tied backfill")]
    args = query_args(0, 4, "hit/", limit=10)
    oversized_base = Row(4, "hit/oversized " + escaped)
    oversized_args = query_args(4, 6, "hit/", limit=10)

    def expect_ndjson(bog, params, expected, label):
        body, cursor = bog.query_ndjson(params)
        check(body.endswith(b"\n") and body.count(b"\n") == len(expected),
              f"{label}: expected {len(expected)} complete newline-terminated records")
        expect_rows(decode_rows(body), expected, label)
        return body, cursor

    # Measure actual response framing and escaping with space for both records.
    with run_bog(binary, directory / "measure", flags=(f"{flag}=4096",)) as bog:
        bog.ingest([first, duplicate, oversized_base])
        prefix, _ = expect_ndjson(bog, args, original[:2], "measure prefix")
        oversized_wire, _ = expect_ndjson(bog, oversized_args, [oversized_base], "measure oversized row")
    cap = len(prefix)
    padding = cap + 1 - len(oversized_wire)
    if padding <= 0:
        raise InfrastructureError("response byte cap fixture has no room for oversized row padding")
    oversized = Row(oversized_base.ns, oversized_base.line + "x" * padding)

    with run_bog(binary, directory / "capped", flags=(f"{flag}={cap}",)) as bog:
        bog.ingest(original[:2])
        bog.ingest([*original[2:], oversized, Row(5, "hit/after oversized row")])
        body, cursor = expect_ndjson(bog, args, original[:2], "ordinary byte-limited prefix")
        check(len(body) == cap, f"ordinary prefix used {len(body)} bytes, expected {cap}")
        check(cursor is None, f"ordinary prefix returned {NEXT_CURSOR}")
        for paging in ({}, {"page": "1"}):
            expect_query_error(bog, {**oversized_args, **paging}, 422,
                               f"{'paged' if paging else 'ordinary'} oversized first match")

        params = {**args, "page": "1"}
        for start, end in ((0, 2), (2, 4), (4, 5)):
            label = f"byte-limited snapshot at row offset {start}"
            body, cursor = expect_ndjson(bog, params, original[start:end], label)
            check(len(body) <= cap, f"{label}: returned {len(body)} bytes with a cap of {cap}")
            check((cursor is not None) == (end < len(original)),
                  f"{label}: {NEXT_CURSOR} must be present exactly when rows remain")
            if start == 0:
                bog.ingest(backfill)
            params = {**args, "cursor": cursor}

        expect_walk(bog, args, oracle(original + backfill, 0, 4, "hit/"), (1,),
                    "fresh snapshot sees both matching backfills")


def rejection_suite(binary, directory):
    good = [Row(1, "acknowledged before bad ingest")]
    prefix = encode_rows([Row(2, "must never commit")])
    valid_ts = stamp(3).encode()
    limit_rows = [Row(100 + i, f"body size limit row={i:03} " + "x" * (256_000 if i == 0 else 30_000))
                  for i in range(128)]
    padding, extra = divmod(MAX_FRAME - len(encode_rows(limit_rows)), len(limit_rows))
    limit_rows = [dataclasses.replace(row, line=row.line + "x" * (padding + (i < extra)))
                  for i, row in enumerate(limit_rows)]
    at_limit = encode_rows(limit_rows)
    if len(at_limit) != MAX_FRAME:
        raise InfrastructureError("the boundary fixture is not exactly 4 MiB")
    with run_bog(binary, directory) as bog:
        bog.ingest(good)
        query = "/query?" + urllib.parse.urlencode({"start": stamp(0), "end": stamp(5)})
        for method, path, body in [
            ("GET", "/ingest", prefix),
            ("PUT", "/ingest", prefix),
            ("POST", query, prefix),
            ("DELETE", query, None),
            ("POST", "/healthz", None),
        ]:
            status, response = bog.request(method, path, body)
            check(status == 405, f"{method} {path}: expected HTTP 405, got {status}: {response[:200]!r}")
        expect_query(bog, good, 0, 5, label="wrong methods did not publish data")
        for label, status, body in [
            ("invalid JSON after valid record", 400, prefix + b'{"ts":'),
            ("trailing JSON value", 400, prefix + encode_rows([Row(3, "trailing")]).rstrip() + b" null\n"),
            ("invalid timestamp", 400, prefix + b'{"ts":"yesterday","line":"bad"}\n'),
            ("missing timestamp zone", 400, prefix + b'{"ts":"2025-03-14T12:00:00","line":"x"}\n'),
            ("reserved exclusive end", 400,
             prefix + b'{"ts":"9999-12-31T23:59:59.999999999Z","line":"bad"}\n'),
            ("wrong line type", 400, prefix + b'{"ts":"' + valid_ts + b'","line":42}\n'),
            ("null line", 400, prefix + b'{"ts":"' + valid_ts + b'","line":null}\n'),
            ("missing line", 400, prefix + b'{"ts":"' + valid_ts + b'"}\n'),
            ("extra field", 400, prefix + b'{"ts":"' + valid_ts + b'","line":"x","extra":1}\n'),
            ("duplicate field", 400, prefix + b'{"ts":"' + valid_ts + b'","line":"x","line":"y"}\n'),
            ("invalid UTF-8", 400, prefix + b'{"ts":"' + valid_ts + b'","line":"\xff"}\n'),
            ("lone high surrogate", 400, prefix + b'{"ts":"' + valid_ts + b'","line":"\\ud800x"}\n'),
            ("lone low surrogate", 400, prefix + b'{"ts":"' + valid_ts + b'","line":"\\udfff"}\n'),
            ("reversed surrogate pair", 400, prefix + b'{"ts":"' + valid_ts + b'","line":"\\ude42\\ud83d"}\n'),
            ("surrogate in timestamp", 400, prefix + b'{"ts":"\\ud800","line":"invalid"}\n'),
            ("surrogate in field name", 400, prefix + b'{"ts":"' + valid_ts + b'","\\ud800":"invalid"}\n'),
            ("empty body", 400, b""),
            ("blank body", 400, b"\n\r\n"),
            ("request one byte above 4 MiB", 413, at_limit + b" "),
        ]:
            got, response = bog.request("POST", "/ingest", body)
            check(got == status, f"{label}: expected HTTP {status}, got {got}: {response[:200]!r}")
            # Use a small limit to detect a partial prefix without downloading oversized data.
            expect_query(bog, good, 0, 5, limit=8, label=label)
        with contextlib.closing(http.client.HTTPConnection("127.0.0.1", bog.port, timeout=HTTP_TIMEOUT)) as client:
            chunks = (at_limit[start:start + 65_536] for start in range(0, len(at_limit), 65_536))
            client.request("POST", "/ingest", itertools.chain(chunks, (b" ",)), encode_chunked=True,
                           headers={"Content-Type": "application/x-ndjson"})
            with client.getresponse() as response:
                check(response.status == 413, f"chunked request one byte above 4 MiB returned {response.status}")
        for label, args in [
            ("bad start timestamp", {"start": "yesterday"}),
            ("bad end timestamp", {"end": "yesterday"}),
            ("reversed bounds", {"start": stamp(6)}),
            ("nonnumeric limit", {"limit": "many"}),
            ("negative limit", {"limit": "-1"}),
            ("zero limit", {"limit": "0"}),
            ("limit above maximum", {"limit": "1001"}),
            ("missing start", {"start": None}),
            ("missing end", {"end": None}),
        ]:
            params = {"start": stamp(0), "end": stamp(5), "limit": 10}
            params.update(args)
            params = {key: value for key, value in params.items() if value is not None}
            got, response = bog.request("GET", "/query?" + urllib.parse.urlencode(params))
            check(got == 400, f"{label}: expected HTTP 400, got {got}: {response[:200]!r}")
        valid = [Row(3, "literal � and \\ud800"), Row(3, "paired 🙂\x00\t\r\n"), Row(4, "")]
        wire = (encode_rows(valid[:1]).replace(b"\n", b"\r\n") + b"\n"
                + b'{"ts":"' + valid_ts + b'","line":"paired \\uD83d\\udE42\\u0000\\t\\r\\n"}\n'
                + encode_rows(valid[2:]).rstrip(b"\n"))
        bog.ingest_body(wire, len(valid))
        good.extend(valid)
        expect_query(bog, good, 0, 6, label="post-rejection service, blanks and optional LF")

        # The header promises another row, but the client closes after a complete first row.
        with bog.open_ingest(len(prefix) + len(wire)) as client:
            client.send(prefix)
            client.sock.shutdown(socket.SHUT_WR)
            try:
                with client.getresponse() as response:
                    check(response.status >= 400, f"truncated POST received HTTP {response.status}")
            except http.client.RemoteDisconnected:
                pass
        expect_query(bog, good, 0, 6, label="client disconnect committed nothing")
        expect_rows(bog.query(100, 228), [], "oversized body committed nothing")
        bog.ingest_body(at_limit, len(limit_rows))
        expect_rows(bog.query(100, 228), limit_rows, "exactly 4 MiB request")
        bog.kill()
    with run_bog(binary, directory) as bog:
        expect_query(bog, good, 0, 6, label="rejected and truncated batches stayed absent after restart")
        expect_rows(bog.query(100, 228), limit_rows, "exactly 4 MiB request after restart")


def make_batches(name, count, size, spacing=1):
    return [
        [
            Row(((count - batch_id - 1) * size + index) * spacing,
                f"level=INFO operation={name} batch={batch_id:03}/{name} row={index:03} "
                f'message="request finished" path=/v1/items status={200 + index % 5}')
            for index in range(size)
        ]
        for batch_id in range(count)
    ]


def concurrency_suite(binary, directory):
    writers = 8
    batches = [
        [dataclasses.replace(row, ns=batch[0].ns if index < 4 else row.ns)
         for index, row in enumerate(batch)]
        for batch in make_batches("snapshot", 24, 16)
    ]
    batch_by_row = {row: i for i, batch in enumerate(batches) for row in batch}
    if sum(map(len, batches)) + 2 >= DEFAULT_QUERY_LIMIT:
        raise InfrastructureError("snapshot fixtures exceed the query limit")
    end = len(batch_by_row) + 1
    lock = threading.Lock()
    invoked = set()
    acknowledged = set()
    go = threading.Barrier(writers + 1)
    first_invoked = [threading.Event() for _ in range(writers)]
    reader_started = threading.Event()

    def inspect_snapshot(actual, label):
        check(all(row in batch_by_row for row in actual), f"{label}: contained unknown rows")
        seen = {batch_by_row[row] for row in actual}
        # Each writer has disjoint timestamp keys. Only serial ingests assert order across tied batches.
        expected = oracle((row for i in seen for row in batches[i]), 0, end)
        expect_rows(actual, expected, f"{label}: all rows from visible batches in timestamp and row order")
        return seen

    with run_bog(binary, directory) as bog, ThreadPoolExecutor(max_workers=writers) as pool:
        def write(worker):
            go.wait(timeout=HTTP_TIMEOUT)
            for batch_id in range(worker, len(batches), writers):
                with lock:
                    invoked.add(batch_id)
                first_invoked[worker].set()
                check(reader_started.wait(HTTP_TIMEOUT), "snapshot reader did not start")
                bog.ingest(batches[batch_id])
                with lock:
                    acknowledged.add(batch_id)
                seen = inspect_snapshot(bog.query(0, end), f"query immediately after POST {batch_id}")
                check(batch_id in seen, f"POST {batch_id} was acknowledged before publishing its batch")

        futures = [pool.submit(write, worker) for worker in range(writers)]
        go.wait(timeout=HTTP_TIMEOUT)
        for event in first_invoked:
            check(event.wait(HTTP_TIMEOUT), "writer did not reach the first snapshot")
        previous = set()
        for sample in range(128):
            with lock:
                must_see = set(acknowledged)
            reader_started.set()
            actual = bog.query(0, end)
            with lock:
                may_see = set(invoked)
            seen = inspect_snapshot(actual, f"snapshot {sample}")
            check(must_see <= seen <= may_see, f"snapshot {sample} violated POST invocation/ack bounds")
            check(previous <= seen, f"snapshot {sample} lost an already visible batch")
            previous = seen
            if all(future.done() for future in futures):
                break
        for future in futures:
            future.result(timeout=HTTP_TIMEOUT)
        all_rows = bog.query(0, end)
        check(inspect_snapshot(all_rows, "all concurrent writes") == set(range(len(batches))),
              "final snapshot missed acknowledged batches")
        expect_rows(bog.query(0, 1, limit=2), batches[-1][:2], "limit within row-order ties")
        pending = [Row(end, "visible when complete/first"), Row(end + 1, "visible when complete/last")]
        with bog.partial_ingest(pending):
            readers = [
                pool.submit(expect_query, bog, all_rows, 0, end + 2,
                            label=f"reader {reader}, snapshot during an unfinished POST")
                for reader in range(2)
            ]
            for reader in readers:
                reader.result(timeout=HTTP_TIMEOUT)
        expect_query(bog, all_rows + pending, 0, end + 2, label="snapshot after completing the POST")
        bog.kill()
    with run_bog(binary, directory) as bog:
        expect_rows(bog.query(0, end + 2), all_rows + pending, "all concurrent writes after replay")
        expect_rows(bog.query(0, 1, limit=2), batches[-1][:2], "limit within row-order ties after replay")


def lock_suite(binary, directory):
    rows = [Row(1, "owner must retain data while lock contender exits")]
    with run_bog(binary, directory) as owner:
        owner.ingest(rows)
        with run_bog(binary, directory, ready=False):
            pass
        expect_query(owner, rows, 0, 2, label="original lock owner")
        owner.kill()
    with run_bog(binary, directory) as successor:
        expect_query(successor, rows, 0, 2, label="directory reusable after SIGKILL")


def shutdown_suite(binary, directory):
    history = [Row(1, "acknowledged before SIGTERM")]
    drained = [Row(4, "active POST with SIGTERM"), Row(2, "late row drained on shutdown")]
    body = encode_rows(drained)
    split = len(encode_rows(drained[:1]))
    with run_bog(binary, directory) as bog:
        bog.ingest(history)
        with bog.open_ingest(len(body), expect_continue=True) as client:
            client.send(body[:split])
            expect_query(bog, history, 0, 5, label="active POST before SIGTERM")
            bog.graceful_stop(client, body[split:])
    with run_bog(binary, directory) as bog:
        expect_query(bog, history + drained, 0, 5, label="durably drained POST after SIGTERM")


def durability_suite(binary, directory, *, rounds=24, paged=True):
    seed = SEEDS["kill-durability"]
    rng = random.Random(seed)
    lower = parse_stamp("0001-01-01T00:00:00Z")
    upper = parse_stamp("9999-12-31T23:59:59.999999999Z")
    outcomes = ["acknowledged"] * 3 + ["rejected"] * 2 + ["incomplete"] * 2 + ["unknown"] * 4
    history = []
    recovered_unknown = Counter()
    log_dir, _ = PROCESS_LOGS.get()
    ledger = log_dir / "ledger.jsonl"

    def record(event):
        wire = json.dumps(event, sort_keys=True)
        with ledger.open("ab") as stream:
            offset = stream.tell()
            stream.write((wire + "\n").encode())
            stream.flush()
            os.fsync(stream.fileno())
        print("BOG_SIGKILL " + wire, flush=True)
        return offset

    def read_event(offset, trial, name):
        with ledger.open("rb") as stream:
            stream.seek(offset)
            event = json.loads(stream.readline())
        if event["trial"] != trial or event["event"] != name:
            raise InfrastructureError(f"expected {name} for trial {trial} in the crash ledger")
        return event["requests"]

    for trial in range(1, rounds + 1):
        delay = rng.choice((0, 0.0002, 0.0006, 0.002, 0.006))
        tag = f"crash/{seed:04x}/{trial:02}"
        outcomes_this_round = rng.sample(outcomes, len(outcomes))
        requests = {}
        for slot, outcome in enumerate(outcomes_this_round):
            batch = f"{tag}/{slot:02}"
            base = -trial * 256 + slot * 16
            times = rng.sample(range(1, 16), rng.randint(2, 5))
            times[1] = times[0]  # Preserve row order at ties within a request.
            padding = rng.randint(128, 512)
            if outcome == "unknown" and trial % 4 == 0:
                padding *= 32
            rows = [Row(base + ns, f"{batch}/row/{i:02} " + "x" * padding)
                    for i, ns in enumerate(times)]
            payload = encode_rows(rows)
            if outcome == "rejected":
                payload += b'{"ts":'
            entry = {"batch": batch, "outcome": outcome, "status": None,
                     "row_count": len(rows), "timestamps_ns": [row.ns for row in rows], "padding": padding,
                     "declared_bytes": len(payload), "payload_sha256": hashlib.sha256(payload).hexdigest()}
            requests[batch] = rows, payload, entry
        entries = [entry for _, _, entry in requests.values()]
        event = {"trial": trial, "seed": seed, "delay_ms": delay * 1000}
        record({**event, "event": "plan", "requests": entries})

        with run_bog(binary, directory) as bog, contextlib.ExitStack() as sockets, \
             ThreadPoolExecutor(max_workers=5) as pool:
            unknown = []
            for _, payload, entry in requests.values():
                if entry["outcome"] in ("incomplete", "unknown"):
                    client = sockets.enter_context(bog.open_ingest(len(payload), expect_continue=True))
                    if entry["outcome"] == "incomplete":
                        uploaded = payload.index(b"\n") + 1
                        client.send(payload[:uploaded])
                        entry["uploaded_bytes"] = uploaded
                    else:
                        unknown.append((client, payload, entry))

            controls = [(payload, entry) for _, payload, entry in requests.values()
                        if entry["outcome"] in ("acknowledged", "rejected")]
            start_controls = threading.Barrier(len(controls))

            def observe_response(payload, entry):
                start_controls.wait(timeout=HTTP_TIMEOUT)
                status, _ = bog.request("POST", "/ingest", payload)
                entry.update(uploaded_bytes=len(payload), status=status)
                expected = 204 if entry["outcome"] == "acknowledged" else 400
                check(status == expected, f"{entry['batch']}: expected HTTP {expected}, got {status}")

            futures = [pool.submit(observe_response, payload, entry) for payload, entry in controls]
            for future in futures:
                future.result()
            receipt_offset = record({**event, "event": "receipts",
                                     "requests": [entry for _, entry in controls]})

            start_unknown = threading.Barrier(len(unknown))

            def send_without_reading(client, payload, entry):
                start_unknown.wait(timeout=HTTP_TIMEOUT)
                client.send(payload)
                entry["uploaded_bytes"] = len(payload)

            futures = [pool.submit(send_without_reading, *request) for request in unknown]
            for future in futures:
                future.result()
            if delay:
                time.sleep(delay)
            for client, _, entry in unknown:
                entry["socket_readable_before_kill"] = bool(select.select([client.sock], [], [], 0)[0])
            bog.kill()
            kill_offset = record({**event, "event": "killed", "signal": "SIGKILL", "requests": entries})

        with run_bog(binary, directory) as bog:
            trial_start = -trial * 256
            actual = bog.query(trial_start, trial_start + 256, limit=MAX_QUERY_LIMIT)
            counts = Counter(actual)
            receipts = {entry["batch"]: entry["status"] for entry in read_event(receipt_offset, trial, "receipts")}
            recovered_entries = read_event(kill_offset, trial, "killed")
            for entry in recovered_entries:
                rows, _, _ = requests[entry["batch"]]
                status = receipts.get(entry["batch"])
                if status is None:
                    fully_uploaded = entry["uploaded_bytes"] == entry["declared_bytes"]
                    outcome = "unknown" if fully_uploaded else "incomplete"
                else:
                    outcome = {204: "acknowledged", 400: "rejected"}[status]
                if outcome != entry["outcome"]:
                    raise InfrastructureError(f"{entry['batch']}: recorded outcome differs from the crash plan")
                multiplicities = [counts[row] for row in rows]
                absent, whole = [0] * len(rows), [1] * len(rows)
                allowed = {"acknowledged": (whole,), "rejected": (absent,),
                           "incomplete": (absent,), "unknown": (absent, whole)}[outcome]
                check(multiplicities in allowed,
                      f"{entry['batch']}: {outcome} batch recovered with row multiplicities {multiplicities}")
                entry["recovered_rows"] = sum(multiplicities)
                if outcome == "unknown":
                    recovered_unknown["whole" if multiplicities == whole else "absent"] += 1
                if multiplicities == whole:
                    history.extend(rows)
            expect_rows(actual, oracle(history, trial_start, trial_start + 256),
                        f"{tag}: missing, duplicated, phantom, or misordered rows in the current trial")
            expected = oracle(history, lower, upper)
            if paged:
                expect_walk(bog, query_args(lower, upper), expected, (23, 127, 61),
                            f"{tag}: complete walk after restart")
            else:
                check(len(expected) < MAX_QUERY_LIMIT, "legacy crash replay exceeded the query limit")
                expect_rows(bog.query(lower, upper, limit=MAX_QUERY_LIMIT), expected,
                            f"{tag}: full query after restart")
            record({**event, "event": "reconciliation", "requests": recovered_entries,
                    "total_recovered_rows": len(history)})
    return {"rounds": rounds, "outcomes": {key: count * rounds for key, count in Counter(outcomes).items()},
            "recovered_unknown": dict(recovered_unknown), "total_recovered_rows": len(history),
            "ledger": str(ledger.relative_to(log_dir.parent))}


def data_files(store):
    files = {}
    for name in ("bog.wal", "bog.commit"):
        path = store / name
        check(path.is_file(), f"Bog did not produce {name}")
        files[name] = path.read_bytes()
    check(files["bog.wal"].startswith(WAL_MAGIC), "Bog produced an invalid WAL magic")
    check(files["bog.commit"] == commit_marker(len(files["bog.wal"])),
          "Bog commit marker does not cover the complete WAL")
    return files


def commit_marker(offset):
    return struct.pack("<8sQQ", COMMIT_MAGIC, offset, offset ^ 0xffff_ffff_ffff_ffff)


def write_data_copy(directory, files):
    directory.mkdir()
    for name, content in files.items():
        (directory / name).write_bytes(content)


def corrupt_byte(content, offset):
    return content[:offset] + bytes([content[offset] ^ 1]) + content[offset + 1:]


def recovery_suite(binary, directory):
    directory.mkdir()
    seed = directory / "seed"
    history = [Row(3, "earlier batch row 1"), Row(1, "earlier batch row 2")]
    final = [Row(2, "final frame marker")]
    with run_bog(binary, seed) as bog:
        bog.ingest(history)
        bog.kill()
    earlier = data_files(seed)
    with run_bog(binary, seed) as bog:
        bog.ingest(final)
        bog.kill()
    committed = data_files(seed)
    old_wal = earlier["bog.wal"]
    wal = committed["bog.wal"]
    check(wal.startswith(old_wal) and len(wal) > len(old_wal),
          "the second durable POST did not append to the WAL")
    check(committed["bog.commit"] != earlier["bog.commit"], "the commit marker did not advance")
    suffix = wal[len(old_wal):]

    resumed = Row(4, "ingest after the uncommitted suffix is discarded")
    for label, suffix_bytes in [
        ("torn-header", suffix[:7]),
        ("torn-payload", suffix[:-1]),
        ("complete-uncommitted-frame", suffix),
        ("unparseable-uncommitted-bytes", b"discard all bytes past the committed offset"),
    ]:
        case = directory / label
        write_data_copy(case, {**earlier, "bog.wal": old_wal + suffix_bytes})
        with run_bog(binary, case) as bog:
            expect_query(bog, history, 0, 5, label=f"recovery from {label}")
            bog.kill()
        check(data_files(case) == earlier, f"{label}: recovery did not restore the exact committed files")
        with run_bog(binary, case) as bog:
            bog.ingest([resumed])
            bog.kill()
        with run_bog(binary, case) as bog:
            expect_query(bog, history + [resumed], 0, 5, label=f"durable append after {label}")

    refusals = []
    for label, files in [
        ("committed-file-header", {**committed, "bog.wal": corrupt_byte(wal, 0)}),
        ("committed-frame-header", {**committed, "bog.wal": corrupt_byte(wal, len(old_wal))}),
        ("committed-payload", {**committed, "bog.wal": corrupt_byte(wal, len(wal) - 2)}),
        ("corrupt-prefix-with-uncommitted-suffix",
         {**earlier, "bog.wal": corrupt_byte(old_wal, len(old_wal) - 2) + suffix}),
        ("committed-truncation", {**committed, "bog.wal": wal[:-1]}),
        ("corrupt-marker", {**committed, "bog.commit": corrupt_byte(committed["bog.commit"], 0)}),
        ("marker-complement", {**committed, "bog.commit": corrupt_byte(committed["bog.commit"], 16)}),
        ("marker-outside-wal", {**committed, "bog.commit": commit_marker(len(wal) + 1)}),
        ("marker-inside-frame", {**committed, "bog.commit": commit_marker(len(wal) - 1)}),
        ("missing-marker", {"bog.wal": wal}),
        ("missing-wal", {"bog.commit": committed["bog.commit"]}),
    ]:
        case = directory / label
        write_data_copy(case, files)
        before = {name: (case / name).stat() for name in files}
        try:
            with run_bog(binary, case, ready=False):
                pass
            for name in committed:
                path = case / name
                if name not in files:
                    check(not path.exists(), f"{label}: refused startup created {name}")
                    continue
                check(path.is_file() and path.read_bytes() == files[name],
                      f"{label}: refused startup changed {name}")
                old, new = before[name], path.stat()
                check((old.st_ino, old.st_mtime_ns, old.st_ctime_ns) ==
                      (new.st_ino, new.st_mtime_ns, new.st_ctime_ns),
                      f"{label}: refused startup rewrote or replaced {name}")
        except Rejected as exc:
            refusals.append(str(exc))
    check(not refusals, ", ".join(refusals))


def crc32c(data):
    """Castagnoli checksum for small fixtures in the documented WAL format."""
    checksum = 0xffff_ffff
    for byte in data:
        checksum ^= byte
        for _ in range(8):
            checksum = (checksum >> 1) ^ (0x82f63b78 if checksum & 1 else 0)
    return checksum ^ 0xffff_ffff


def wal_frame(payload):
    header = struct.pack("<III", len(payload), len(payload) ^ 0xffff_ffff, crc32c(payload))
    return header + struct.pack("<I", crc32c(header)) + payload


def historical_surrogate_suite(binary, directory):
    fresh = Row(3, "durable append after historical replay")
    with run_bog(binary, directory) as bog:
        bog.ingest([fresh])
        bog.kill()
    initial = data_files(directory)
    escaped = br'old high=\ud800; low=\udfff; pair=\ud83d\ude42; literal=\\ud800'
    payload = b'{"ts":"' + stamp(1).encode() + b'","line":"' + escaped + b'"}\n'
    historical = Row(1, "old high=�; low=�; pair=🙂; literal=\\ud800")
    wal = initial["bog.wal"] + wal_frame(payload)
    replay = directory / "historical"
    fixture = {"bog.wal": wal, "bog.commit": commit_marker(len(wal))}
    write_data_copy(replay, fixture)
    appended = Row(2, "new row between historical and current")
    with run_bog(binary, replay) as bog:
        expect_query(bog, [fresh, historical], 0, 4, label="historical UTF-16 escapes")
        check(data_files(replay) == fixture, "replay rewrote the historical frame")
        bog.ingest([appended])
        bog.kill()
    with run_bog(binary, replay) as bog:
        expect_query(bog, [fresh, historical, appended], 0, 4,
                     label="historical escapes with durable current append")
    check(data_files(replay)["bog.wal"].startswith(wal), "append rewrote the historical frame")


def wal_handoff_suite(baseline, candidate, directory, baseline_sha):
    directory.mkdir()
    verified = []

    def concurrent_appends(bog, label, start):
        batches = [[dataclasses.replace(row, ns=start + row.ns) for row in batch]
                   for batch in make_batches(label, 8, 8)]
        barrier = threading.Barrier(len(batches))

        def write(batch):
            barrier.wait(timeout=HTTP_TIMEOUT)
            bog.ingest(batch)

        with ThreadPoolExecutor(max_workers=len(batches)) as pool:
            list(pool.map(write, batches))
        return list(itertools.chain.from_iterable(batches))

    def verify_rows(bog, rows, label):
        expect_query(bog, rows, -5, 300, label=label)
        if baseline_sha == CYCLE7_BASELINE_SHA:
            expect_walk(bog, query_args(-5, 300), oracle(rows, -5, 300), (2, 17, 37), label)

    for source, target, name in [(baseline, candidate, "baseline-to-candidate"),
                                 (candidate, baseline, "candidate-to-baseline")]:
        case = directory / name
        case.mkdir()
        source_rows = [Row(8, f"{name} original Z"), Row(-1, f"{name} out of order"),
                       Row(8, f"{name} original A", -450)]
        target_rows = [Row(8, f"{name} appended tie", 345), Row(-2, f"{name} backfill"),
                       Row(10, f"{name} appended last")]

        with run_bog(source, case / "source") as bog:
            bog.ingest(source_rows)
            bog.ingest(source_rows[-1:])
            source_rows.append(source_rows[-1])
            source_rows.extend(concurrent_appends(bog, f"{name}/source", 100))
            verify_rows(bog, source_rows, f"{name}: original writer")
            bog.kill()
        original = data_files(case / "source")
        write_data_copy(case / "target", original)
        with run_bog(target, case / "target") as bog:
            verify_rows(bog, source_rows, f"{name}: target replay")
            check(data_files(case / "target") == original, f"{name}: target rewrote the committed files")
            bog.ingest(target_rows)
            target_rows.extend(concurrent_appends(bog, f"{name}/target", 200))
            verify_rows(bog, source_rows + target_rows, f"{name}: target append")
            bog.kill()
        extended = data_files(case / "target")
        check(extended["bog.wal"].startswith(original["bog.wal"])
              and len(extended["bog.wal"]) > len(original["bog.wal"]),
              f"{name}: target did not append to the original WAL")
        write_data_copy(case / "return", extended)
        with run_bog(source, case / "return") as bog:
            verify_rows(bog, source_rows + target_rows, f"{name}: original writer reopens target append")
            bog.stop()
        check(data_files(case / "return") == extended, f"{name}: source rewrote target's committed files")
        verified.append({"direction": name, "source_rows": len(source_rows), "appended_rows": len(target_rows),
                         "initial_wal_sha256": hashlib.sha256(original["bog.wal"]).hexdigest(),
                         "extended_wal_sha256": hashlib.sha256(extended["bog.wal"]).hexdigest()})
    return {"baseline_sha": baseline_sha, "directions": verified}


def free_bytes(path):
    stats = os.statvfs(path)
    return stats.f_bavail * stats.f_frsize


def bounded_mount():
    if sys.platform != "linux" or os.geteuid() == 0:
        raise InfrastructureError("ENOSPC suites require an unprivileged Linux process")
    supplied = os.environ.get("SLIPWAY_PARAM_ENOSPC_MOUNT")
    mount = Path(supplied or "/dev/shm").resolve()
    mountinfo = Path("/proc/self/mountinfo")
    if mountinfo.is_file() and mount.is_dir() and mount != Path("/"):
        mounts = [line.split(" - ", 1) for line in mountinfo.read_text().splitlines()]
        for left, right in mounts:
            if left.split()[4].replace(r"\040", " ") != str(mount):
                continue
            if not supplied and right.split()[0] != "tmpfs":
                continue
            stats = os.statvfs(mount)
            capacity = stats.f_blocks * stats.f_frsize
            if (1024**2 <= capacity <= 128 * 1024**2 and free_bytes(mount) >= capacity * 0.9
                    and os.access(mount, os.W_OK | os.X_OK)):
                return mount, capacity
    raise InfrastructureError(f"ENOSPC requires {mount} to be a writable, mostly empty, private 1–128 MiB mount")


def fill_blocks(filler, capacity):
    with filler.open("wb", buffering=0) as stream:
        chunk = bytes(1024 * 1024)
        try:
            while stream.tell() <= capacity:
                if not stream.write(chunk):
                    raise InfrastructureError("filler write made no progress")
        except OSError as exc:
            if exc.errno != errno.ENOSPC:
                raise
            allocated = stream.tell()
            print(f"ENOSPC filesystem_control_errno={exc.errno} "
                  f"capacity_bytes={capacity} allocated_bytes={allocated}")
        else:
            raise InfrastructureError("bounded filesystem did not return kernel ENOSPC")
        os.fsync(stream.fileno())
    return allocated


def constrain_append(filler, capacity, payload_size):
    allocated = fill_blocks(filler, capacity)
    # Leave space for the header and some payload pages before the append hits ENOSPC.
    os.truncate(filler, allocated - 64 * 1024)
    available = free_bytes(filler.parent)
    if not 0 < available < payload_size:
        raise InfrastructureError(f"cannot constrain WAL append: available_bytes={available}, "
                                  f"payload_bytes={payload_size}")
    print(f"ENOSPC append_available_bytes={available} payload_bytes={payload_size}")


def enospc_suite(binary, directory):
    mount, capacity = bounded_mount()
    print(f"ENOSPC available=true mount={mount} capacity_bytes={capacity}")
    history = [Row(1, "ENOSPC acknowledged history/1"), Row(2, "ENOSPC acknowledged history/2")]
    interrupted = [[Row(3 + i, f"ENOSPC failed row {i}: " + "x" * 16_384) for i in range(start, start + 8)]
                   for start in range(0, 32, 8)]
    payloads = [encode_rows(batch) for batch in interrupted]
    barrier = threading.Barrier(len(payloads))
    resumed = [dataclasses.replace(row, line=row.line.replace("failed", "rescue", 1))
               for row in itertools.chain.from_iterable(interrupted)]
    with tempfile.TemporaryDirectory(prefix="bog-enospc-", dir=mount) as tmp:
        store = Path(tmp) / "store"
        with run_bog(binary, store) as bog:
            bog.ingest(history)
            bog.kill()
        prior = data_files(store)
        filler = Path(tmp) / "filler"
        with run_bog(binary, store) as bog, ThreadPoolExecutor(max_workers=len(payloads)) as pool:
            constrain_append(filler, capacity, min(map(len, payloads)))

            def write(payload):
                barrier.wait(timeout=HTTP_TIMEOUT)
                return bog.request("POST", "/ingest", payload)

            for status, response in pool.map(write, payloads):
                check(status == 503, f"ENOSPC append expected HTTP 503, got {status}: {response[:200]!r}")
            expect_rows(bog.query(0, 41), history, "ENOSPC failed batch was not published")
            bog.kill()
        filler.unlink()
        check(data_files(store) == prior, "ENOSPC failed batch changed the committed files")
        with run_bog(binary, store) as bog:
            expect_rows(bog.query(0, 41), history, "ENOSPC acknowledged history after restart")
            bog.ingest(resumed)
            bog.kill()
        with run_bog(binary, store) as bog:
            expect_rows(bog.query(0, 41), history + resumed, "ENOSPC new durable write after second restart")
    return {"available": True, "capacity_bytes": capacity, "kernel_errno": errno.ENOSPC,
            "rejected_writers": len(payloads)}


def require_full_blocks(path):
    stats = os.statvfs(path)
    if stats.f_bavail != 0 or stats.f_favail <= 0:
        raise InfrastructureError(f"expected zero allocatable blocks and free inodes at {path}: "
                                  f"blocks={stats.f_bavail}, inodes={stats.f_favail}")
    return stats


def probe_full_disk(probe):
    stats = require_full_blocks(probe.parent)
    with probe.open("xb", buffering=0) as stream:
        try:
            stream.write(bytes(stats.f_frsize))
        except OSError as exc:
            if exc.errno != errno.ENOSPC:
                raise
        else:
            raise InfrastructureError("fresh inode accepted an allocating write on the full filesystem")
    probe.unlink()
    return require_full_blocks(probe.parent)


def full_disk_restart_suite(binary, directory):
    mount, capacity = bounded_mount()
    history = [Row(2, "full-disk acknowledged first"), Row(1, "full-disk acknowledged late")]
    resumed = Row(3, "full-disk durable append after space was released")
    with tempfile.TemporaryDirectory(prefix="bog-full-restart-", dir=mount) as tmp:
        root = Path(tmp)
        store = root / "store"
        with run_bog(binary, store) as bog:
            bog.ingest(history)
            bog.kill()
        prior = data_files(store)
        marker = store / "bog.commit"
        filler = root / "filler"

        # Keep the original inode alive so an unlink and replacement cannot reuse its number.
        with marker.open("rb") as saved_marker:
            identity = os.fstat(saved_marker.fileno())
            allocated = fill_blocks(filler, capacity)
            stats = probe_full_disk(root / "allocation-probe")
            evidence = {
                "mount": str(mount), "capacity_bytes": capacity, "filler_bytes": allocated,
                "uid": os.geteuid(), "allocatable_blocks": stats.f_bavail, "free_inodes": stats.f_favail,
                "kernel_errno": errno.ENOSPC, "marker_inode_before": identity.st_ino,
                "marker_sha256_before": hashlib.sha256(prior["bog.commit"]).hexdigest(),
            }
            print("BOG_FULL_DISK " + json.dumps(evidence, sort_keys=True))

            def verify_preserved_files():
                check(data_files(store) == prior, "full-disk restart changed the acknowledged WAL or marker bytes")
                current = marker.stat()
                check((current.st_dev, current.st_ino) == (identity.st_dev, identity.st_ino),
                      f"full-disk restart replaced bog.commit inode {identity.st_ino} with {current.st_ino}")
                require_full_blocks(store)
                return current.st_ino

            with run_bog(binary, store) as bog:
                expect_query(bog, history, 0, 4, label="acknowledged data reopened at zero allocatable blocks")
                verify_preserved_files()
                bog.stop()
            evidence["marker_inode_after"] = verify_preserved_files()
            evidence["marker_bytes_preserved"] = True

        filler.unlink()
        if free_bytes(store) == 0:
            raise InfrastructureError("failed to release space on the bounded filesystem")
        with run_bog(binary, store) as bog:
            bog.ingest([resumed])
            bog.kill()
        with run_bog(binary, store) as bog:
            expect_query(bog, history + [resumed], 0, 4, label="append after disk space was freed survives restart")
    return evidence


def milliseconds(seconds):
    return round(seconds * 1000, 3)


def latency_metrics(seconds, *, sample_limit=None):
    ordered = sorted(seconds)
    samples = seconds
    if sample_limit is not None and len(seconds) > sample_limit:
        samples = [seconds[index * (len(seconds) - 1) // (sample_limit - 1)]
                   for index in range(sample_limit)]
    return {
        "sample_count": len(seconds),
        "samples_ms": [milliseconds(value) for value in samples],
        **{f"p{p}_ms": milliseconds(ordered[math.ceil(p * len(ordered) / 100) - 1])
           for p in (50, 95, 99)},
    }


def peak_rss_kib(process):
    # VmHWM is the kernel's process high-water mark, including peaks between HTTP calls.
    status = Path(f"/proc/{process.pid}/status")
    if not status.exists() and sys.platform != "linux":
        return None
    for line in status.read_text().splitlines():
        if line.startswith("VmHWM:"):
            return int(line.split()[1])
    raise InfrastructureError("Linux process status did not contain VmHWM")


BENCH_BATCH_ROWS = 500
BENCH_PROFILES = {"steady": 1, "burst": 4, "backfill": 4}
BENCH_SEEDS = tuple(SEEDS["performance-smoke"] + i for i in range(4))
BENCH_REPEATS = 4
BENCH_LARGE_ROWS = 1_000_000
CYCLE3_BATCH_ROWS = 8
CYCLE3_PROFILES = {"steady": 1, "burst": 8, "backfill": 8}
CYCLE3_COMPARE_ROWS = 32_768
RARE_INTERVAL = 8191
RARE_LITERAL = " bog-verifier/rare "
ABSENT_LITERAL = " bog-verifier/absent "
# Ratios are candidate divided by the pinned Cycle 1 indexed baseline.
INDEXED_TARGETS = {
    "wide_query_p95": ("<=", 0.50),
    "narrow_query_p95": ("<=", 1.25),
    "rare_or_absent_query_p95": ("<=", 1.50),
    "durable_rows_per_second": (">=", 0.80),
    "peak_rss_kib": ("<=", 1.25),
    "restart_ready_ms": ("<=", 1.25),
}


def write_benchmark_bodies(path, starts, rows_for, count, batch_rows):
    digest = hashlib.sha256()
    batches = []
    with path.open("wb") as stream:
        for start in starts:
            indices = range(start, min(start + batch_rows, count))
            payload = encode_rows(rows_for(indices))
            batches.append((stream.tell(), len(payload), len(indices)))
            stream.write(payload)
            digest.update(payload)
    return batches, digest.hexdigest()


class Benchmark:
    """One seeded set of HTTP bodies and expected results shared by both binaries."""

    def __init__(self, path, count, profile, seed, corpus, *, batch_rows, writers):
        self.path = path
        self.count = count
        self.profile = profile
        self.seed = seed
        self.writers = writers
        self.batch_rows = batch_rows
        rng = random.Random(seed)
        self.lines = [row.line for row in corpus if len(row.line.encode()) <= 128]
        rng.shuffle(self.lines)

        starts = list(range(0, count, batch_rows))
        if profile == "backfill":
            rng.shuffle(starts)
        self.batches, self.digest = write_benchmark_bodies(path, starts, self.rows, count, batch_rows)
        self.size = path.stat().st_size

        self.queries = []
        for sample in range(24):
            narrow = rng.randrange(count - 24)
            wide = rng.randrange(count // 4)
            first_rare = (wide + RARE_INTERVAL - 1) // RARE_INTERVAL * RARE_INTERVAL
            for kind, left, right, literal, indices in [
                ("narrow", narrow, narrow + 24, "", range(narrow, narrow + 24)),
                ("broad", wide, count, "", range(wide, wide + MAX_QUERY_LIMIT)),
                ("rare_or_absent", wide, count, RARE_LITERAL if sample % 2 == 0 else ABSENT_LITERAL,
                 range(first_rare, count, RARE_INTERVAL) if sample % 2 == 0 else ()),
            ]:
                args = query_args(left * SECOND, right * SECOND, literal, MAX_QUERY_LIMIT)
                self.queries.append((sample, kind, query_target(args), self.rows(indices)))

    def rows(self, indices):
        # Timestamp keys are unique, even when the HTTP writers race.
        return [Row(i * SECOND, f"perf/{i:07} "
                    + (RARE_LITERAL if i % RARE_INTERVAL == 0 else "")
                    + self.lines[i % len(self.lines)])
                for i in indices]

    def query_metrics(self, bog, *, restarted=False):
        durations = {"narrow": [], "broad": [], "rare_or_absent": []}
        for sample, kind, target, expected in self.queries:
            started = time.monotonic()
            status, body, headers = bog.checked_exchange("GET", target)
            elapsed = time.monotonic() - started
            check(status == 200, f"benchmark {kind} returned HTTP {status}: {body[:150]!r}")
            check(headers.get_all(NEXT_CURSOR) is None, f"benchmark legacy query returned {NEXT_CURSOR}")
            expect_rows(decode_rows(body), expected, f"benchmark {kind} query {sample}")
            if sample >= 2:
                durations[kind].append(elapsed)
        return {kind: latency_metrics(times) for kind, times in durations.items()}

    def reconcile(self, bog, phase):
        # Leave room for an unexpected row and cover the rest of the UTC domain as well.
        step = MAX_QUERY_LIMIT - 1
        for left in range(0, self.count, step):
            right = min(left + step, self.count)
            expect_rows(bog.query(left * SECOND, right * SECOND, limit=MAX_QUERY_LIMIT),
                        self.rows(range(left, right)), f"benchmark {phase}, row interval [{left}, {right})")
        beginning = parse_stamp("0001-01-01T00:00:00Z")
        end = parse_stamp("9999-12-31T23:59:59.999999999Z")
        expect_rows(bog.query(beginning, 0), [], f"benchmark {phase}, before corpus")
        expect_rows(bog.query(self.count * SECOND, end), [], f"benchmark {phase}, after corpus")


def measure_benchmark(binary, directory, workload, *, reconcile=False, keep_alive=False, full_post_samples=False):
    start_writers = threading.Barrier(workload.writers + 1)
    with run_bog(binary, directory) as bog, ThreadPoolExecutor(max_workers=workload.writers) as pool:
        def write(worker):
            durations = []
            connection = (contextlib.closing(http.client.HTTPConnection("127.0.0.1", bog.port, timeout=HTTP_TIMEOUT))
                          if keep_alive else contextlib.nullcontext())
            with workload.path.open("rb") as fixture, connection as client:
                start_writers.wait(timeout=HTTP_TIMEOUT)
                for position, size, rows in workload.batches[worker::workload.writers]:
                    fixture.seek(position)
                    payload = fixture.read(size)
                    if len(payload) != size:
                        raise InfrastructureError("benchmark fixture truncated")
                    started = time.monotonic()
                    bog.ingest_body(payload, rows, connection=client)
                    durations.append(time.monotonic() - started)
            return durations

        empty_ready_ms = milliseconds(bog.startup_seconds)
        futures = [pool.submit(write, worker) for worker in range(workload.writers)]
        started = time.monotonic()
        start_writers.wait(timeout=HTTP_TIMEOUT)
        post_times = [duration for future in futures for duration in future.result()]
        elapsed = time.monotonic() - started
        ingest_rss = peak_rss_kib(bog.process)
        live_queries = workload.query_metrics(bog)
        if reconcile:
            workload.reconcile(bog, "before restart")
        live_rss = peak_rss_kib(bog.process)
        bog.kill()

    wal = directory / "bog.wal"
    check(wal.is_file() and wal.stat().st_size > len(WAL_MAGIC), "benchmark WAL is empty")
    with run_bog(binary, directory) as bog:
        restart_ms = milliseconds(bog.startup_seconds)
        replay_rss = peak_rss_kib(bog.process)
        restart_queries = workload.query_metrics(bog, restarted=True)
        if reconcile:
            workload.reconcile(bog, "after restart")
        restart_rss = peak_rss_kib(bog.process)
        bog.kill()
    return {
        "rows": workload.count, "batches": len(workload.batches),
        "batch_rows": workload.batch_rows, "writers": workload.writers, "keep_alive": keep_alive,
        "profile": workload.profile, "seed": workload.seed, "workload_sha256": workload.digest,
        "rows_per_second": round(workload.count / elapsed, 2),
        "batches_per_second": round(len(workload.batches) / elapsed, 2),
        "mib_per_second": round(workload.size / (1024 ** 2 * elapsed), 2),
        "ingest_elapsed_ms": milliseconds(elapsed),
        "post": latency_metrics(post_times, sample_limit=128 if keep_alive and not full_post_samples else None),
        "live_query": live_queries, "restart_query": restart_queries,
        "empty_ready_ms": empty_ready_ms, "restart_ready_ms": restart_ms,
        "live_peak_rss_kib": live_rss, "restart_peak_rss_kib": restart_rss,
        "ingest_peak_rss_kib": ingest_rss, "replay_peak_rss_kib": replay_rss,
        "peak_rss_kib": max(live_rss, restart_rss),
        "wal_bytes": wal.stat().st_size,
    }


def performance_suite(binary, directory):
    directory.mkdir()
    _, corpus = load_corpus()
    workload = Benchmark(directory / "workload.ndjson", 8_192, "backfill", BENCH_SEEDS[0], corpus,
                         batch_rows=CYCLE3_BATCH_ROWS, writers=CYCLE3_PROFILES["backfill"])
    return measure_benchmark(binary, directory / "store", workload, reconcile=True, keep_alive=True)


LOG_BLOCK_ROWS = 128  # Documented append block size, used to place fixture rows.
LOG_REPLAY_ROWS = 65_536 + 37
LOG_REPLAY_BATCH_ROWS = 317
LOG_REPLAY_ORDERS = ("steady", "shuffled")
LOG_REPLAY_SEEDS = (SEEDS["log-replay"], SEEDS["log-replay"] + 1)
LOG_DENSE_PREFIX_ROWS = 8_192
LOG_BLOCK_TEXT_BUDGET = 64 * 1024
LOG_QUERY_SAMPLES = 36
LOG_DENSE = " env=production"
LOG_RARE = " trace=7dbf-before-retry"
LOG_ABSENT = " trace=7DBF-before-retry"
LOG_SPLIT_GRAMS = "j9vQZ7"
LOG_UNICODE = "café_東京_🙂"
LOG_DECOMPOSED = "cafe\u0301_東京_🙂"
LOG_ESCAPED = 'path="C:\\spool\\audit"\tmsg="queued"\nnext=\x00'


def log_replay_sources():
    _, archive = load_corpus()
    raw = SYSLOG_PATH.read_bytes()
    if hashlib.sha256(raw).hexdigest() != SYSLOG_SHA256:
        raise InfrastructureError("syslog fixture digest mismatch")
    syslog = raw.decode("utf-8").split("\n")
    if syslog.pop() != "" or len(syslog) != 12:
        raise InfrastructureError("expected 12 LF-terminated syslog messages")
    return (
        [row.line for row in load_apache()],
        [row.line for row in load_git_daemon()],
        [row.line for row in archive if row.line.startswith("id=app-") and "\nTraceback" in row.line],
        syslog,
    )


class LogReplay:
    """Offline input and exact results for a serial HTTP replay."""

    def __init__(self, sources, seed, order):
        self.seed = seed
        self.order = order
        rng = random.Random(seed)
        rows = []
        for i in range(LOG_REPLAY_ROWS):
            dense = i < LOG_DENSE_PREFIX_ROWS or (i + 1) % LOG_DENSE_PREFIX_ROWS == 0
            env = LOG_DENSE if dense else " env=staging"
            rows.append(Row(i // 4 * SECOND, env + f" seq={i:05} " + rng.choice(sources[i % len(sources)])))
        for i in range(0, len(rows), 8191):
            rows[i] = Row(rows[i].ns, rows[i].line + LOG_RARE)
        rows[0] = Row(rows[0].ns, rows[0].line + " block=first")
        rows[-1] = Row(rows[-1].ns, rows[-1].line + LOG_RARE + " block=tail")
        rows[17] = rows[16]  # Exact duplicate followed by distinct rows at the same timestamp.
        rows[30] = Row(rows[30].ns, rows[30].line + f" Qz={LOG_UNICODE}")
        rows[31] = Row(rows[31].ns, rows[31].line + f" Qz={LOG_DECOMPOSED}")
        rows[32] = Row(rows[32].ns, rows[32].line + " " + LOG_ESCAPED)
        for i in range(len(LOG_SPLIT_GRAMS) - 3):
            ordinal = LOG_BLOCK_ROWS - 1 - i
            rows[ordinal] = Row(rows[ordinal].ns, rows[ordinal].line + f" fragment={LOG_SPLIT_GRAMS[i:i+4]}")
        large = LOG_REPLAY_ROWS // 2 // LOG_BLOCK_ROWS * LOG_BLOCK_ROWS
        rows[large] = Row(
            rows[large].ns,
            " env=staging level=ERROR " + "x" * (96 * 1024) + "\ncontinuation:large-log-end",
        )
        self.end = rows[-1].ns + 2 * SECOND
        if order == "shuffled":
            tail_start = len(rows) // LOG_BLOCK_ROWS * LOG_BLOCK_ROWS
            # Keep the shaped prefix and the three append-position probes in place.
            for left, right in ((LOG_BLOCK_ROWS, LOG_DENSE_PREFIX_ROWS), (LOG_DENSE_PREFIX_ROWS, large),
                                (large + 1, tail_start)):
                segment = rows[left:right]
                rng.shuffle(segment)
                rows[left:right] = segment
        if (sum(len(row.line.encode()) for row in rows[:LOG_BLOCK_ROWS]) > LOG_BLOCK_TEXT_BUDGET
                or any(LOG_SPLIT_GRAMS in row.line for row in rows)):
            raise InfrastructureError("split grams must occupy separate rows in an under-budget sealed block")
        grams = [LOG_SPLIT_GRAMS[i:i + 4] for i in range(len(LOG_SPLIT_GRAMS) - 3)]
        gram_rows = [[i for i, row in enumerate(rows[:LOG_BLOCK_ROWS]) if gram in row.line] for gram in grams]
        if gram_rows != [[LOG_BLOCK_ROWS - 1 - i] for i in range(len(grams))]:
            raise InfrastructureError("expected every split gram in a different row of the first sealed block")
        self.rows = rows
        self.batches = []
        digest = hashlib.sha256()
        for start in range(0, len(rows), LOG_REPLAY_BATCH_ROWS):
            batch = rows[start:start + LOG_REPLAY_BATCH_ROWS]
            body = encode_rows(batch)
            self.batches.append((body, len(batch)))
            digest.update(body)
        self.append_sha256 = digest.hexdigest()
        self.append_bytes = sum(len(body) for body, _ in self.batches)
        # The old partial block seals on this acknowledged append. Early rows
        # backfill, and later rows tie with the last old row or extend beyond it.
        tail = len(rows) % LOG_BLOCK_ROWS
        self.backfill = [
            Row(SECOND if i % 3 == 0 else rows[-1].ns + (i % 3 - 1) * SECOND,
                LOG_DENSE + (LOG_RARE if i < 3 else "") + f" retroactive-retry={i:02}")
            for i in range(LOG_BLOCK_ROWS - tail)
        ]
        self.backfill_batches = [encode_rows(self.backfill[:3]), encode_rows(self.backfill[3:])]
        self.backfill_sha256 = hashlib.sha256(b"".join(self.backfill_batches)).hexdigest()

    def queries(self, rows):
        cases = [
            ("all-rows", 0, self.end, ""),
            ("dense", 0, self.end, LOG_DENSE),
            ("rare", 0, self.end, LOG_RARE),
            ("absent", 0, self.end, LOG_ABSENT),
            ("split-grams", 0, self.end, LOG_SPLIT_GRAMS),
            ("sparse-after-prefix", LOG_DENSE_PREFIX_ROWS // 4 * SECOND, self.end, LOG_DENSE),
            ("first-block", 0, self.end, "block=first"),
            ("final-partial-block", 0, self.end, "block=tail"),
            ("large-line", 0, self.end, "\ncontinuation:large-log-end"),
            ("unicode", 0, self.end, LOG_UNICODE),
            ("decomposed-unicode", 0, self.end, LOG_DECOMPOSED),
            ("escaped-text", 0, self.end, LOG_ESCAPED),
            ("short-literal", 0, self.end, "Qz"),
            ("ties-at-narrow-boundary", 4 * SECOND, 4 * SECOND + 1, ""),
            ("ties-across-posts", LOG_REPLAY_BATCH_ROWS // 4 * SECOND,
             LOG_REPLAY_BATCH_ROWS // 4 * SECOND + 1, ""),
            ("narrow-multiline", 4 * SECOND, 9 * SECOND, "\nTraceback"),
            ("empty-window", 4 * SECOND, 4 * SECOND, LOG_DENSE),
        ]
        return [(name, query_args(left, right, literal), oracle(rows, left, right, literal))
                for name, left, right, literal in cases]

    def timing_queries(self):
        rows = self.rows + self.backfill
        rng = random.Random(self.seed)
        ranges = [rng.randrange(LOG_DENSE_PREFIX_ROWS // 8) * SECOND for _ in range(LOG_QUERY_SAMPLES // 3)]
        return [
            [(name, query_target(query_args(left, self.end, literal, MAX_QUERY_LIMIT)),
              oracle(rows, left, self.end, literal)[:MAX_QUERY_LIMIT])
             for name, literal in (("dense", LOG_DENSE), ("rare", LOG_RARE), ("absent", LOG_ABSENT))]
            for left in ranges
        ]


def verify_log_queries(bog, cases, phase, *, hold=()):
    pending = []
    for name, args, expected in cases:
        label = f"log replay {phase} {name}"
        limit = MAX_QUERY_LIMIT
        actual, cursor = bog.query_page({**args, "limit": limit})
        check(cursor is None, f"{label}: unpaged response included {NEXT_CURSOR}")
        expect_rows(actual, expected[:limit], f"{label} unpaged")
        if name in hold:
            first_limit = 3 if name == "rare" else 257
            cursor = expect_page(bog, args, expected, 0, first_limit, None, label)
            check(cursor is not None, f"{label}: expected a cursor to resume across backfill")
            pending.append((args, expected, first_limit, cursor, label))
        else:
            # Small pages split timestamp ties and duplicates, while wide
            # results use larger pages to keep the PR check bounded.
            limits = (997, None, 1000) if len(expected) > MAX_QUERY_LIMIT else (1, 2, 23)
            expect_walk(bog, args, expected, limits, label)
    return pending


def measure_log_queries(bog, queries):
    durations = {"dense": [], "rare": [], "absent": []}
    with contextlib.closing(http.client.HTTPConnection("127.0.0.1", bog.port, timeout=HTTP_TIMEOUT)) as client:
        for sample, group in enumerate(queries[:2] + queries * 3):
            for name, target, expected in group:
                started = time.monotonic()
                status, body, headers = bog.checked_exchange("GET", target, connection=client)
                elapsed = time.monotonic() - started
                check(status == 200, f"log replay timing {name} returned HTTP {status}: {body[:150]!r}")
                check(headers.get_all(NEXT_CURSOR) is None, f"log replay timing {name} returned {NEXT_CURSOR}")
                expect_rows(decode_rows(body), expected, f"log replay timing {name}, sample {sample}")
                if sample >= 2:
                    durations[name].append(elapsed)
    return {name: latency_metrics(times) for name, times in durations.items()}


def measure_log_replay(binary, directory, replay):
    initial = replay.queries(replay.rows)
    final = replay.queries(replay.rows + replay.backfill)
    timing = replay.timing_queries()
    with run_bog(binary, directory) as bog:
        empty_ready_ms = milliseconds(bog.startup_seconds)
        with contextlib.closing(http.client.HTTPConnection("127.0.0.1", bog.port, timeout=HTTP_TIMEOUT)) as client:
            post_times = []
            started = time.monotonic()
            for body, count in replay.batches:
                request_start = time.monotonic()
                bog.ingest_body(body, count, connection=client)
                post_times.append(time.monotonic() - request_start)
            elapsed = time.monotonic() - started
        ingest_rss = peak_rss_kib(bog.process)
        pending = verify_log_queries(bog, initial, "before backfill", hold=("dense", "rare"))
        bog.ingest_body(replay.backfill_batches[0], 3)
        resumed = []
        for args, expected, position, cursor, label in pending:
            next_cursor = expect_page(bog, args, expected, position, 1, cursor, f"{label}, during backfill")
            check(next_cursor is not None, f"{label}: expected another page after early and tied backfill")
            resumed.append((args, expected, position + 1, next_cursor, label))
        bog.ingest_body(replay.backfill_batches[1], len(replay.backfill) - 3)
        for args, expected, position, cursor, label in resumed:
            expect_walk(bog, args, expected, (997, None, 1000), f"{label}, resumed after sealing",
                        position=position, cursor=cursor)
        live_queries = measure_log_queries(bog, timing)
        verify_log_queries(bog, final, "fresh after backfill")
        live_rss = peak_rss_kib(bog.process)
        bog.kill()

    with run_bog(binary, directory) as bog:
        restart_ready_ms = milliseconds(bog.startup_seconds)
        replay_rss = peak_rss_kib(bog.process)
        for args, _, _, cursor, label in pending:
            expect_bad_query(bog, {**args, "cursor": cursor}, f"{label}, stale after restart")
        restart_queries = measure_log_queries(bog, timing)
        verify_log_queries(bog, final, "fresh after restart")
        restart_rss = peak_rss_kib(bog.process)
        tied = replay.rows[-1].ns
        near_limit = Row(replay.end, "large POST after replay ")
        padding = MAX_FRAME - 1 - len(encode_rows([near_limit]))
        near_limit = dataclasses.replace(near_limit, line=near_limit.line + "x" * padding)
        tiny = [Row(tied, "tiny POST tied with replayed data"),
                Row(SECOND, "tiny POST backfilled after replay")]
        bog.ingest([near_limit])
        bog.ingest(tiny)
        bog.kill()
    with run_bog(binary, directory) as bog:
        appended = replay.rows + replay.backfill + [near_limit] + tiny
        for left, right in ((SECOND, SECOND + 1), (tied, tied + 1), (replay.end, replay.end + 1)):
            label = "log replay after a near-limit frame and a tiny append"
            expect_query(bog, appended, left, right, label=label)
            expect_walk(bog, query_args(left, right), oracle(appended, left, right), (1, 7), label)
    return {
        "order": replay.order, "seed": replay.seed, "rows": len(replay.rows),
        "backfill_rows": len(replay.backfill), "batches": len(replay.batches),
        "append_sha256": replay.append_sha256, "backfill_sha256": replay.backfill_sha256,
        "ingest_elapsed_ms": milliseconds(elapsed),
        "durable_rows_per_second": round(len(replay.rows) / elapsed, 2),
        "durable_mib_per_second": round(replay.append_bytes / (1024 ** 2 * elapsed), 2),
        "post": latency_metrics(post_times),
        "live_query": live_queries, "restart_query": restart_queries,
        "empty_ready_ms": empty_ready_ms, "restart_ready_ms": restart_ready_ms,
        "ingest_peak_rss_kib": ingest_rss, "replay_peak_rss_kib": replay_rss,
        "live_peak_rss_kib": live_rss, "restart_peak_rss_kib": restart_rss,
        "peak_rss_kib": max(live_rss, restart_rss),
    }


def log_replay_suite(binary, directory):
    if sys.platform != "linux":
        raise InfrastructureError("log replay needs Linux process RSS telemetry")
    directory.mkdir()
    sources = log_replay_sources()
    return {order: measure_log_replay(binary, directory / order, LogReplay(sources, LOG_REPLAY_SEEDS[0], order))
            for order in LOG_REPLAY_ORDERS}


CONTROLLED_REPLAY_REPEATS = 3
CONTROLLED_REPLAY_SAMPLES = LOG_QUERY_SAMPLES
LOG_QUERY_KINDS = ("dense", "rare", "absent", "narrow", "unfiltered")
LOG_QUERY_METRICS = tuple(f"{kind}_query_p95" for kind in LOG_QUERY_KINDS) + tuple(
    f"{kind}_{'page' if kind == 'absent' else 'cursor'}_p95" for kind in LOG_QUERY_KINDS
)


class ControlledLogReplay:
    """Large real-log workload with each timestamp group contained in one POST."""

    def __init__(self, path, sources, seed, order):
        self.path, self.seed, self.profile = path, seed, order
        self.count, self.batch_rows, self.writers = BENCH_LARGE_ROWS, BENCH_BATCH_ROWS, 4
        rows_per_timestamp = 4
        if self.batch_rows % rows_per_timestamp:
            raise InfrastructureError("controlled replay timestamps would tie across concurrent POSTs")
        rng = random.Random(seed)
        dense_end = self.count // 8
        self.rows = [
            Row(i // rows_per_timestamp * SECOND,
                (LOG_DENSE if i < dense_end or (i + 1) % LOG_DENSE_PREFIX_ROWS == 0 else " env=staging")
                + (LOG_RARE if i % RARE_INTERVAL == 0 else "")
                + f" seq={i:07} " + rng.choice(sources[i % len(sources)]))
            for i in range(self.count)
        ]
        starts = list(range(0, self.count, self.batch_rows))
        if order == "shuffled":
            rng.shuffle(starts)
        self.batches, self.digest = write_benchmark_bodies(
            path, starts, lambda indices: self.rows[indices.start:indices.stop], self.count, self.batch_rows)
        self.size = path.stat().st_size
        self.end = (self.rows[-1].ns // SECOND + 1) * SECOND

        matches = {literal: oracle(self.rows, 0, self.end, literal)
                   for literal in (LOG_DENSE, LOG_RARE, LOG_ABSENT)}
        self.query_cases = []
        for _ in range(CONTROLLED_REPLAY_SAMPLES + 2):
            wide = rng.randrange(dense_end // (2 * rows_per_timestamp)) * SECOND
            narrow = rng.randrange(self.end // SECOND - 24) * SECOND
            cases = []
            for kind, left, right, literal in (
                ("dense", wide, self.end, LOG_DENSE),
                ("rare", wide, self.end, LOG_RARE),
                ("absent", wide, self.end, LOG_ABSENT),
                ("narrow", narrow, narrow + 24 * SECOND, ""),
                ("unfiltered", wide, self.end, ""),
            ):
                rows = matches[literal] if literal else self.rows
                start = bisect.bisect_left(rows, left, key=lambda row: row.ns)
                stop = bisect.bisect_left(rows, right, key=lambda row: row.ns)
                args = query_args(left, right, literal)
                first_limit = 3
                results = rows[start:min(stop, start + MAX_QUERY_LIMIT + first_limit + 1)]
                if kind != "absent" and len(results) <= first_limit:
                    raise InfrastructureError(f"controlled replay has too few {kind} rows for a continuation")
                cases.append((kind, args, results))
            self.query_cases.append(cases)

    def reconcile(self, bog, phase):
        bounds = query_args(parse_stamp("0001-01-01T00:00:00Z"),
                            parse_stamp("9999-12-31T23:59:59.999999999Z"))
        expect_walk(bog, bounds, self.rows, (1000, 997), f"controlled replay {phase}, complete walk")

    def query_metrics(self, bog, *, restarted=False):
        durations = {name: [] for name in LOG_QUERY_METRICS}

        def timed(client, args, expected, label, *, has_more=False):
            target = query_target(args)
            started = time.monotonic()
            status, body, headers = bog.checked_exchange("GET", target, connection=client)
            elapsed = time.monotonic() - started
            check(status == 200, f"controlled replay {label} returned HTTP {status}: {body[:150]!r}")
            cursors = headers.get_all(NEXT_CURSOR, [])
            check((len(cursors) == 1 and bool(cursors[0].strip())) if has_more else not cursors,
                  f"controlled replay {label} returned an unexpected {NEXT_CURSOR} header")
            expect_rows(decode_rows(body), expected, f"controlled replay {label}")
            return elapsed

        with contextlib.closing(http.client.HTTPConnection("127.0.0.1", bog.port, timeout=HTTP_TIMEOUT)) as client:
            for sample, cases in enumerate(self.query_cases):
                for kind, args, expected in cases:
                    limit = MAX_QUERY_LIMIT
                    ordinary = timed(client, {**args, "limit": limit}, expected[:limit], kind)
                    if kind == "absent":
                        page = timed(client, {**args, "page": "1", "limit": limit}, [], kind)
                        metric = f"{kind}_page_p95"
                    else:
                        cursor = expect_page(bog, args, expected, 0, 3, None, f"controlled replay {kind}")
                        page = timed(client, {**args, "cursor": cursor, "limit": limit}, expected[3:3 + limit],
                                     f"{kind} continuation", has_more=len(expected) > 3 + limit)
                        metric = f"{kind}_cursor_p95"
                    if sample >= 2:
                        durations[f"{kind}_query_p95"].append(ordinary)
                        durations[metric].append(page)
            if restarted and self.profile == "steady":
                cadence = 0.025
                next_request = time.monotonic()
                fixed = []
                for sample in range(CONTROLLED_REPLAY_SAMPLES + 2):
                    time.sleep(max(0, next_request - time.monotonic()))
                    next_request += cadence
                    _, args, expected = self.query_cases[0][0]
                    elapsed = timed(client, {**args, "limit": MAX_QUERY_LIMIT}, expected[:MAX_QUERY_LIMIT],
                                    "dense at fixed cadence")
                    if sample >= 2:
                        fixed.append(elapsed)
                durations["fixed_dense_query_p95"] = fixed
        return {name: latency_metrics(times) for name, times in durations.items()}


def log_replay_ratios(baseline, candidate):
    for key in ("order", "seed", "rows", "backfill_rows", "batches", "append_sha256", "backfill_sha256"):
        if baseline[key] != candidate[key]:
            raise InfrastructureError(f"log replay pair used different input: {key}")

    def measurements(result):
        if result["post"]["sample_count"] != result["batches"] or len(result["post"]["samples_ms"]) != result["batches"]:
            raise InfrastructureError("paired log replay missing raw POST samples")
        for phase in ("live", "restart"):
            for kind in ("dense", "rare", "absent"):
                metric = result[f"{phase}_query"][kind]
                if metric["sample_count"] != LOG_QUERY_SAMPLES or len(metric["samples_ms"]) != LOG_QUERY_SAMPLES:
                    raise InfrastructureError(f"paired log replay missing raw {phase} {kind} samples")
        return {
            **{key: result[key] for key in ("durable_rows_per_second", "peak_rss_kib", "restart_ready_ms")},
            **{f"{kind}_query_p95/{phase}": result[f"{phase}_query"][kind]["p95_ms"]
               for phase in ("live", "restart") for kind in ("dense", "rare", "absent")},
        }

    before, after = measurements(baseline), measurements(candidate)
    if any(not math.isfinite(value) or value <= 0 for value in (*before.values(), *after.values())):
        raise InfrastructureError("log replay pair has invalid measurements")
    return {name: after[name] / value for name, value in before.items()}


def log_replay_pair(binaries, directory, ledger, run, measure, compare):
    results = {}
    for role in run["order"]:
        prefix = f"{run['append_order']}-{run['seed']}-{run['repeat']}-{role}-"
        try:
            with tempfile.TemporaryDirectory(prefix=prefix, dir=directory) as store:
                results[role] = measure(binaries[role], Path(store))
        except (Rejected, subprocess.TimeoutExpired) as exc:
            sha = run[f"{role}_sha"]
            print("BOG_LOG_REPLAY_SAMPLE " + json.dumps({**run, "role": role, "diagnostic": diagnostic(exc)}))
            if role == "baseline":
                raise InfrastructureError(f"log replay baseline {sha} failed: {exc}") from exc
            raise
        print("BOG_LOG_REPLAY_SAMPLE " + json.dumps({**run, "role": role, "metrics": results[role]},
                                                   sort_keys=True), flush=True)
    ratios = compare(results["baseline"], results["candidate"])
    summary = {**run, "ratios": ratios}
    with ledger.open("a") as stream:
        stream.write(json.dumps({**summary, **results}, sort_keys=True) + "\n")
    print("BOG_LOG_REPLAY_PAIR " + json.dumps(summary, sort_keys=True))
    return ratios


def paired_log_replay_suite(baseline, candidate, directory, *, baseline_sha, candidate_sha):
    directory.mkdir()
    log_dir, _ = PROCESS_LOGS.get()
    ledger = log_dir / "pairs.jsonl"
    revisions = {"baseline_sha": baseline_sha, "candidate_sha": candidate_sha}
    binaries = {"baseline": baseline, "candidate": candidate}
    sources = log_replay_sources()
    pairs = []
    for append_order, order in zip(LOG_REPLAY_ORDERS, (["baseline", "candidate"], ["candidate", "baseline"])):
        replay = LogReplay(sources, LOG_REPLAY_SEEDS[0], append_order)
        run = {**revisions, "append_order": replay.order, "seed": replay.seed, "repeat": 1,
               "order": order, "append_sha256": replay.append_sha256, "backfill_sha256": replay.backfill_sha256}
        ratios = log_replay_pair(binaries, directory, ledger, run,
                                 lambda binary, store: measure_log_replay(binary, store, replay), log_replay_ratios)
        pairs.append({**run, "ratios": ratios})
    return {**revisions, "pairs": pairs, "ledger": str(ledger.relative_to(log_dir.parent))}


def controlled_replay_ratios(baseline, candidate):
    for key in ("workload_sha256", "profile", "seed", "rows", "batch_rows", "writers", "keep_alive"):
        if baseline[key] != candidate[key]:
            raise InfrastructureError(f"controlled replay pair used different input: {key}")

    def require_samples(metric, count):
        if metric["sample_count"] != count or len(metric["samples_ms"]) != count:
            raise InfrastructureError(f"controlled replay expected {count} raw samples")

    def measurements(result):
        require_samples(result["post"], result["batches"])
        metrics = {"durable_rows_per_second": result["rows_per_second"], "post_p99": result["post"]["p99_ms"]}
        for key in ("ingest_peak_rss_kib", "replay_peak_rss_kib", "restart_ready_ms"):
            metrics[key] = result[key]
        for phase in ("live", "restart"):
            for name, metric in result[f"{phase}_query"].items():
                require_samples(metric, CONTROLLED_REPLAY_SAMPLES)
                metrics[f"{name}/{phase}"] = metric["p95_ms"]
        return metrics

    before, after = measurements(baseline), measurements(candidate)
    if before.keys() != after.keys() or any(not math.isfinite(v) or v <= 0 for v in (*before.values(), *after.values())):
        raise InfrastructureError("controlled replay pair has missing or invalid measurements")
    return {name: after[name] / value for name, value in before.items()}


def log_replay_targets(pairs, append_order, baseline_sha):
    limits = {name: ("<=", 1.15) for name in LOG_QUERY_METRICS}
    limits.update(post_p99=("<=", 1.15), durable_rows_per_second=(">=", 0.90),
                  ingest_peak_rss_kib=("<=", 1.05), replay_peak_rss_kib=("<=", 1.05),
                  restart_ready_ms=("<=", 0.95 if append_order == "steady" else 1.05))
    required = {f"{name}/{phase}" for name in LOG_QUERY_METRICS for phase in ("live", "restart")}
    required.update(set(limits) - set(LOG_QUERY_METRICS))
    if append_order == "steady":
        limits["fixed_dense_query_p95"] = ("<=", 1.15)
        required.add("fixed_dense_query_p95/restart")
    if (len(pairs) != len(LOG_REPLAY_SEEDS) * CONTROLLED_REPLAY_REPEATS
            or any(pair.keys() != required for pair in pairs)):
        raise InfrastructureError("log replay performance needs every configured pair and measurement")
    if baseline_sha == COMPARISON_BASELINE_SHA:
        for name in ("rare_query_p95", "rare_cursor_p95", "absent_query_p95", "absent_page_p95"):
            limits[name] = ("<=", 0.25)
        selected = {name for name in required if name.startswith(("rare_", "absent_"))}
        if append_order == "steady":
            selected.update(("dense_query_p95/restart", "dense_cursor_p95/restart", "fixed_dense_query_p95/restart"))
        pairs = [{name: pair[name] for name in sorted(selected)} for pair in pairs]
    return median_targets(pairs, limits)


def controlled_log_replay_suite(baseline, pre_bloom, candidate, directory, *, candidate_sha):
    directory.mkdir()
    sources = log_replay_sources()
    log_dir, _ = PROCESS_LOGS.get()
    ledger = log_dir / "pairs.jsonl"
    references = {CYCLE7_BASELINE_SHA: baseline, COMPARISON_BASELINE_SHA: pre_bloom}
    profiles, failures = {}, []
    for append_order in LOG_REPLAY_ORDERS:
        trials = {sha: [] for sha in references}
        for seed in LOG_REPLAY_SEEDS:
            replay = ControlledLogReplay(directory / "workload.ndjson", sources, seed, append_order)

            def measure(binary, store):
                return measure_benchmark(binary, store, replay, reconcile=True, keep_alive=True, full_post_samples=True)

            for baseline_sha, reference in references.items():
                binaries = {"baseline": reference, "candidate": candidate}
                pairs = trials[baseline_sha]
                for repeat in range(1, CONTROLLED_REPLAY_REPEATS + 1):
                    order = ["baseline", "candidate"] if len(pairs) % 2 == 0 else ["candidate", "baseline"]
                    run = {"baseline_sha": baseline_sha, "candidate_sha": candidate_sha, "append_order": append_order,
                           "seed": seed, "repeat": repeat, "order": order, "workload_sha256": replay.digest}
                    pairs.append(log_replay_pair(binaries, directory, ledger, run, measure, controlled_replay_ratios))
            replay.path.unlink()
            del replay
        profiles[append_order] = {}
        for baseline_sha, pairs in trials.items():
            targets = log_replay_targets(pairs, append_order, baseline_sha)
            profiles[append_order][baseline_sha] = {"pairs": len(pairs), "targets": targets}
            failures.extend(f"{append_order}/{baseline_sha[:7]}/{name}"
                            for name, target in targets.items() if not target["passed"])
    return {"candidate_sha": candidate_sha, "baseline_shas": list(references),
            "profiles": profiles, "failed_targets": failures,
            "ledger": str(ledger.relative_to(log_dir.parent))}


def paired_ratios(baseline, candidate, *, small_batches=False):
    for key in ("workload_sha256", "profile", "seed", "rows", "batch_rows", "writers", "keep_alive"):
        if baseline[key] != candidate[key]:
            raise InfrastructureError(f"benchmark pair used different workload input: {key}")

    def measurements(result):
        metrics = {"durable_rows_per_second": result["rows_per_second"],
                   "peak_rss_kib": result["peak_rss_kib"], "restart_ready_ms": result["restart_ready_ms"]}
        if small_batches:
            metrics.update(durable_batches_per_second=result["batches_per_second"],
                           post_p95=result["post"]["p95_ms"], post_p99=result["post"]["p99_ms"])
        for phase in ("live", "restart"):
            for sample, category in (("broad", "wide"), ("narrow", "narrow"), ("rare_or_absent", "rare_or_absent")):
                metrics[f"{category}_query_p95/{phase}"] = result[f"{phase}_query"][sample]["p95_ms"]
        return metrics

    before, after = measurements(baseline), measurements(candidate)
    if any(not math.isfinite(value) or value <= 0 for value in (*before.values(), *after.values())):
        raise InfrastructureError("benchmark pair has invalid measurements")
    return {name: after[name] / value for name, value in before.items()}


def indexed_targets(pairs):
    if len(pairs) != len(BENCH_SEEDS) * BENCH_REPEATS:
        raise InfrastructureError("indexed performance needs every configured benchmark pair")
    return median_targets(pairs, INDEXED_TARGETS)


def median_targets(pairs, limits):
    targets = {}
    for metric in pairs[0]:
        comparison, target = limits[metric.partition("/")[0]]
        ratio = statistics.median(pair[metric] for pair in pairs)
        passed = ratio <= target if comparison == "<=" else ratio >= target
        targets[metric] = {"median_ratio": ratio, "comparison": comparison, "target": target, "passed": passed}
    return targets


def paired_performance_suite(baseline, candidate, directory, *, indexed, baseline_sha, candidate_sha):
    directory.mkdir()
    _, corpus = load_corpus()
    log_dir, _ = PROCESS_LOGS.get()
    ledger = log_dir / "pairs.jsonl"
    scenarios = BENCH_PROFILES if indexed else CYCLE3_PROFILES
    seeds = BENCH_SEEDS if indexed else BENCH_SEEDS[:2]
    repeats = BENCH_REPEATS if indexed else 2
    rows = BENCH_LARGE_ROWS if indexed else CYCLE3_COMPARE_ROWS
    batch_rows = BENCH_BATCH_ROWS if indexed else CYCLE3_BATCH_ROWS
    revisions = {"baseline_sha": baseline_sha, "candidate_sha": candidate_sha}
    profiles, failures = {}, []
    for profile, writers in scenarios.items():
        pairs = []
        for seed in seeds:
            workload = Benchmark(directory / "workload.ndjson", rows, profile, seed, corpus,
                                 batch_rows=batch_rows, writers=writers)
            for repeat in range(repeats):
                order = ["baseline", "candidate"] if len(pairs) % 2 == 0 else ["candidate", "baseline"]
                binaries = {"baseline": baseline, "candidate": candidate}
                results = {}
                for role in order:
                    prefix = f"{profile}-{seed}-{repeat + 1}-{role}-"
                    with tempfile.TemporaryDirectory(prefix=prefix, dir=directory) as store:
                        results[role] = measure_benchmark(binaries[role], Path(store), workload,
                                                          keep_alive=not indexed, reconcile=not indexed)
                ratios = paired_ratios(results["baseline"], results["candidate"], small_batches=not indexed)
                pairs.append(ratios)
                record = {**revisions, "profile": profile, "seed": seed, "repeat": repeat + 1, "order": order,
                          "ratios": ratios, **results}
                with ledger.open("a") as stream:
                    stream.write(json.dumps(record, sort_keys=True) + "\n")
                summary = {**revisions, "profile": profile, "seed": seed, "repeat": repeat + 1, "order": order,
                           "ratios": ratios, "workload_sha256": workload.digest}
                print("BOG_PERFORMANCE_PAIR " + json.dumps(summary, sort_keys=True))
            workload.path.unlink()
        profiles[profile] = {"pairs": len(pairs), "writers": writers,
                             "median_ratios": {key: statistics.median(pair[key] for pair in pairs)
                                               for key in pairs[0]}}
        if indexed:
            targets = indexed_targets(pairs)
            profiles[profile]["targets"] = targets
            failures.extend(f"{profile}/{key}" for key, value in targets.items() if not value["passed"])
    result = {**revisions,
              "rows_per_run": rows, "batch_rows": batch_rows,
              "profiles": profiles, "ledger": str(ledger.relative_to(log_dir.parent))}
    if indexed:
        result["failed_targets"] = failures
    return result


SUITES = (
    ("query-oracle", corpus_suite),
    ("snapshot-pagination", pagination_suite),
    ("query-limits", query_limits_suite),
    ("query-admission", query_admission_suite),
    ("query-response-bytes", query_response_bytes_suite),
    ("archived-corpus", replay_corpus_suite),
    ("request-rejection", rejection_suite),
    ("concurrent-snapshots", concurrency_suite),
    ("directory-lock", lock_suite),
    ("kill-durability", durability_suite),
    ("wal-recovery", recovery_suite),
    ("historical-surrogates", historical_surrogate_suite),
    ("enospc-recovery", enospc_suite),
    ("performance-smoke", performance_suite),
    ("log-replay", log_replay_suite),
)
REQUIRED_SUITES = (
    "query-oracle",
    "snapshot-pagination",
    "query-limits",
    "query-admission",
    "query-response-bytes",
    "archived-corpus",
    "request-rejection",
    "concurrent-snapshots",
    "directory-lock",
    "kill-durability",
    "wal-recovery",
    "historical-surrogates",
    "enospc-recovery",
    "performance-smoke",
    "log-replay",
)
EXTENDED_SUITES = (
    ("graceful-shutdown", shutdown_suite),
    ("full-disk-restart", full_disk_restart_suite),
    ("wal-handoff", wal_handoff_suite),
)
COMPARISON_SUITES = {"full": "small-batch-performance", "post-cycle": "small-batch-performance",
                     "indexed": "indexed-performance"}
LOG_REPLAY_COMPARISON = "log-replay-performance"
LOG_REPLAY_SMOKE = "log-replay-paired-smoke"
CYCLE7_HANDOFF = "cycle7-wal-handoff"
CYCLE7_PROFILES = ("pr", "full", "post-cycle")


def suite_plan(suites, profile, sha):
    if sha in (BASELINE_SHA, COMPARISON_BASELINE_SHA, CYCLE7_BASELINE_SHA):
        suites = tuple((name, run) for name, run in suites if name != "query-limits")
    if profile == "legacy":
        return tuple((name, run) for name, run in suites if name not in ("snapshot-pagination", "log-replay"))
    if profile in COMPARISON_SUITES:
        suites = (*suites, *EXTENDED_SUITES, (COMPARISON_SUITES[profile], paired_performance_suite))
    if profile in CYCLE7_PROFILES:
        suites += ((CYCLE7_HANDOFF, wal_handoff_suite), (LOG_REPLAY_SMOKE, paired_log_replay_suite))
    if profile == "post-cycle":
        suites += ((LOG_REPLAY_COMPARISON, controlled_log_replay_suite),)
    return suites


def build(source, work, log):
    binary = work / "bog"
    log.touch()
    check((source / "cmd" / "bog").is_dir(), "missing ./cmd/bog")
    try:
        with log.open("wb") as output:
            completed = subprocess.run(
                ["go", "build", "-mod=readonly", "-trimpath", "-o", str(binary), "./cmd/bog"], cwd=source,
                stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT, timeout=120,
            )
    except subprocess.TimeoutExpired as exc:
        raise Rejected("go build ./cmd/bog timed out after 120s") from exc
    if completed.returncode:
        tail = " ".join(log_tail(log, 1200).split())
        raise Rejected(f"go build ./cmd/bog failed (status {completed.returncode}): {tail}")
    check(not binary.is_symlink() and binary.is_file() and os.access(binary, os.X_OK),
          "go build ./cmd/bog did not produce an executable Bog binary")
    return binary


def build_baseline(source, work, evidence, baseline_sha, *, label="baseline"):
    revision = subprocess.run(["git", "rev-parse", "--verify", f"{baseline_sha}^{{commit}}"], cwd=source,
                              capture_output=True, text=True, timeout=15)
    if revision.returncode or revision.stdout.strip() != baseline_sha:
        raise InfrastructureError(f"comparison baseline revision {baseline_sha} is missing from the fetched history")
    baseline_dir = work / label
    baseline_dir.mkdir()
    checkout = baseline_dir / "source"
    fetched = subprocess.run(["git", "worktree", "add", "--detach", str(checkout), baseline_sha],
                             cwd=source, capture_output=True, text=True, timeout=30)
    if fetched.returncode:
        raise InfrastructureError(f"cannot check out comparison SHA {baseline_sha}: {fetched.stderr}")
    checked_out = subprocess.run(["git", "rev-parse", "--verify", "HEAD"], cwd=checkout,
                                 capture_output=True, text=True, timeout=15)
    if checked_out.returncode or checked_out.stdout.strip() != baseline_sha:
        raise InfrastructureError(f"comparison checkout does not match {baseline_sha}")
    log = evidence / f"{label}-build.log"
    try:
        binary = build(checkout, baseline_dir, log)
    except Rejected as exc:
        raise InfrastructureError(f"comparison baseline {baseline_sha} build failed: {exc}") from exc
    finally:
        if log.exists():
            print("BOG_BUILD " + json.dumps({"role": label, "sha": baseline_sha,
                                             "log_tail": log_tail(log, 4096)}))
    return binary


def diagnostic(exc):
    return (" ".join(str(exc).split()) or type(exc).__name__)[:560]


def file_sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def reject(work, sha, stage, completed, reason):
    (work / "rejection").write_text(f"Bog {sha} rejected in {stage} (suites={completed}): {reason}")
    return 1


def log_tail(path, size):
    with path.open("rb") as log:
        log.seek(max(0, path.stat().st_size - size))
        return log.read().decode(errors="replace")


def new_result(requested_sha, tested_sha, profile="pr"):
    required = suite_plan(tuple((name, None) for name in REQUIRED_SUITES), profile, tested_sha or requested_sha)
    baseline_sha = {"pr": CYCLE7_BASELINE_SHA, "full": COMPARISON_BASELINE_SHA, "post-cycle": COMPARISON_BASELINE_SHA,
                    "legacy": BASELINE_SHA, "indexed": BASELINE_SHA}.get(profile)
    return {
        "schema_version": 1, "requested_sha": requested_sha, "tested_sha": tested_sha,
        "profile": profile,
        "baseline_sha": baseline_sha,
        "corpus_sha256": CORPUS_SHA256, "apache_fixture_sha256": APACHE_SHA256,
        "git_daemon_fixture_sha256": GIT_DAEMON_SHA256, "syslog_fixture_sha256": SYSLOG_SHA256, "seeds": SEEDS,
        "run_name": os.environ.get("SLIPWAY_RUN_NAME"), "run_uid": os.environ.get("SLIPWAY_RUN_UID"),
        "step": os.environ.get("SLIPWAY_STEP_NAME"),
        "image_digest": os.environ.get("BOG_VERIFIER_IMAGE_DIGEST"),
        "build": {"status": "pending"},
        **({"baseline_build": {"sha": baseline_sha, "status": "pending"}} if profile in COMPARISON_SUITES else {}),
        **({"cycle7_baseline_build": {"sha": CYCLE7_BASELINE_SHA, "status": "pending"}}
           if profile in CYCLE7_PROFILES else {}),
        "suites": [{"name": name, "status": "pending"} for name, _ in required],
        "status": "running",
    }


def publish_result(work, code, reason, requested_sha, tested_sha, profile="pr"):
    evidence = work / "artifacts"
    evidence.mkdir(exist_ok=True)
    (evidence / "result.tmp").unlink(missing_ok=True)
    path = evidence / "result.json"
    result = json.loads(path.read_text()) if path.is_file() else new_result(requested_sha, tested_sha or None, profile)
    status = {0: "passed", 1: "rejected"}.get(code, "infra_error")
    if code == 0 and result["status"] != "passed":
        raise InfrastructureError("passing suite result is missing")
    result.update(status=status, exit_code=code)
    if reason and "diagnostic" not in result:
        result["diagnostic"] = reason
    builds = [result[key] for key in ("build", "baseline_build", "cycle7_baseline_build") if key in result]
    for check_result in [*builds, *result["suites"]]:
        if check_result["status"] == "pending":
            check_result["status"] = "blocked"
        if check_result["status"] == "running":
            check_result["status"] = "interrupted"
    line = json.dumps(result, sort_keys=True)
    path.write_text(line + "\n")
    print("BOG_RESULT " + line)


def main(source, work, sha, profile="pr"):
    evidence = work / "artifacts"
    evidence.mkdir()
    build_log = evidence / "build.log"
    result = new_result(sha, sha, profile)
    required = tuple(suite["name"] for suite in result["suites"])
    suites = suite_plan(SUITES, profile, sha)
    result["build"].update(status="running", log="build.log")

    def checkpoint():
        temporary = evidence / "result.tmp"
        temporary.write_text(json.dumps(result, sort_keys=True) + "\n")
        temporary.replace(evidence / "result.json")

    def finish(status, reason=None):
        result["status"] = status
        if reason:
            result["diagnostic"] = reason
        checkpoint()

    checkpoint()
    (work / "stage").write_text(f"build, 0/{len(required)} suites completed")
    try:
        check(profile != "legacy" or sha == BASELINE_SHA,
              f"legacy mode requires pinned Cycle 1 SHA {BASELINE_SHA}")
        binary = build(source, work, build_log)
    except Rejected as exc:
        reason = diagnostic(exc)
        result["build"].update(status="rejected", diagnostic=reason)
        for suite in result["suites"]:
            suite.update(status="blocked", diagnostic="build prerequisite failed")
        finish("rejected", f"build: {reason}")
        return reject(work, sha, "build", 0, reason)
    finally:
        if build_log.exists():
            print("BOG_BUILD " + json.dumps({"role": "candidate", "sha": sha, "log_tail": log_tail(build_log, 4096)}))

    digest = file_sha256(binary)
    result["build"].update(status="passed", binary_sha256=digest)
    print(f"binary_sha256={digest} candidate_sha={sha}")
    if not SUITES:
        reason = "zero verification suites registered"
        finish("rejected", reason)
        return reject(work, sha, "harness", 0, reason)
    if tuple(name for name, _ in suites) != required:
        finish("infra_error", "suite registry does not match the required suite list")
        return 2

    completed = []
    skipped = 0
    rejected = []
    errors = []
    baselines = {}
    comparison_stage = COMPARISON_SUITES.get(profile)
    baseline_sha = result["baseline_sha"]
    for label, key in (("baseline", "baseline_build"), ("cycle7-baseline", "cycle7_baseline_build")):
        if key not in result:
            continue
        baseline_build = result[key]
        commit = baseline_build["sha"]
        print(f"bog comparison candidate_sha={sha} {label}_sha={commit}")
        (work / "stage").write_text(f"{label} build {commit}, 0/{len(required)} suites completed")
        baseline_build.update(status="running")
        checkpoint()
        try:
            baselines[label] = build_baseline(source, work, evidence, commit, label=label)
        except (InfrastructureError, subprocess.TimeoutExpired) as exc:
            reason = diagnostic(exc)
            print(f"ERROR {label} {commit}: {reason}", file=sys.stderr)
            baseline_build.update(status="infra_error", diagnostic=reason)
            finish("infra_error", reason)
            return 2
        finally:
            log_name = f"{label}-build.log"
            if (evidence / log_name).exists():
                baseline_build["log"] = log_name
                checkpoint()
        baseline_build.update(status="passed", binary_sha256=file_sha256(baselines[label]))
        checkpoint()

    for (stage, run), suite in zip(suites, result["suites"]):
        if stage in (comparison_stage, LOG_REPLAY_SMOKE, LOG_REPLAY_COMPARISON) and (rejected or errors):
            suite.update(status="blocked", diagnostic="correctness or smoke prerequisite failed")
            continue
        log_dir = evidence / stage
        log_dir.mkdir()
        suite.update(status="running", processes=[])
        checkpoint()
        (work / "stage").write_text(f"{stage}, {len(completed)}/{len(required)} suites completed")
        print(f"RUN {stage}")
        started = time.monotonic()
        token = PROCESS_LOGS.set((log_dir, suite["processes"]))
        try:
            if stage == "wal-handoff":
                metrics = run(baselines["baseline"], binary, work / stage, baseline_sha)
            elif stage == CYCLE7_HANDOFF:
                metrics = run(baselines["cycle7-baseline"], binary, work / stage, CYCLE7_BASELINE_SHA)
            elif stage == comparison_stage:
                metrics = run(baselines["baseline"], binary, work / stage, indexed=profile == "indexed",
                              baseline_sha=baseline_sha, candidate_sha=sha)
            elif stage == LOG_REPLAY_SMOKE:
                metrics = run(baselines["cycle7-baseline"], binary, work / stage,
                              baseline_sha=CYCLE7_BASELINE_SHA, candidate_sha=sha)
            elif stage == LOG_REPLAY_COMPARISON:
                metrics = run(baselines["cycle7-baseline"], baselines["baseline"], binary, work / stage,
                              candidate_sha=sha)
            elif stage == "kill-durability" and profile == "post-cycle":
                metrics = run(binary, work / stage, rounds=56)
            elif stage == "kill-durability" and profile == "legacy":
                metrics = run(binary, work / stage, paged=False)
            else:
                metrics = run(binary, work / stage)
            if isinstance(metrics, SuiteSkipped):
                suite.update(status="skipped", diagnostic=metrics.reason)
                completed.append(stage)
                skipped += 1
                print(f"SKIP {stage}: {metrics.reason}")
                continue
            if metrics is not None:
                suite["metrics"] = metrics
            if stage == LOG_REPLAY_COMPARISON or (profile == "indexed" and stage == comparison_stage):
                failed = metrics["failed_targets"]
                check(not failed, f"{stage} missed {len(failed)} targets: {', '.join(failed)}")
            if not any(case.get("ready_ms") is not None for case in suite["processes"]):
                raise InfrastructureError("required suite ran without a ready Bog subprocess")
        except (Rejected, subprocess.TimeoutExpired, threading.BrokenBarrierError,
                ConnectionError, TimeoutError, http.client.HTTPException) as exc:
            reason = diagnostic(exc)
            print(f"FAIL {stage}: {reason}")
            suite.update(status="rejected", diagnostic=reason)
            rejected.append((stage, reason))
        except Exception as exc:
            reason = diagnostic(exc)
            print(f"ERROR {stage}: {reason}")
            suite.update(status="infra_error", diagnostic=reason)
            errors.append(stage)
        else:
            completed.append(stage)
            suite["status"] = "passed"
            print(f"PASS {stage} seconds={time.monotonic() - started:.3f}")
        finally:
            PROCESS_LOGS.reset(token)
            suite["elapsed_ms"] = milliseconds(time.monotonic() - started)
            checkpoint()

    print(f"candidate_sha={sha} binary_sha256={digest} "
          f"suites_passed={len(completed) - skipped}/{len(required)} suites_skipped={skipped} "
          f"suites_rejected={len(rejected)} suites_infra_error={len(errors)}")
    if errors:
        finish("infra_error", f"required suites with infrastructure errors: {', '.join(errors)}")
        return 2
    if rejected:
        stage, reason = rejected[0]
        failed = ", ".join(name for name, _ in rejected)
        finish("rejected", f"{stage}: {reason} (failed: {failed})")
        return reject(work, sha, stage, len(completed), f"{reason} (failed: {failed})")
    if tuple(completed) != required:
        finish("infra_error", "required suite execution did not complete")
        return 2
    finish("passed")
    (work / "passed").write_text(f"{sha} {digest} {len(completed)}\n")
    print(f"verified_sha={sha} binary_sha256={digest} suites={len(completed)}")
    return 0


if __name__ == "__main__":
    try:
        if sys.argv[1] == "--report":
            publish_result(Path(sys.argv[2]), int(sys.argv[3]), *sys.argv[4:])
            sys.exit(0)
        if sys.argv[1] == "--baseline":
            print(BASELINE_SHA)
            sys.exit(0)
        sys.exit(main(Path(sys.argv[1]), Path(sys.argv[2]), *sys.argv[3:]))
    except Exception as exc:
        print(f"ERROR harness: {diagnostic(exc)}", file=sys.stderr)
        raise SystemExit(2) from exc
