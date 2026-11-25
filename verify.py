"""Black-box Bog verifier. Run through verify.sh."""
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
SEEDS = {
    "query-oracle": 0xB061, "kill-durability": 0xB067, "performance-smoke": 0xB070,
    "apache-replay": 0xB091, "snapshot-pagination": 0xB102,
}
PROCESS_LOGS = contextvars.ContextVar("process_logs")


class Rejected(Exception):
    pass


class InfrastructureError(Exception):
    pass


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

    def __init__(self, binary, directory, log_path):
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
                    [str(binary), "-addr", f"127.0.0.1:{self.port}", "-data-dir", str(directory)],
                    cwd=directory, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                )
            except (FileNotFoundError, PermissionError) as exc:
                raise Rejected(f"unable to launch Bog: {exc}") from exc

    def exchange(self, method, target, body=None, timeout=HTTP_TIMEOUT):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=timeout)
        try:
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
        finally:
            conn.close()

    def request(self, method, target, body=None):
        status, data, _ = self.checked_exchange(method, target, body)
        return status, data

    def checked_exchange(self, method, target, body=None):
        try:
            return self.exchange(method, target, body)
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

    def ingest_body(self, payload, count):
        status, body = self.request("POST", "/ingest", payload)
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
        status, body, headers = self.checked_exchange("GET", query_target(args))
        check(status == 200, f"query returned {status}: {body[:200]!r}")
        cursors = headers.get_all(NEXT_CURSOR)
        if cursors is not None:
            check(len(cursors) == 1 and bool(cursors[0].strip()),
                  f"expected a single nonempty {NEXT_CURSOR}")
        return decode_rows(body), cursors[0] if cursors else None


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
def run_bog(binary, directory, *, ready=True):
    log_dir, cases = PROCESS_LOGS.get()
    path = log_dir / f"bog-{len(cases):02d}.log"
    case = {"store": directory.name, "log": str(path.relative_to(log_dir.parent)),
            "expected_ready": ready}
    cases.append(case)
    try:
        bog = Bog(binary, directory, path)
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
        original = oracle(rows, snapshot_start, snapshot_end)
        active = expect_page(bog, snapshot_args, original, 0, 2, None, "first page before backfill")
        late = [Row(snapshot_start + i, f"backfilled snapshot row {i}") for i in (100, 60, 30, 5, 15, 20)]
        late.append(Row(11, "backfilled row at the cursor's timestamp"))
        bog.ingest(late)
        expect_walk(bog, snapshot_args, original, (2,), "active walk after backfill", position=2, cursor=active)
        expect_walk(bog, args, expected, (1, 1000), "active tied walk after backfill",
                    position=DEFAULT_QUERY_LIMIT, cursor=saved)
        rows.extend(late)
        expect_walk(bog, snapshot_args, oracle(rows, snapshot_start, snapshot_end),
                    (2, 1, 1000), "fresh walk after backfill")
        expect_walk(bog, args, oracle(rows, 11, 12), (1000,), "fresh tied walk after backfill")
        bog.kill()

    with run_bog(binary, directory) as bog:
        expect_bad_query(bog, continuation, "cursor from the previous process")
        expect_bad_query(bog, {**snapshot_args, "cursor": active}, "backfill cursor from the previous process")
        expect_walk(bog, query_args(beginning, end_of_time), oracle(rows, beginning, end_of_time),
                    (1000,), "fresh full walk after WAL replay")


def rejection_suite(binary, directory):
    good = [Row(1, "acknowledged before bad ingest")]
    prefix = encode_rows([Row(2, "must never commit")])
    valid_ts = stamp(3).encode()
    limit_rows = [Row(100 + i, f"body size limit row={i:03} " + "x" * 32_000) for i in range(128)]
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
        valid = [Row(3, "literal � and \\ud800"), Row(3, "paired 🙂"), Row(4, "")]
        wire = (encode_rows(valid[:1]).replace(b"\n", b"\r\n") + b"\n"
                + b'{"ts":"' + valid_ts + b'","line":"paired \\ud83d\\ude42"}\n'
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
    writers = 4
    batches = [
        [dataclasses.replace(row, ns=0 if index < 4 else row.ns + 1)
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
        check(Counter(actual) == Counter(row for i in seen for row in batches[i]),
              f"{label}: partial or duplicated batch")
        times = [row.ns for row in actual]
        check(times == sorted(times), f"{label}: rows out of timestamp order")
        tied_batches = set()
        for index, group in itertools.groupby((row for row in actual if row.ns == 0), batch_by_row.get):
            check(index not in tied_batches, f"{label}: interleaved concurrent ties")
            tied_batches.add(index)
            expect_rows(list(group), batches[index][:4], f"{label}: tie order within batch {index}")
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

        futures = [pool.submit(write, worker) for worker in range(writers)]
        go.wait(timeout=HTTP_TIMEOUT)
        for event in first_invoked:
            check(event.wait(HTTP_TIMEOUT), "writer did not reach the first snapshot")
        previous = set()
        previous_rows = []
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
            expect_rows([row for row in actual if batch_by_row[row] in previous], previous_rows,
                        f"snapshot {sample}, stable concurrent tie order")
            previous = seen
            previous_rows = actual
            if all(future.done() for future in futures):
                break
        for future in futures:
            future.result(timeout=HTTP_TIMEOUT)
        all_rows = bog.query(0, end)
        check(inspect_snapshot(all_rows, "all concurrent writes") == set(range(len(batches))),
              "final snapshot missed acknowledged batches")
        ties = [row for row in all_rows if row.ns == 0]
        expect_rows(bog.query(0, 1, limit=13), ties[:13], "limit within concurrent ties")
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
        expect_rows(bog.query(0, end + 2), all_rows + pending, "concurrent tie order after replay")
        expect_rows(bog.query(0, 1, limit=13), ties[:13], "limit within concurrent ties after replay")


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


def durability_suite(binary, directory):
    seed = SEEDS["kill-durability"]
    rng = random.Random(seed)
    phases = ["idle", "partial-upload", "full-upload", "observed-204"] * 6
    rng.shuffle(phases)
    lower = parse_stamp("0001-01-01T00:00:00Z")
    upper = parse_stamp("9999-12-31T23:59:59.999999999Z")
    history = []
    trials = []
    log_dir, _ = PROCESS_LOGS.get()
    ledger = log_dir / "ledger.jsonl"

    def record(event):
        wire = json.dumps(event, sort_keys=True)
        with ledger.open("a") as stream:
            stream.write(wire + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        print("BOG_SIGKILL " + wire, flush=True)

    def probe(bog):
        # All expected rows fit in one bounded query over the supported time domain.
        actual = bog.query(lower, upper, limit=MAX_QUERY_LIMIT)
        check(len(actual) < MAX_QUERY_LIMIT, "SIGKILL reconciliation reached the query limit")
        return actual

    for trial, phase in enumerate(phases, 1):
        tag = f"crash/{seed:04x}/{trial:02}/{phase}"
        base = trial * 32
        padding = rng.randrange(256, 4097)
        row_count = rng.randrange(4, 13)
        delay = rng.choice((0, 0.0003, 0.001, 0.004))
        acknowledged = [Row(base, tag + "/pre-ack")]
        rejected = [Row(base + 1, tag + "/pre-reject")]
        target = [Row(base + 2 + i, f"{tag}/target/{i:02} " + "x" * padding)
                  for i in range(row_count)]
        payload = encode_rows(target)
        event = {"trial": trial, "phase": phase, "tag": tag, "seed": seed,
                 "row_count": row_count, "padding": padding, "delay_ms": delay * 1000,
                 "first_ns": base, "payload_sha256": hashlib.sha256(payload).hexdigest()}
        record({**event, "event": "plan"})
        outcome = {"idle": "not-sent", "partial-upload": "incomplete", "full-upload": "unknown",
                   "observed-204": "acknowledged"}[phase]
        uploaded, status, response_ready = 0, None, None
        with run_bog(binary, directory) as bog:
            bog.ingest(acknowledged)
            record({"trial": trial, "batch": tag + "/pre-ack", "outcome": "acknowledged", "status": 204})
            status, _ = bog.request("POST", "/ingest", encode_rows(rejected) + b'{"ts":')
            record({"trial": trial, "batch": tag + "/pre-reject", "outcome": "rejected", "status": status})
            check(status == 400, f"{tag}/pre-reject: expected HTTP 400, got {status}")
            history.extend(acknowledged)

            if phase == "idle":
                expect_rows(probe(bog), history, f"{tag}: idle state before kill")
                bog.kill()
            else:
                with bog.open_ingest(len(payload), expect_continue=True) as client:
                    uploaded = payload.index(b"\n") + 1 if phase == "partial-upload" else len(payload)
                    client.send(payload[:uploaded])
                    if phase == "partial-upload":
                        expect_rows(probe(bog), history, f"{tag}: prefix visible before kill")
                    if delay:
                        time.sleep(delay)
                    response_ready = bool(select.select([client.sock], [], [], 0)[0])
                    if phase == "observed-204":
                        with client.getresponse() as response:
                            status = response.status
                        check(status == 204, f"{tag}: expected HTTP 204 before SIGKILL, got {status}")
                    bog.kill()
            record({"trial": trial, "batch": tag + "/target", "outcome": outcome,
                    "uploaded_bytes": uploaded, "declared_bytes": len(payload),
                    "socket_readable_before_kill": response_ready, "status": status,
                    "signal": "SIGKILL"})

        with run_bog(binary, directory) as bog:
            actual = probe(bog)
            counts = Counter(actual)
            copies = [counts[row] for row in target]
            allowed = {"not-sent": [[0] * row_count], "incomplete": [[0] * row_count],
                       "unknown": [[0] * row_count, [1] * row_count],
                       "acknowledged": [[1] * row_count]}[outcome]
            check(copies in allowed, f"{tag}: {outcome} batch recovered with row multiplicities {copies}")
            check(all(counts[row] == 0 for row in rejected), f"{tag}: rejected batch survived")
            if copies[0]:
                history.extend(target)
            expect_rows(actual, history, f"{tag}: missing, duplicated, phantom, or misordered rows after restart")
        trials.append({**event, "outcome": outcome, "recovered_rows": sum(copies),
                       "total_recovered_rows": len(history)})
        record({**trials[-1], "event": "reconciliation"})
    return {"trials": trials, "phase_counts": dict(Counter(phases)),
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
        try:
            with run_bog(binary, case, ready=False):
                pass
            for name in committed:
                path = case / name
                observed = path.read_bytes() if path.exists() else None
                check(observed == files.get(name), f"{label}: refused startup changed {name}")
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


def wal_handoff_suite(baseline, candidate, directory):
    directory.mkdir()
    verified = []
    for source, target, name in [(baseline, candidate, "legacy-to-candidate"),
                                 (candidate, baseline, "candidate-to-legacy")]:
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
            expect_query(bog, source_rows, -5, 15, label=f"{name}: original writer")
            bog.kill()
        original = data_files(case / "source")
        write_data_copy(case / "target", original)
        with run_bog(target, case / "target") as bog:
            expect_query(bog, source_rows, -5, 15, label=f"{name}: target replay")
            check(data_files(case / "target") == original, f"{name}: target rewrote the committed files")
            bog.ingest(target_rows)
            expect_query(bog, source_rows + target_rows, -5, 15, label=f"{name}: target append")
            bog.kill()
        extended = data_files(case / "target")
        check(extended["bog.wal"].startswith(original["bog.wal"])
              and len(extended["bog.wal"]) > len(original["bog.wal"]),
              f"{name}: target did not append to the original WAL")
        write_data_copy(case / "return", extended)
        with run_bog(source, case / "return") as bog:
            expect_query(bog, source_rows + target_rows, -5, 15,
                         label=f"{name}: original writer reopens target append")
            bog.stop()
        check(data_files(case / "return") == extended, f"{name}: source rewrote target's committed files")
        verified.append({"direction": name, "source_rows": len(source_rows), "appended_rows": len(target_rows),
                         "initial_wal_sha256": hashlib.sha256(original["bog.wal"]).hexdigest(),
                         "extended_wal_sha256": hashlib.sha256(extended["bog.wal"]).hexdigest()})
    return {"baseline_sha": BASELINE_SHA, "directions": verified}


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
    interrupted = [Row(3 + i, f"ENOSPC failed row {i}: " + "x" * 16_384) for i in range(32)]
    payload = encode_rows(interrupted)
    resumed = [dataclasses.replace(row, line=row.line.replace("failed", "rescue", 1)) for row in interrupted]
    with tempfile.TemporaryDirectory(prefix="bog-enospc-", dir=mount) as tmp:
        store = Path(tmp) / "store"
        with run_bog(binary, store) as bog:
            bog.ingest(history)
            bog.kill()
        prior = data_files(store)
        filler = Path(tmp) / "filler"
        with run_bog(binary, store) as bog:
            constrain_append(filler, capacity, len(payload))
            status, response = bog.request("POST", "/ingest", payload)
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
    return {"available": True, "capacity_bytes": capacity, "kernel_errno": errno.ENOSPC}


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


def latency_metrics(seconds):
    ordered = sorted(seconds)
    return {
        "samples_ms": [milliseconds(value) for value in seconds],
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


class Benchmark:
    """One seeded set of HTTP bodies and expected results shared by both binaries."""

    def __init__(self, path, count, profile, seed, corpus):
        self.path = path
        self.count = count
        self.profile = profile
        self.seed = seed
        self.writers = BENCH_PROFILES[profile]
        rng = random.Random(seed)
        self.lines = [row.line for row in corpus if len(row.line.encode()) <= 128]
        rng.shuffle(self.lines)

        starts = list(range(0, count, BENCH_BATCH_ROWS))
        if profile == "backfill":
            rng.shuffle(starts)
        digest = hashlib.sha256()
        self.batches = []
        with path.open("wb") as stream:
            for start in starts:
                indices = range(start, min(start + BENCH_BATCH_ROWS, count))
                payload = encode_rows(self.rows(indices))
                self.batches.append((stream.tell(), len(payload), len(indices)))
                stream.write(payload)
                digest.update(payload)
        self.digest = digest.hexdigest()
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

    def query_metrics(self, bog):
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
                        self.rows(range(left, right)), f"smoke {phase}, row interval [{left}, {right})")
        beginning = parse_stamp("0001-01-01T00:00:00Z")
        end = parse_stamp("9999-12-31T23:59:59.999999999Z")
        expect_rows(bog.query(beginning, 0), [], f"smoke {phase}, before corpus")
        expect_rows(bog.query(self.count * SECOND, end), [], f"smoke {phase}, after corpus")


def measure_benchmark(binary, directory, workload, *, reconcile=False):
    start_writers = threading.Barrier(workload.writers + 1)
    with run_bog(binary, directory) as bog, ThreadPoolExecutor(max_workers=workload.writers) as pool:
        def write(worker):
            durations = []
            with workload.path.open("rb") as fixture:
                start_writers.wait(timeout=HTTP_TIMEOUT)
                for position, size, rows in workload.batches[worker::workload.writers]:
                    fixture.seek(position)
                    payload = fixture.read(size)
                    if len(payload) != size:
                        raise InfrastructureError("benchmark fixture truncated")
                    started = time.monotonic()
                    bog.ingest_body(payload, rows)
                    durations.append(time.monotonic() - started)
            return durations

        empty_ready_ms = milliseconds(bog.startup_seconds)
        futures = [pool.submit(write, worker) for worker in range(workload.writers)]
        started = time.monotonic()
        start_writers.wait(timeout=HTTP_TIMEOUT)
        post_times = [duration for future in futures for duration in future.result()]
        elapsed = time.monotonic() - started
        live_queries = workload.query_metrics(bog)
        if reconcile:
            workload.reconcile(bog, "before restart")
        live_rss = peak_rss_kib(bog.process)
        bog.kill()

    wal = directory / "bog.wal"
    check(wal.is_file() and wal.stat().st_size > len(WAL_MAGIC), "benchmark WAL is empty")
    with run_bog(binary, directory) as bog:
        restart_ms = milliseconds(bog.startup_seconds)
        restart_queries = workload.query_metrics(bog)
        if reconcile:
            workload.reconcile(bog, "after restart")
        restart_rss = peak_rss_kib(bog.process)
        bog.stop()
    return {
        "rows": workload.count, "batch_rows": BENCH_BATCH_ROWS, "writers": workload.writers,
        "profile": workload.profile, "seed": workload.seed, "workload_sha256": workload.digest,
        "rows_per_second": round(workload.count / elapsed, 2),
        "mib_per_second": round(workload.size / (1024 ** 2 * elapsed), 2),
        "ingest_elapsed_ms": milliseconds(elapsed), "post": latency_metrics(post_times),
        "live_query": live_queries, "restart_query": restart_queries,
        "empty_ready_ms": empty_ready_ms, "restart_ready_ms": restart_ms,
        "live_peak_rss_kib": live_rss, "restart_peak_rss_kib": restart_rss,
        "peak_rss_kib": max(live_rss, restart_rss),
        "wal_bytes": wal.stat().st_size,
    }


def performance_suite(binary, directory):
    directory.mkdir()
    _, corpus = load_corpus()
    workload = Benchmark(directory / "workload.ndjson", 100_000, "backfill", BENCH_SEEDS[0], corpus)
    return measure_benchmark(binary, directory / "store", workload, reconcile=True)


def paired_ratios(baseline, candidate):
    if baseline["workload_sha256"] != candidate["workload_sha256"]:
        raise InfrastructureError("benchmark pair used different fixture bytes")

    def measurements(result):
        metrics = {"durable_rows_per_second": result["rows_per_second"],
                   "peak_rss_kib": result["peak_rss_kib"], "restart_ready_ms": result["restart_ready_ms"]}
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
    targets = {}
    for metric in pairs[0]:
        comparison, target = INDEXED_TARGETS[metric.partition("/")[0]]
        ratio = statistics.median(pair[metric] for pair in pairs)
        passed = ratio <= target if comparison == "<=" else ratio >= target
        targets[metric] = {"median_ratio": ratio, "comparison": comparison, "target": target, "passed": passed}
    return targets


def indexed_performance_suite(baseline, candidate, directory):
    directory.mkdir()
    _, corpus = load_corpus()
    log_dir, _ = PROCESS_LOGS.get()
    ledger = log_dir / "pairs.jsonl"
    profiles, failures = {}, []
    for profile in BENCH_PROFILES:
        pairs = []
        for seed in BENCH_SEEDS:
            workload = Benchmark(directory / "workload.ndjson", BENCH_LARGE_ROWS, profile, seed, corpus)
            for repeat in range(BENCH_REPEATS):
                order = ["baseline", "candidate"] if len(pairs) % 2 == 0 else ["candidate", "baseline"]
                binaries = {"baseline": baseline, "candidate": candidate}
                results = {}
                for role in order:
                    prefix = f"{profile}-{seed}-{repeat + 1}-{role}-"
                    with tempfile.TemporaryDirectory(prefix=prefix, dir=directory) as store:
                        results[role] = measure_benchmark(binaries[role], Path(store), workload)
                ratios = paired_ratios(results["baseline"], results["candidate"])
                pairs.append(ratios)
                record = {"profile": profile, "seed": seed, "repeat": repeat + 1, "order": order,
                          "ratios": ratios, **results}
                with ledger.open("a") as stream:
                    stream.write(json.dumps(record, sort_keys=True) + "\n")
                summary = {"profile": profile, "seed": seed, "repeat": repeat + 1, "order": order,
                           "ratios": ratios, "workload_sha256": workload.digest}
                print("BOG_PERFORMANCE_PAIR " + json.dumps(summary, sort_keys=True))
            workload.path.unlink()
        targets = indexed_targets(pairs)
        profiles[profile] = {"pairs": len(pairs), "targets": targets}
        failures.extend(f"{profile}/{key}" for key, value in targets.items() if not value["passed"])
    return {"baseline_sha": BASELINE_SHA, "rows_per_run": BENCH_LARGE_ROWS,
            "profiles": profiles, "failed_targets": failures, "ledger": str(ledger.relative_to(log_dir.parent))}


SUITES = (
    ("query-oracle", corpus_suite),
    ("snapshot-pagination", pagination_suite),
    ("archived-corpus", replay_corpus_suite),
    ("request-rejection", rejection_suite),
    ("concurrent-snapshots", concurrency_suite),
    ("directory-lock", lock_suite),
    ("graceful-shutdown", shutdown_suite),
    ("kill-durability", durability_suite),
    ("wal-recovery", recovery_suite),
    ("historical-surrogates", historical_surrogate_suite),
    ("wal-handoff", wal_handoff_suite),
    ("enospc-recovery", enospc_suite),
    ("full-disk-restart", full_disk_restart_suite),
    ("performance-smoke", performance_suite),
)
REQUIRED_SUITES = (
    "query-oracle",
    "snapshot-pagination",
    "archived-corpus",
    "request-rejection",
    "concurrent-snapshots",
    "directory-lock",
    "graceful-shutdown",
    "kill-durability",
    "wal-recovery",
    "historical-surrogates",
    "wal-handoff",
    "enospc-recovery",
    "full-disk-restart",
    "performance-smoke",
)
LEGACY_OMISSIONS = {"snapshot-pagination", "wal-handoff"}
POST_CYCLE_SUITE = ("indexed-performance", indexed_performance_suite)


def suite_plan(suites, profile):
    if profile == "legacy":
        return tuple((name, run) for name, run in suites if name not in LEGACY_OMISSIONS)
    if profile == "post-cycle":
        return (*suites, POST_CYCLE_SUITE)
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


def build_baseline(source, work, evidence):
    ancestor = subprocess.run(["git", "merge-base", "--is-ancestor", BASELINE_SHA, "HEAD"], cwd=source,
                              capture_output=True, timeout=15)
    check(ancestor.returncode == 0, f"candidate checkout does not descend from pinned Cycle 1 SHA {BASELINE_SHA}")
    baseline_dir = work / "baseline"
    baseline_dir.mkdir()
    checkout = baseline_dir / "source"
    fetched = subprocess.run(["git", "worktree", "add", "--detach", str(checkout), BASELINE_SHA],
                             cwd=source, capture_output=True, text=True, timeout=30)
    if fetched.returncode:
        raise InfrastructureError(f"cannot check out pinned Cycle 1 SHA {BASELINE_SHA}: {fetched.stderr}")
    log = evidence / "baseline-build.log"
    try:
        binary = build(checkout, baseline_dir, log)
    except Rejected as exc:
        raise InfrastructureError(f"pinned Cycle 1 baseline build failed: {exc}") from exc
    finally:
        if log.exists():
            print("BOG_BUILD " + json.dumps({"role": "baseline", "sha": BASELINE_SHA,
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
    required = suite_plan(tuple((name, None) for name in REQUIRED_SUITES), profile)
    return {
        "schema_version": 1, "requested_sha": requested_sha, "tested_sha": tested_sha,
        "profile": profile, "baseline_sha": BASELINE_SHA,
        "corpus_sha256": CORPUS_SHA256, "apache_fixture_sha256": APACHE_SHA256, "seeds": SEEDS,
        "run_name": os.environ.get("SLIPWAY_RUN_NAME"), "run_uid": os.environ.get("SLIPWAY_RUN_UID"),
        "step": os.environ.get("SLIPWAY_STEP_NAME"),
        "image_digest": os.environ.get("BOG_VERIFIER_IMAGE_DIGEST"),
        "build": {"status": "pending"},
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
    for check_result in [result["build"], *result["suites"]]:
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
    suites = suite_plan(SUITES, profile)
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
            print("BOG_BUILD " + json.dumps({"log_tail": log_tail(build_log, 4096)}))

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
    rejected = []
    errors = []
    baseline = None
    for (stage, run), suite in zip(suites, result["suites"]):
        if stage == POST_CYCLE_SUITE[0] and (rejected or errors):
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
                baseline = build_baseline(source, work, evidence)
                result["baseline_build"] = {"sha": BASELINE_SHA, "binary_sha256": file_sha256(baseline),
                                            "log": "baseline-build.log"}
            if stage in ("wal-handoff", POST_CYCLE_SUITE[0]):
                metrics = run(baseline, binary, work / stage)
            else:
                metrics = run(binary, work / stage)
            if metrics is not None:
                suite["metrics"] = metrics
            if stage == POST_CYCLE_SUITE[0]:
                failed = metrics["failed_targets"]
                check(not failed, f"indexed performance missed {len(failed)} targets: {', '.join(failed)}")
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
          f"suites_passed={len(completed)}/{len(required)} "
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
