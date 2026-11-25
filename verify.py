"""Black-box Bog verifier. Run through verify.sh."""
import contextlib
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
import signal
import socket
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
FRAME = struct.Struct("<III")
MAX_FRAME = 4 * 1024 * 1024
HTTP_TIMEOUT = 5
START_TIMEOUT = 12
CORPUS_PATH = Path(__file__).resolve().parent / "corpus" / "replay.ndjson"
CORPUS_SHA256 = "7b79f2ac83692126019934e6a7738524aaa55f3e2151237d8421cae0539aff72"
CORPUS_SOURCES = {"access": 513, "error": 36, "app": 1009, "seed": 1000}


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


def decode_rows(body):
    try:
        result = []
        for line in body.split(b"\n"):
            if not line.strip():
                continue
            value = json.loads(line.decode("utf-8"))
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

    def http(self, method, target, body=None, timeout=HTTP_TIMEOUT):
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
                return response.status, data
        finally:
            conn.close()

    def request(self, method, target, body=None):
        try:
            return self.http(method, target, body)
        except (OSError, http.client.HTTPException) as exc:
            raise Rejected(f"{method} {target} failed: {exc}; {self.log_tail()}") from exc

    def log_tail(self):
        with self.log_path.open("rb") as log:
            log.seek(max(0, self.log_path.stat().st_size - 1200))
            tail = " ".join(log.read().decode(errors="replace").split())
        return tail or "(empty process log)"

    def ready(self):
        return self.http("GET", "/healthz", timeout=0.2)[0] == 200

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
                check(should_start, "Bog became ready when startup should have failed")
                check(self.process.poll() is None, f"Bog exited at readiness: {self.log_tail()}")
                return time.monotonic() - self.started
            time.sleep(0.025)
        expectation = "become ready" if should_start else "exit with a startup error"
        raise Rejected(f"Bog did not {expectation} in {START_TIMEOUT}s: {self.log_tail()}")

    def kill(self):
        check(self.process.poll() is None, f"Bog exited before SIGKILL: {self.log_tail()}")
        self.process.kill()
        check(self.process.wait(timeout=5) == -signal.SIGKILL, "Bog did not exit via SIGKILL")

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
    def open_ingest(self, length):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=HTTP_TIMEOUT)
        try:
            conn.putrequest("POST", "/ingest")
            conn.putheader("Content-Type", "application/x-ndjson")
            conn.putheader("Content-Length", str(length))
            conn.endheaders()
            yield conn
        finally:
            conn.close()

    @contextlib.contextmanager
    def partial_ingest(self, rows):
        body = encode_rows(rows)
        with self.open_ingest(len(body)) as conn:
            split = body.index(b"\n") + 1
            conn.send(body[:split])
            yield
            conn.send(body[split:])
            with conn.getresponse() as response:
                check(response.status == 204,
                      f"completed partial POST returned {response.status}")

    def query(self, start, end, contains="", limit=500, offset=0):
        args = {"start": stamp(start, offset), "end": stamp(end, offset)}
        if limit is not None:
            args["limit"] = limit
        if contains:
            args["contains"] = contains
        status, body = self.request("GET", "/query?" + urllib.parse.urlencode(args))
        check(status == 200, f"query returned {status}: {body[:200]!r}")
        return decode_rows(body)


@contextlib.contextmanager
def run_bog(binary, directory, *, ready=True, log_directory=None):
    path = (log_directory or directory.parent) / f"bog-{next(LOG_IDS)}.log"
    try:
        bog = Bog(binary, directory, path)
        try:
            bog.startup_seconds = bog.wait_startup(ready)
            yield bog
        finally:
            bog.close()
    finally:
        path.unlink(missing_ok=True)


LOG_IDS = itertools.count()


def expect_rows(actual, expected, label):
    for index, (got, wanted) in enumerate(zip(actual, expected)):
        if got != wanted:
            # Raw lines can be large. Keep the termination message bounded.
            raise Rejected(f"{label}: row {index} differs, expected {repr(wanted)[:200]}, "
                           f"got {repr(got)[:200]}")
    check(len(actual) == len(expected), f"{label}: expected {len(expected)} rows, got {len(actual)}")


def expect_query(bog, rows, start, end, *, contains="", limit=500, offset=0, label):
    # sorted is stable, so equal instants retain acknowledged ingest order.
    matched = [row for row in rows if start <= row.ns < end and contains in row.line]
    expect_rows(bog.query(start, end, contains, limit, offset),
                sorted(matched, key=lambda row: row.ns)[:500 if limit is None else limit], label)


def load_corpus():
    raw = CORPUS_PATH.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != CORPUS_SHA256:
        raise InfrastructureError(f"replay corpus digest mismatch: {digest}")
    records = raw.splitlines(keepends=True)
    rows = decode_rows(raw)
    ids = [row.line.split(" ", 1)[0] for row in rows]
    counts = Counter(record_id.split("-", 1)[0].removeprefix("id=") for record_id in ids)
    if len(records) != 2558 or len(ids) != 2558 or len(set(ids)) != 2558 or counts != CORPUS_SOURCES:
        raise InfrastructureError(f"replay corpus record count mismatch: {len(ids)} rows, {dict(counts)}")
    print(f"corpus records={len(rows)} sha256={digest} sources={dict(sorted(counts.items()))}")
    return records, rows


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
    try:
        records, rows = load_corpus()
    except Rejected as exc:
        raise InfrastructureError(f"invalid archived corpus: {exc}") from exc
    start, end = min(row.ns for row in rows), max(row.ns for row in rows) + 1
    for replay in (False, True):
        with run_bog(binary, directory) as bog:
            if not replay:
                for index in range(0, len(records), 100):
                    batch = records[index:index + 100]
                    bog.ingest_body(b"".join(batch), len(batch))
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
    rng = random.Random(0xB061)
    access = [
        '192.0.2.{} - - [14/Mar/2025:12:00:00 +0000] "GET /v1/items?q=a+b&v=1 HTTP/1.1" 200 83',
        '198.51.100.{} - - [14/Mar/2025:12:00:00 +0000] "POST /login HTTP/1.1" 401 21',
    ]
    templates = access + [
        "level=ERROR service=orders trace={} café",
        "level=error service=orders trace={} café",
        'trace={} message="panic"\n\tat app.run()\r\nraw=C:\\logs [a.*] ☃\u2028tail',
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
        Row(7, "tie/z first"),  # Identical logical row with a different wire timestamp.
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


def rejection_suite(binary, directory):
    good = [Row(1, "acknowledged before bad ingest")]
    prefix = encode_rows([Row(2, "must never commit")])
    valid_ts = stamp(3).encode()
    limit_rows = [Row(100 + i, f"body size limit row={i:03} " + "x" * 32_000) for i in range(128)]
    padding, extra = divmod(MAX_FRAME - len(encode_rows(limit_rows)), len(limit_rows))
    limit_rows = [dataclasses.replace(row, line=row.line + "x" * (padding + (i < extra)))
                  for i, row in enumerate(limit_rows)]
    at_limit = encode_rows(limit_rows)
    with run_bog(binary, directory) as bog:
        bog.ingest(good)
        for label, status, body in [
            ("invalid JSON after valid record", 400, prefix + b'{"ts":'),
            ("trailing JSON value", 400, prefix + encode_rows([Row(3, "trailing")]).rstrip() + b" null\n"),
            ("invalid timestamp", 400, prefix + b'{"ts":"yesterday","line":"bad"}\n'),
            ("missing timestamp zone", 400, prefix + b'{"ts":"2025-03-14T12:00:00","line":"x"}\n'),
            ("wrong line type", 400, prefix + b'{"ts":"' + valid_ts + b'","line":42}\n'),
            ("null line", 400, prefix + b'{"ts":"' + valid_ts + b'","line":null}\n'),
            ("missing line", 400, prefix + b'{"ts":"' + valid_ts + b'"}\n'),
            ("extra field", 400, prefix + b'{"ts":"' + valid_ts + b'","line":"x","extra":1}\n'),
            ("duplicate field", 400, prefix + b'{"ts":"' + valid_ts + b'","line":"x","line":"y"}\n'),
            ("invalid UTF-8", 400, prefix + b'{"ts":"' + valid_ts + b'","line":"\xff"}\n'),
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
        valid = [Row(3, "valid ingest after rejection"), Row(4, "")]
        wire = encode_rows(valid[:1]).replace(b"\n", b"\r\n") + b"\n" + encode_rows(valid[1:]).rstrip(b"\n")
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
            expect_query(bog, all_rows, 0, end + 2, label="snapshot during an unfinished POST")
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


def durability_suite(binary, directory):
    # A response is evidence only if a client actually observed it before losing the connection.
    recorded = {}
    previous = []
    writers = 4
    upper = 3_000

    def reconcile(bog, wave):
        actual = bog.query(0, upper, limit=1000)
        counts = Counter(actual)
        required = []
        resolved = {}
        for tag, (outcome, batch) in recorded.items():
            copies = [counts[row] for row in batch]
            if outcome == "unknown":
                check(all(count == 0 for count in copies) or all(count == 1 for count in copies),
                      f"SIGKILL wave {wave}: {tag} was partial or repeated after an unknown outcome")
                resolved[tag] = ("recovered" if copies[0] else "absent", batch)
            else:
                expected = int(outcome in {"acknowledged", "recovered"})
                check(all(count == expected for count in copies),
                      f"SIGKILL wave {wave}: {tag} {outcome} batch expected {expected} copies, got {copies}")
            if copies[0] == 1:
                required.extend(batch)
        expect_rows(actual, sorted(required, key=lambda row: row.ns), f"SIGKILL wave {wave} reconciliation")
        check(Counter(previous) <= counts, f"SIGKILL wave {wave} lost previously recovered rows")
        if resolved:
            outcomes = Counter(outcome for outcome, _ in resolved.values())
            print(f"SIGKILL replay={wave} unknown_resolved={dict(sorted(outcomes.items()))}")
            recorded.update(resolved)
        return actual

    for wave, delay in enumerate((0, 0.001, 0.010)):
        def tag_batch(kind, number, size, padding=0):
            tag = f"crash/wave-{wave}/{kind}-{number}"
            rows = [Row(wave * 1000 + number * 32 + i, f"{tag} row={i:02d} " + "x" * padding)
                    for i in range(size)]
            return tag, rows

        with run_bog(binary, directory) as bog:
            previous = reconcile(bog, wave)
            tag, rows = tag_batch("ack", 0, 12)
            bog.ingest(rows)
            recorded[tag] = ("acknowledged", rows)
            tag, rows = tag_batch("invalid", 1, 3)
            status, _ = bog.request("POST", "/ingest", encode_rows(rows) + b'{"ts":')
            check(status == 400, f"{tag}: expected definite HTTP 400 rejection, got {status}")
            recorded[tag] = ("rejected", rows)

            incomplete_tag, incomplete_rows = tag_batch("incomplete", 2, 2)
            unknown_tag, unknown_rows = tag_batch("unread-response", 3, 16)
            incomplete = encode_rows(incomplete_rows)
            unknown = encode_rows(unknown_rows)
            started = [threading.Event() for _ in range(writers)]
            finish = threading.Event()

            def race(worker):
                tag, rows = tag_batch("concurrent", worker + 4, 16, padding=2048)
                payload = encode_rows(rows)
                try:
                    with bog.open_ingest(len(payload)) as client:
                        started[worker].set()
                        check(finish.wait(HTTP_TIMEOUT), f"{tag}: crash clients did not start together")
                        client.send(payload)
                        with client.getresponse() as response:
                            status = response.status
                except (OSError, http.client.HTTPException):
                    return tag, "unknown", rows
                check(status == 204 or 400 <= status < 600, f"{tag}: unexpected HTTP {status}")
                if status == 204:
                    outcome = "acknowledged"
                elif status < 500 or status == 503:
                    outcome = "rejected"
                else:
                    outcome = "unknown"
                return tag, outcome, rows

            with bog.open_ingest(len(incomplete)) as partial, bog.open_ingest(len(unknown)) as unread:
                partial.send(encode_rows(incomplete_rows[:1]))
                unread.send(unknown)
                recorded[incomplete_tag] = ("incomplete", incomplete_rows)
                recorded[unknown_tag] = ("unknown", unknown_rows)
                with ThreadPoolExecutor(max_workers=writers) as pool:
                    futures = [pool.submit(race, i) for i in range(writers)]
                    for event in started:
                        check(event.wait(HTTP_TIMEOUT), "crash client did not connect")
                    finish.set()
                    time.sleep(delay)
                    bog.kill()
                    for future in futures:
                        tag, outcome, rows = future.result(timeout=HTTP_TIMEOUT)
                        recorded[tag] = (outcome, rows)
            print(f"SIGKILL wave={wave + 1} delay_ms={delay * 1000:g} "
                  f"batch_outcomes={dict(sorted(Counter(outcome for outcome, _ in recorded.values()).items()))}")
    with run_bog(binary, directory) as bog:
        reconcile(bog, 3)


def frame_offsets(wal):
    check(wal.startswith(WAL_MAGIC), "WAL file did not start with BOGWAL01")
    offset = len(WAL_MAGIC)
    offsets = []
    while offset < len(wal):
        check(len(wal) - offset >= FRAME.size, "acknowledged WAL contained a short frame header")
        size, complement, _ = FRAME.unpack_from(wal, offset)
        check(1 <= size <= MAX_FRAME and size ^ complement == 0xFFFFFFFF,
              f"invalid WAL length/complement at offset {offset}")
        offsets.append(offset)
        offset += FRAME.size + size
        check(offset <= len(wal), "acknowledged WAL contained a short frame payload")
    return offsets


def crc32c(payload):
    crc = 0xFFFFFFFF
    for byte in payload:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return crc ^ 0xFFFFFFFF


def recovery_suite(binary, directory):
    directory.mkdir()
    seed = directory / "seed"
    history = [Row(3, "earlier batch row 1"), Row(1, "earlier batch row 2")]
    final = [Row(2, "final frame marker")]
    with run_bog(binary, seed) as bog:
        bog.ingest(history)
        bog.kill()
    path = seed / "bog.wal"
    check(path.is_file(), "Bog did not produce bog.wal")
    earlier = path.read_bytes()
    with run_bog(binary, seed) as bog:
        bog.ingest(final)
        bog.kill()
    wal = path.read_bytes()
    offsets = frame_offsets(wal)
    check(offsets == [len(WAL_MAGIC), len(earlier)] and wal.startswith(earlier),
          "last one-row ingest did not append a complete frame to the existing WAL")
    frame = offsets[-1]
    payload = frame + FRAME.size
    size, complement, checksum = FRAME.unpack_from(wal, frame)
    check(crc32c(wal[payload:]) == checksum, "last complete frame has an invalid CRC32C")
    check(wal[payload:] == encode_rows(final), "WAL did not preserve the original POST body")

    resumed = Row(4, "ingest after the interrupted frame is discarded")
    for label, torn in [("short-header", wal[:frame + FRAME.size - 1]), ("short-payload", wal[:-1])]:
        case = directory / label
        case.mkdir()
        (case / "bog.wal").write_bytes(torn)
        with run_bog(binary, case) as bog:
            expect_query(bog, history, 0, 5, label=f"recovery from {label}")
            check((case / "bog.wal").read_bytes() == earlier, f"{label}: torn frame was not truncated")
            bog.ingest([resumed])
            bog.kill()
        with run_bog(binary, case) as bog:
            expect_query(bog, history + [resumed], 0, 5, label=f"second restart after {label}")

    corrupted = bytearray(wal)
    corrupted[payload + size // 2] ^= 1
    bad_payload = b"!" + wal[payload + 1:]
    for label, invalid in [
        ("bad-file-header", b"!" + wal[1:]),
        ("bad-frame-header", wal[:frame] + FRAME.pack(size, complement ^ 1, checksum) + wal[payload:]),
        ("checksum-mismatch", corrupted),
        ("bad-complete-payload", wal[:frame] + FRAME.pack(size, complement, crc32c(bad_payload)) + bad_payload),
    ]:
        case = directory / label
        case.mkdir()
        (case / "bog.wal").write_bytes(invalid)
        with run_bog(binary, case, ready=False):
            pass


def free_bytes(path):
    stats = os.statvfs(path)
    return stats.f_bavail * stats.f_frsize


def bounded_tmpfs():
    # The container runtime provides a private tmpfs without extra capabilities.
    shm = Path("/dev/shm")
    mountinfo = Path("/proc/self/mountinfo")
    if not mountinfo.is_file() or not shm.is_dir():
        raise InfrastructureError("ENOSPC requires a private, size-limited Linux /dev/shm tmpfs")
    mounts = [line.split(" - ", 1) for line in mountinfo.read_text().splitlines()]
    if not any(left.split()[4] == str(shm) and right.split()[0] == "tmpfs" for left, right in mounts):
        raise InfrastructureError("ENOSPC /dev/shm is not a separate tmpfs mount")
    stats = os.statvfs(shm)
    capacity = stats.f_blocks * stats.f_frsize
    if not 8 * 1024**2 <= capacity <= 128 * 1024**2 or free_bytes(shm) < capacity * 0.9:
        raise InfrastructureError(f"ENOSPC requires a largely empty 8–128 MiB tmpfs, capacity={capacity}")
    return shm, capacity


def constrain_append(filler, capacity, payload_size):
    with filler.open("wb", buffering=0) as stream:
        chunk = bytes(1024 * 1024)
        try:
            while stream.tell() <= capacity:
                stream.write(chunk)
        except OSError as exc:
            if exc.errno != errno.ENOSPC:
                raise
            allocated = stream.tell()
            print(f"ENOSPC filesystem_control_errno={exc.errno} "
                  f"capacity_bytes={capacity} allocated_bytes={allocated}")
        else:
            raise InfrastructureError("bounded filesystem did not return kernel ENOSPC")
        # Leave space for the header and some payload pages before the append hits ENOSPC.
        stream.truncate(allocated - 64 * 1024)
    available = free_bytes(filler.parent)
    if not 0 < available < payload_size:
        raise InfrastructureError(f"cannot constrain WAL append: available_bytes={available}, "
                                  f"payload_bytes={payload_size}")
    print(f"ENOSPC append_available_bytes={available} payload_bytes={payload_size}")


def enospc_suite(binary, directory):
    shm, capacity = bounded_tmpfs()
    directory.mkdir()
    history = [Row(1, "ENOSPC acknowledged history/1"), Row(2, "ENOSPC acknowledged history/2")]
    interrupted = [Row(3 + i, f"ENOSPC failed row {i}: " + "x" * 16_384) for i in range(32)]
    payload = encode_rows(interrupted)
    resumed = [dataclasses.replace(row, line=row.line.replace("failed", "rescue", 1)) for row in interrupted]
    with tempfile.TemporaryDirectory(prefix="bog-enospc-", dir=shm) as tmp:
        store = Path(tmp) / "store"
        with run_bog(binary, store, log_directory=directory) as bog:
            bog.ingest(history)
            wal = store / "bog.wal"
            check(wal.is_file(), "ENOSPC run did not produce bog.wal")
            prior = wal.read_bytes()
            filler = Path(tmp) / "filler"
            constrain_append(filler, capacity, len(payload))
            status, response = bog.request("POST", "/ingest", payload)
            check(status == 503, f"ENOSPC append expected HTTP 503, got {status}: {response[:200]!r}")
            expect_rows(bog.query(0, 41), history, "ENOSPC failed batch was not published")
            check(wal.read_bytes() == prior, "ENOSPC failed batch was not rolled back in the WAL")
            bog.kill()
        filler.unlink()
        with run_bog(binary, store, log_directory=directory) as bog:
            expect_rows(bog.query(0, 41), history, "ENOSPC acknowledged history after restart")
            bog.ingest(resumed)
            bog.kill()
        with run_bog(binary, store, log_directory=directory) as bog:
            expect_rows(bog.query(0, 41), history + resumed, "ENOSPC new durable write after second restart")


def percentiles(seconds):
    ordered = sorted(seconds)
    return tuple(round(1000 * ordered[math.ceil(p * len(ordered)) - 1], 3) for p in (0.50, 0.95))


def performance_suite(binary, directory):
    writers = 4
    batch_size = 500
    count = 20_000
    spacing = 5_000_000  # 200 log records per second of event time.
    batches = make_batches("perf", count // batch_size, batch_size, spacing)
    go = threading.Barrier(writers + 1)

    def query_workload(bog):
        durations = []
        for i, batch in enumerate(batches):
            for part in (batch[:batch_size // 2], batch[batch_size // 2:]):
                lower = part[0].ns if part[0].ns else -SECOND
                upper = part[-1].ns + spacing
                if upper == count * spacing:
                    upper += SECOND
                started = time.monotonic()
                rows = bog.query(lower, upper, limit=batch_size)
                durations.append(time.monotonic() - started)
                expect_rows(rows, part, f"performance batch {i}, starting at {part[0].ns}")
        return durations

    with run_bog(binary, directory) as bog, ThreadPoolExecutor(max_workers=writers) as pool:
        def write(index):
            go.wait(timeout=HTTP_TIMEOUT)
            durations = []
            for batch in batches[index::writers]:
                started = time.monotonic()
                bog.ingest(batch)
                durations.append(time.monotonic() - started)
            return durations

        futures = [pool.submit(write, i) for i in range(writers)]
        started = time.monotonic()
        go.wait(timeout=HTTP_TIMEOUT)
        post_times = [duration for future in futures for duration in future.result()]
        records_per_second = count / (time.monotonic() - started)
        query_times = query_workload(bog)
        wal = directory / "bog.wal"
        check(wal.is_file(), "performance run did not produce bog.wal")
        wal_size = wal.stat().st_size
        check(wal_size > len(WAL_MAGIC), "performance WAL is empty")
        bog.kill()

    with run_bog(binary, directory) as bog:
        restart_ms = round(bog.startup_seconds * 1000, 3)
        query_workload(bog)
    post_p50, post_p95 = percentiles(post_times)
    query_p50, query_p95 = percentiles(query_times)
    print(f"performance rows={count} batch_rows={batch_size} writers={writers} "
          f"records/s={records_per_second:.1f} post_p50_ms={post_p50} post_p95_ms={post_p95} "
          f"query_p50_ms={query_p50} query_p95_ms={query_p95} wal_bytes={wal_size} "
          f"restart_to_ready_ms={restart_ms}")


SUITES = (
    ("query-oracle", corpus_suite),
    ("archived-corpus", replay_corpus_suite),
    ("request-rejection", rejection_suite),
    ("concurrent-snapshots", concurrency_suite),
    ("directory-lock", lock_suite),
    ("kill-durability", durability_suite),
    ("wal-recovery", recovery_suite),
    ("enospc-recovery", enospc_suite),
    ("performance-smoke", performance_suite),
)
REQUIRED_SUITES = (
    "query-oracle",
    "archived-corpus",
    "request-rejection",
    "concurrent-snapshots",
    "directory-lock",
    "kill-durability",
    "wal-recovery",
    "enospc-recovery",
    "performance-smoke",
)


def build(source, work):
    binary = work / "bog"
    check((source / "cmd" / "bog").is_dir(), "missing ./cmd/bog")
    log = work / "build.log"
    try:
        with log.open("wb") as output:
            completed = subprocess.run(
                ["go", "build", "-trimpath", "-o", str(binary), "./cmd/bog"], cwd=source,
                stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT, timeout=120,
            )
    except subprocess.TimeoutExpired as exc:
        raise Rejected("go build ./cmd/bog timed out after 120s") from exc
    if completed.returncode:
        with log.open("rb") as output:
            output.seek(max(0, log.stat().st_size - 1200))
            tail = " ".join(output.read().decode(errors="replace").split())
        raise Rejected(f"go build ./cmd/bog failed (status {completed.returncode}): {tail}")
    check(not binary.is_symlink() and binary.is_file() and os.access(binary, os.X_OK),
          "go build ./cmd/bog did not produce an executable Bog binary")
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


def main(source, work, sha):
    (work / "stage").write_text(f"build, 0/{len(REQUIRED_SUITES)} suites completed")
    try:
        binary = build(source, work)
    except Rejected as exc:
        for name in REQUIRED_SUITES:
            print(f"SKIP {name}: build prerequisite failed")
        return reject(work, sha, "build", 0, diagnostic(exc))

    digest = file_sha256(binary)
    print(f"binary_sha256={digest} candidate_sha={sha}")
    if not SUITES:
        return reject(work, sha, "harness", 0, "zero verification suites registered")
    if tuple(name for name, _ in SUITES) != REQUIRED_SUITES:
        print("ERROR harness: suite registry does not match the required suite list", file=sys.stderr)
        return 2

    passed = []
    rejected = []
    errors = []
    for stage, run in SUITES:
        (work / "stage").write_text(f"{stage}, {len(passed)}/{len(REQUIRED_SUITES)} suites passed")
        print(f"RUN {stage}")
        started = time.monotonic()
        try:
            run(binary, work / stage)
        except (Rejected, subprocess.TimeoutExpired, threading.BrokenBarrierError,
                ConnectionError, TimeoutError, http.client.HTTPException) as exc:
            reason = diagnostic(exc)
            print(f"FAIL {stage}: {reason}")
            rejected.append((stage, reason))
        except (InfrastructureError, OSError) as exc:
            print(f"ERROR {stage}: {diagnostic(exc)}")
            errors.append(stage)
        else:
            passed.append(stage)
            print(f"PASS {stage} seconds={time.monotonic() - started:.3f}")

    print(f"candidate_sha={sha} binary_sha256={digest} "
          f"suites_passed={len(passed)}/{len(REQUIRED_SUITES)} "
          f"suites_rejected={len(rejected)} suites_infra_error={len(errors)}")
    if errors:
        print(f"required suites with infrastructure errors: {', '.join(errors)}", file=sys.stderr)
        return 2
    if rejected:
        stage, reason = rejected[0]
        failed = ", ".join(name for name, _ in rejected)
        return reject(work, sha, stage, len(passed), f"{reason} (failed: {failed})")
    if tuple(passed) != REQUIRED_SUITES:
        print("ERROR harness: required suite execution did not complete", file=sys.stderr)
        return 2
    (work / "passed").write_text(f"{sha} {digest} {len(passed)}\n")
    print(f"verified_sha={sha} binary_sha256={digest} suites={len(passed)}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]))
    except Exception as exc:
        print(f"ERROR harness: {diagnostic(exc)}", file=sys.stderr)
        raise SystemExit(2) from exc
