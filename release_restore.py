"""Bounded native parity fixture for two successive writable restores."""
import hashlib
import json
import os
import struct
import subprocess
import time
from urllib.parse import urlencode

from verify import (CAPACITY_PATH, CONTROL_SCOPE_REQUESTS, RETAINED_TAIL_FLAG, SECOND, WAL_MAGIC, Row,
                    advertised_flags, check, commit_marker, decode_rows, encode_rows, expect_bad_query,
                    expect_page, expect_query, expect_query_error, expect_rows, expect_walk, oracle,
                    query_args, run_bog, unique_fields, wal_frame)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def fixture_tool(helper, *args):
    result = subprocess.run([str(helper), *map(str, args)], capture_output=True, timeout=10)
    check(result.returncode == 0, f"backup fixture {args[0]} failed: {result.stderr[:500]!r}")


def retargeted_append(bog, link, active, rows):
    def ready():
        status, raw = bog.request("GET", "/ready")
        body = json.loads(raw, object_pairs_hook=unique_fields)
        check(status == 200 and isinstance(body, dict) and body.get("ready") is True and
              body.get("reason") == "ready" and not body.get("category"),
              f"expected ready on pinned directory, got HTTP {status}: {body!r}")

    # Allow the asynchronous sampler to publish its first observation.
    deadline = time.monotonic() + 5
    while True:
        status, raw = bog.request("GET", "/ready")
        if status == 200:
            break
        check(status == 503 and time.monotonic() < deadline and
              json.loads(raw).get("reason") == "sampling_pending",
              f"initial /ready returned HTTP {status}: {raw!r}")
        time.sleep(0.02)
    ready()
    check(os.statvfs(link).f_bavail > 0 and os.statvfs("/proc").f_bavail == 0,
          "readiness fixture requires headroom at the active directory and none on procfs")
    def retarget(target):
        replacement = link.with_suffix(".replacement")
        replacement.symlink_to(target, target_is_directory=True)
        replacement.replace(link)
        time.sleep(6.1)  # Outlive the five-second evidence window and a refresh interval.
        ready()
        return 200

    away = retarget("/proc")
    bog.ingest(rows)
    return {"away_ready_status": away, "append_status": 204, "back_ready_status": retarget(active)}


def compaction(bog, cutoff, committed):
    state = compaction_status(bog, "POST", "start", cutoff)
    deadline = time.monotonic() + 5
    while state.get("state") == "running" and time.monotonic() < deadline:
        time.sleep(0.02)
        state = compaction_status(bog, "GET", "status", cutoff)
    check(state.get("state") == "complete" and state.get("covered_rows") == cutoff and
          state.get("committed_rows") == committed, f"compaction missed exact cutoff: {state!r}")
    return state


def compaction_status(bog, method, action, cutoff):
    status, raw = bog.request(method, f"{CAPACITY_PATH}?action={action}&cutoff={cutoff}")
    check(200 <= status < 300, f"compaction {action} returned HTTP {status}: {raw[:300]!r}")
    return json.loads(raw, object_pairs_hook=unique_fields)


def predecessor_observation(bog, publication):
    state = compaction_status(bog, "GET", "status", publication["covered_rows"])
    check(all(state.get(key) == publication[key] for key in ("state", "generation", "covered_rows", "committed_rows")),
          f"pin observation changed compaction publication: {state!r}")
    metrics = state.get("metrics") or {}
    pins = metrics.get("retired_generation_pins")
    check(type(pins) is int and pins >= 0, f"missing predecessor pin observation: {pins!r}")
    return pins, metrics


def reclaim_bytes(metrics, predecessor, successor):
    fields = ("reclaimed_predecessor_generation", "reclaimed_replacement_generation", "reclaimed_bytes")
    values = tuple(metrics.get(key) for key in fields)
    if all(value is None for value in values):
        return None
    check(all(type(value) is int and value >= 0 for value in values),
          f"invalid reclamation observation: {values!r}")
    return values[2] if values[:2] == (predecessor, successor) else None


def append_and_kill(bog, rows):
    payload = encode_rows(rows)
    with bog.open_ingest(len(payload)) as connection:
        connection.send(payload)
        with connection.getresponse() as response:
            check(response.status == 204, f"post-restore ingest returned HTTP {response.status}")
            # Kill before reading or closing the acknowledgement body.
            bog.kill()
    return -bog.process.returncode


def ordered_walk(bog, args, expected, label):
    ordered = oracle(expected, 0, SECOND)
    body, cursor = bog.query_ndjson(args, exact_framing=True)
    check(cursor is None, f"{label}: ordinary query returned a cursor")
    expect_rows(decode_rows(body), ordered, f"{label}: ordinary query")
    expect_walk(bog, args, ordered, (1, 2), label, exact_framing=True)
    return len(ordered)


def ordinary_wal_reopen(binary, directory, args, flags, rows, extra):
    directory.mkdir()
    prefix = WAL_MAGIC + wal_frame(encode_rows(rows))
    (directory / "bog.wal").write_bytes(prefix)
    (directory / "bog.commit").write_bytes(commit_marker(len(prefix)))
    with run_bog(binary, directory, flags=flags) as bog:
        reopened = ordered_walk(bog, args, rows, "ordinary WAL reopen")
        cursor = expect_page(bog, args, oracle(rows, 0, SECOND), 0, 1, None,
                             "ordinary WAL capture", exact_framing=True)
        hidden = {}
        for action, method, path in CONTROL_SCOPE_REQUESTS:
            if action == "start":
                path = f"{CAPACITY_PATH}?action=start&cutoff={len(rows)}"
            elif action == "retire":
                path += "&" + urlencode({"cursor": cursor})
            status, _ = bog.request(method, path)
            check(status == 404, f"ordinary WAL without opt-in: {action} returned HTTP {status}")
            hidden[action] = status
        exit_signal = append_and_kill(bog, extra)
    with run_bog(binary, directory, flags=flags) as bog:
        expect_bad_query(bog, {**args, "cursor": cursor}, "prior-process ordinary WAL cursor")
        replayed = ordered_walk(bog, args, rows + extra, "ordinary WAL replay after immediate SIGKILL")
        bog.stop()
    return dict(reopened_rows=reopened, append_status=204, exit_signal=exit_signal,
                replay_rows=replayed, default_control=hidden)


def bundle_point(bundle, version, covered, next_ordinal, committed, suffix, predecessor=None):
    raw = (bundle / "bog.backup").read_bytes()
    rsuffix = (bundle / "bog.wal.tail").read_bytes()
    generation = raw[8:40]
    bounds = struct.pack("<QQQ", covered, next_ordinal, covered + len(suffix))
    if version == 2:
        bounds += struct.pack("<Q", committed)
    metadata = f"BOGBAK0{version}".encode() + generation + bounds + hashlib.sha256(suffix).digest()
    check(raw == metadata + hashlib.sha256(metadata).digest() and rsuffix == suffix,
          f"{bundle.name}: wrong metadata bounds or exact suffix")
    manifest = json.loads((bundle / "bog.checkpoint").read_bytes())["payload"]
    check(manifest["version"] == version and manifest["covered_offset"] == covered and
          manifest["next_ordinal"] == next_ordinal, f"{bundle.name}: wrong manifest boundary")
    if predecessor is not None:
        check(manifest.get("advance") == {
            "generation": predecessor["generation"], "covered_offset": predecessor["covered_offset"],
            "next_ordinal": predecessor["next_ordinal"], "consumed_sha256": predecessor["suffix_sha256"],
        }, f"{bundle.name}: successor does not bind the exact consumed frames and predecessor")
    return dict(version=version, generation=generation.hex(), covered_offset=covered,
                next_ordinal=next_ordinal, committed_end=covered + len(suffix),
                committed_ordinal=committed, suffix_bytes=len(suffix), suffix_sha256=digest(rsuffix))


def restore_cycles(binary, directory, helper):
    check(helper.is_file(), "backup fixture helper is missing")
    available = advertised_flags(binary, directory)
    directory.mkdir()
    seed, bundle, active = (directory / name for name in ("seed", "v1", "cycle-1"))
    rows = [Row(2, "checkpoint"), Row(1, "duplicate"), Row(1, "duplicate")]
    suffix_rows = [rows[1], Row(0, "first backfill"), Row(1, "first carried tie")]
    seed.mkdir()
    prefix = WAL_MAGIC + wal_frame(encode_rows(rows))
    (seed / "bog.wal").write_bytes(prefix)
    (seed / "bog.commit").write_bytes(commit_marker(len(prefix)))
    fixture_tool(helper, "checkpoint", seed)
    covered = len(prefix)
    rows += suffix_rows
    suffix = wal_frame(encode_rows(suffix_rows))
    (seed / "bog.wal").write_bytes(prefix + suffix)
    (seed / "bog.commit").write_bytes(commit_marker(covered + len(suffix)))
    fixture_tool(helper, "export", seed, "bog.checkpoint", "bog.wal", bundle, len(rows))
    point = bundle_point(bundle, 1, covered, 3, len(rows), suffix)
    initial = point
    fixture_tool(helper, "restore", bundle, active)
    bundle.rename(bundle.with_suffix(".parked"))
    seed.rename(seed.with_suffix(".parked"))
    flags = (f"{RETAINED_TAIL_FLAG}=65536",) if RETAINED_TAIL_FLAG in available else ()
    args = query_args(0, SECOND)
    ordinary = ordinary_wal_reopen(binary, directory / "ordinary", args, flags, rows[:3], suffix_rows)

    cycles = []
    for number in (1, 2):
        check(not (active / "bog.wal").exists(), "restore unexpectedly contains a full WAL")
        backup_meta = (active / "bog.backup").read_bytes()
        extra = [rows[1], Row(0, f"cycle {number} backfill"), Row(1, f"cycle {number} tie")]
        next_suffix = wal_frame(encode_rows(extra))
        augmented = rows + extra
        held = oracle(rows, 0, SECOND)
        launch = active
        if number == 1:
            launch = directory / "data-link"
            launch.symlink_to(active, target_is_directory=True)
        with run_bog(binary, launch, capacity=True, flags=flags) as bog:
            predecessor = compaction_status(bog, "GET", "status", point["next_ordinal"])["generation"]
            cursor = expect_page(bog, args, held, 0, 1, None, "initial retained page", exact_framing=True)
            bad_batch = encode_rows([Row(1, f"cycle {number} rejected row")]) + b'{"ts":'
            rejected, body = bog.request("POST", "/ingest", bad_batch)
            check(rejected == 400, f"malformed restore append returned HTTP {rejected}: {body[:200]!r}")
            expect_query(bog, rows, 0, SECOND, label="rejected restore append rolled back")
            if number == 1:
                retarget = retargeted_append(bog, launch, active, extra)
            else:
                bog.ingest(extra)
            publication = compaction(bog, len(rows), len(augmented))
            continuation = {**args, "cursor": cursor, "limit": 2}
            page, next_cursor = bog.query_ndjson(continuation, exact_framing=True)
            retried, terminal_cursor = bog.query_ndjson(continuation, exact_framing=True)
            expect_rows(decode_rows(page), held[1:3], "held continuation after advance")
            check(page == retried and next_cursor and terminal_cursor,
                  "retry changed the held continuation bytes or dropped its cursor")
            terminal_args = {**args, "cursor": terminal_cursor, "limit": len(held) - 3}
            terminal, next_cursor = bog.query_ndjson(terminal_args, exact_framing=True)
            expect_rows(decode_rows(terminal), held[3:], "held terminal page after advance")
            check(next_cursor is None and bog.query_ndjson(terminal_args, exact_framing=True) == (terminal, None),
                  "retry changed the held terminal page or cursor header")
            pins_while_held, metrics = predecessor_observation(bog, publication)
            check(pins_while_held > 0, "held cursor did not pin the predecessor")
            successor = publication["generation"]
            check(type(predecessor) is int and type(successor) is int and 0 <= predecessor < successor,
                  f"compaction did not replace the predecessor: {predecessor!r} -> {successor!r}")
            check(reclaim_bytes(metrics, predecessor, successor) is None,
                  "replacement was reclaimed before final predecessor pin release")
            pinned = metrics.get("predecessor_pin_generation")
            check(type(pinned) is int and pinned == predecessor,
                  "held pin observation did not identify the predecessor")
            retire = urlencode({"action": "retire", "cursor": terminal_cursor})
            status, body = bog.request("POST", f"{CAPACITY_PATH}?{retire}")
            check(status == 204 and not body, f"predecessor capture retirement returned HTTP {status}: {body!r}")
            retired = expect_query_error(bog, terminal_args, 410, "retired predecessor cursor")["status"]
            deadline = time.monotonic() + 5
            while True:
                pins_after_release, metrics = predecessor_observation(bog, publication)
                reclaimed = reclaim_bytes(metrics, predecessor, successor)
                check(pins_after_release == 0 or reclaimed is None,
                      "replacement was reclaimed while predecessor pins remained")
                if pins_after_release == 0 and reclaimed is not None:
                    break
                check(time.monotonic() < deadline,
                      f"predecessor pin drain or reclamation did not finish: "
                      f"remaining pins={pins_after_release}, reclaimed bytes={reclaimed}")
                time.sleep(0.02)
            fresh = ordered_walk(bog, args, augmented, "fresh retained walk after advance")
            stale_cursor = expect_page(bog, args, oracle(augmented, 0, SECOND), 0, 1, None,
                                       "capture before replacement restart", exact_framing=True)
            bog.kill()
            replacement_signal = -bog.process.returncode

        manifests = []
        for path in active.glob("bog-checkpoint-*"):
            payload = json.loads(path.read_bytes())["payload"]
            if payload.get("next_ordinal") == len(rows):
                manifests.append(path.name)
        check(len(manifests) == 1, f"cycle {number}: expected one published successor manifest")
        tails = [path.name for path in active.iterdir() if path.is_file() and
                 path.stat().st_size == len(next_suffix) and path.read_bytes() == next_suffix]
        check(len(tails) == 1, f"cycle {number}: expected exactly one rebased tail with the acknowledged frame")
        check((active / "bog.backup").read_bytes() == backup_meta,
              f"cycle {number}: startup or replacement changed immutable backup metadata")

        bundle = directory / f"export-{number}"
        restored = directory / f"cycle-{number + 1}"
        fixture_tool(helper, "export", active, manifests[0], tails[0], bundle, len(augmented))
        exported = bundle_point(bundle, 2, point["committed_end"], len(rows), len(augmented),
                                next_suffix, point)
        fixture_tool(helper, "restore", bundle, restored)
        parked = bundle.with_suffix(".parked")
        bundle.rename(parked)
        restart_append = [Row(1, f"cycle {number} append after replacement restart")]
        with run_bog(binary, active, flags=flags) as bog:
            hidden, _ = bog.request("GET", f"{CAPACITY_PATH}?action=status")
            check(hidden == 404, f"default compaction status returned HTTP {hidden}")
            expect_bad_query(bog, {**args, "cursor": stale_cursor}, "prior-process retained cursor")
            restarted = ordered_walk(bog, args, augmented, "same-directory restart after advance")
            restart_append_signal = append_and_kill(bog, restart_append)
        with run_bog(binary, active, flags=flags) as bog:
            restart_append_rows = ordered_walk(bog, args, augmented + restart_append,
                                               "replay after replacement restart append")
            bog.stop()
        with run_bog(binary, restored, flags=flags) as bog:
            restored_rows = ordered_walk(bog, args, augmented, "independent writable restore")
            if number == 2:
                last = [Row(1, "tie appended after second restore")]
                bog_exit_signal = append_and_kill(bog, last)
            else:
                bog.stop()
        check(exported == bundle_point(parked, 2, point["committed_end"], len(rows), len(augmented),
                                       next_suffix, point), f"cycle {number}: source backup changed")
        cycles.append(dict(input=point, exported=exported, append_status=204, rejected_append_status=rejected,
                           terminal_retry_byte_identical=True, held_rows=len(held),
                           fresh_rows=fresh, restart_rows=restarted, restored_rows=restored_rows,
                           replacement_exit_signal=replacement_signal,
                           restart_append_exit_signal=restart_append_signal,
                           restart_append_replay_rows=restart_append_rows,
                           reclaimed_bytes=reclaimed,
                           retired_cursor_status=retired,
                           default_control_status=hidden, pins_while_held=pins_while_held,
                           pins_after_release=pins_after_release))
        active, point, rows = restored, exported, augmented

    recovered = rows + last
    drained = [Row(0, "backfill drained on retained shutdown"), Row(1, "tie drained on retained shutdown")]
    payload = encode_rows(drained)
    split = len(encode_rows(drained[:1]))
    with run_bog(binary, active, flags=flags) as bog:
        final_rows = ordered_walk(bog, args, recovered, "restart after acknowledged second-restore append")
        cursor = expect_page(bog, args, oracle(recovered, 0, SECOND), 0, 1, None,
                             "held cursor before retained shutdown", exact_framing=True)
        # Leave the capture live and keep the POST admitted while SIGTERM closes the listener.
        with bog.open_ingest(len(payload), expect_continue=True) as client:
            client.send(payload[:split])
            bog.graceful_stop(client, payload[split:])
        shutdown_exit = bog.process.returncode
    with run_bog(binary, active, flags=flags) as bog:
        expect_bad_query(bog, {**args, "cursor": cursor}, "cursor from clean retained shutdown")
        shutdown_rows = ordered_walk(bog, args, recovered + drained, "replay after retained shutdown")
        bog.stop()
    return dict(initial=initial, cycles=cycles, descriptor_ready_status=retarget["away_ready_status"],
                ordinary_wal_reopen=ordinary, restored_retarget=retarget,
                final_append_status=204, final_exit_signal=bog_exit_signal, final_restart_rows=final_rows,
                retained_shutdown=dict(held_cursor=True, append_status=204, exit_code=shutdown_exit,
                                       prior_cursor_rejected=True, replay_rows=shutdown_rows))
