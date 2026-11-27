"""Bounded native parity fixture for two successive writable restores."""
import hashlib
import json
import os
import struct
import subprocess
import time

from verify import (CAPACITY_PATH, RETAINED_TAIL_FLAG, SECOND, WAL_MAGIC, Row, SuiteSkipped,
                    advertised_flags, check, commit_marker, encode_rows, expect_page, expect_query,
                    expect_walk, oracle, query_args, run_bog, unique_fields, wal_frame)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def fixture_tool(helper, *args):
    result = subprocess.run([str(helper), *map(str, args)], capture_output=True, timeout=10)
    check(result.returncode == 0, f"backup fixture {args[0]} failed: {result.stderr[:500]!r}")


def ready_after_retarget(bog, link):
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
    replacement = link.with_suffix(".replacement")
    replacement.symlink_to("/proc", target_is_directory=True)
    replacement.replace(link)
    time.sleep(6.1)  # Outlive the five-second evidence window and a refresh interval.
    ready()
    return 200


def compaction(bog, cutoff, committed):
    def request(method, action):
        status, raw = bog.request(method, f"{CAPACITY_PATH}?action={action}&cutoff={cutoff}")
        check(200 <= status < 300, f"compaction {action} returned HTTP {status}: {raw[:300]!r}")
        return json.loads(raw, object_pairs_hook=unique_fields)

    state = request("POST", "start")
    deadline = time.monotonic() + 5
    while state.get("state") == "running" and time.monotonic() < deadline:
        time.sleep(0.02)
        state = request("GET", "status")
    check(state.get("state") == "complete" and state.get("covered_rows") == cutoff and
          state.get("committed_rows") == committed, f"compaction missed exact cutoff: {state!r}")


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
    if RETAINED_TAIL_FLAG not in advertised_flags(binary, directory):
        return SuiteSkipped(f"candidate has no {RETAINED_TAIL_FLAG}")
    check(helper.is_file(), "candidate advertises retained recovery but the backup fixture helper is missing")
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
    flags = (f"{RETAINED_TAIL_FLAG}=65536",)
    args = query_args(0, SECOND)

    def walk(bog, expected, label):
        expect_query(bog, expected, 0, SECOND, label=label)
        expect_walk(bog, args, oracle(expected, 0, SECOND), (1, 2), label, exact_framing=True)
        return len(expected)

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
            if number == 1:
                readiness = ready_after_retarget(bog, launch)
            cursor = expect_page(bog, args, held, 0, 1, None, "initial retained page", exact_framing=True)
            bog.ingest(extra)
            compaction(bog, len(rows), len(augmented))
            expect_walk(bog, args, held, (2, 1), "held retained walk after advance", position=1,
                        cursor=cursor, exact_framing=True)
            fresh = walk(bog, augmented, "fresh retained walk after advance")
            bog.stop()

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
        with run_bog(binary, active, flags=flags) as bog:
            hidden, _ = bog.request("GET", f"{CAPACITY_PATH}?action=status")
            check(hidden == 404, f"default compaction status returned HTTP {hidden}")
            restarted = walk(bog, augmented, "same-directory restart after advance")
            bog.stop()
        with run_bog(binary, restored, flags=flags) as bog:
            restored_rows = walk(bog, augmented, "independent writable restore")
            if number == 2:
                last = [Row(1, "tie appended after second restore")]
                bog.ingest(last)
                bog.kill()
                bog_exit = bog.process.returncode
            else:
                bog.stop()
        check(exported == bundle_point(parked, 2, point["committed_end"], len(rows), len(augmented),
                                       next_suffix, point), f"cycle {number}: source backup changed")
        cycles.append(dict(input=point, exported=exported, append_status=204, held_rows=len(held),
                           fresh_rows=fresh, restart_rows=restarted, restored_rows=restored_rows,
                           default_control_status=hidden))
        active, point, rows = restored, exported, augmented

    with run_bog(binary, active, flags=flags) as bog:
        final_rows = walk(bog, rows + last, "restart after acknowledged second-restore append")
        bog.stop()
    return dict(initial=initial, cycles=cycles, descriptor_ready_status=readiness,
                final_append_status=204, final_exit_signal=-bog_exit, final_restart_rows=final_rows)
