"""Timing and lifecycle helpers for the bog 0.2 release journeys."""

import signal
import sys
import time
from contextlib import contextmanager

from lib import expect


def require_linux():
    if sys.platform != "linux":
        raise RuntimeError("this journey requires Linux")


def budget(deadline, maximum, activity):
    remaining = deadline - time.monotonic()
    expect(remaining > 0, activity, "deadline expired")
    return min(remaining, maximum)


def stop(bog):
    clean = False
    try:
        code = bog.stop(timeout=4)
        expect(code == 0, "exit 0 after SIGTERM within 4s", f"process wait result {code!r}")
        clean = True
    finally:
        if not clean:
            bog.kill(timeout=2)


@contextmanager
def serving(bog, deadline, startup_seconds, *, preexec_fn=None, crash=False):
    startup_deadline = min(deadline, time.monotonic() + startup_seconds)
    try:
        bog.start(timeout=budget(startup_deadline, startup_seconds, "Bog to start before the deadline"),
                  request_timeout=2, preexec_fn=preexec_fn)
        yield startup_deadline
        if crash:
            code = bog.kill(timeout=3)
            expect(code == -signal.SIGKILL, "termination by SIGKILL within 3s", f"process wait result {code!r}")
    except BaseException:
        if bog.proc is not None and bog.proc.poll() is None:
            stop(bog)
        raise
    else:
        if not crash:
            stop(bog)
