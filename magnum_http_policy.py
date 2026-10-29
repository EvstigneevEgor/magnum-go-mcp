"""Conservative request scheduling. Contains no credentials or request data."""

from __future__ import annotations

from contextlib import contextmanager
import json
import math
import os
from pathlib import Path
import stat
import sys
import threading
import time

from magnum_config import ConfigurationError, DEFAULT_REQUEST_INTERVAL_SECONDS, load_settings


MAX_AUTOMATIC_WAIT = 12.0
DEFAULT_RATE_LIMIT_COOLDOWN = 300.0


class RequestDeferred(RuntimeError):
    def __init__(self, retry_after_seconds):
        self.retry_after_seconds = max(1, math.ceil(retry_after_seconds))
        super().__init__("API request deferred; retry after {} seconds.".format(self.retry_after_seconds))


class RequestPolicyUnavailable(RuntimeError):
    def __init__(self):
        super().__init__("The shared API request scheduler is unavailable.")


class RequestPolicy:
    """One request at a time, with a configurable interval between starts.

    Linux uses an owned private runtime file and flock, shared by CLI and MCP.
    Other platforms serialize the current process. Tests may inject a clock.
    A long Retry-After is reported to the caller; requests are never retried.
    """

    def __init__(self, *, interval=DEFAULT_REQUEST_INTERVAL_SECONDS, clock=None, sleeper=None, runtime_dir=None):
        try:
            valid = type(interval) in (int, float) and math.isfinite(interval) and interval > 0
        except OverflowError:
            valid = False
        if not valid:
            raise ValueError("Invalid request interval.")
        self.interval = float(interval)
        self.clock = clock or time.monotonic
        self.sleep = sleeper or time.sleep
        self.runtime_dir = Path(runtime_dir) if runtime_dir is not None else None
        self._thread_lock = threading.RLock()
        self._memory = {"next_start": 0.0, "cooldown_until": 0.0}

    def _open_shared(self):
        import fcntl
        root = self.runtime_dir or Path("/run/user") / str(os.getuid())
        try:
            info = root.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise RequestPolicyUnavailable()
            fd = os.open(root / "magnumgo-http.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            try:
                info = os.fstat(fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                        or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
                    raise RequestPolicyUnavailable()
                started = time.monotonic()
                while True:
                    try:
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        return fd
                    except BlockingIOError:
                        if time.monotonic() - started >= 35:
                            raise RequestDeferred(10)
                        time.sleep(0.05)
            except BaseException:
                os.close(fd)
                raise
        except (RequestDeferred, RequestPolicyUnavailable):
            raise
        except (OSError, ValueError):
            raise RequestPolicyUnavailable() from None

    def _read(self, fd):
        if fd is None:
            return dict(self._memory)
        try:
            os.lseek(fd, 0, os.SEEK_SET)
            raw = os.read(fd, 1025)
            if not raw:
                return {"next_start": 0.0, "cooldown_until": 0.0}
            value = json.loads(raw)
            if len(raw) > 1024 or not isinstance(value, dict) or set(value) != {"next_start", "cooldown_until"}:
                raise ValueError
            for item in value.values():
                if type(item) not in (int, float) or not math.isfinite(item) or item < 0:
                    raise ValueError
            return value
        except (OSError, ValueError, TypeError):
            raise RequestPolicyUnavailable() from None

    def _write(self, fd, value):
        if fd is None:
            self._memory = dict(value)
            return
        raw = json.dumps(value, separators=(",", ":")).encode("ascii")
        try:
            os.lseek(fd, 0, os.SEEK_SET)
            os.ftruncate(fd, 0)
            if os.write(fd, raw) != len(raw):
                raise OSError
            os.fsync(fd)
        except OSError:
            raise RequestPolicyUnavailable() from None

    @contextmanager
    def request_slot(self):
        with self._thread_lock:
            fd = self._open_shared() if sys.platform.startswith("linux") else None
            try:
                state = self._read(fd)
                now = self.clock()
                delay = max(state["next_start"], state["cooldown_until"]) - now
                if delay > MAX_AUTOMATIC_WAIT:
                    raise RequestDeferred(delay)
                if delay > 0:
                    self.sleep(delay)
                state["next_start"] = self.clock() + self.interval
                self._write(fd, state)
                try:
                    yield
                except Exception as error:
                    if getattr(error, "http_status", None) == 429:
                        requested = getattr(error, "retry_after_seconds", None)
                        duration = (float(requested) if type(requested) in (int, float)
                                    and math.isfinite(requested) and requested > 0
                                    else DEFAULT_RATE_LIMIT_COOLDOWN)
                        state["cooldown_until"] = self.clock() + duration
                        self._write(fd, state)
                    raise
            finally:
                if fd is not None:
                    os.close(fd)


_default_policy = None
_default_policy_lock = threading.Lock()


def request_slot():
    # Keep local status/imports usable even if HTTP configuration needs fixing.
    # Each long-lived MCP process loads settings once, before its first request.
    global _default_policy
    with _default_policy_lock:
        if _default_policy is None:
            try:
                settings = load_settings()
            except ConfigurationError:
                raise RequestPolicyUnavailable() from None
            _default_policy = RequestPolicy(interval=settings.request_interval_seconds)
        scheduler = _default_policy
    return scheduler.request_slot()
