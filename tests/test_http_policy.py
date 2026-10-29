"""Offline request-policy tests using synthetic clocks and private temp files.

No HTTP, session, credentials or real interval sleeps are used. Linux
file-lock tests run on the Pi; memory-path and corrupt-file tests run everywhere.
"""

import json
import math
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import magnum_http_policy as policy


class FakeClock:
    def __init__(self):
        self.now = 100.0
        self.sleeps = []

    def __call__(self):
        return self.now

    def sleep(self, duration):
        if not math.isfinite(duration) or duration < 0:
            raise AssertionError("Invalid sleep duration")
        self.sleeps.append(duration)
        self.now += duration


class SyntheticHTTP429(RuntimeError):
    http_status = 429

    def __init__(self, retry_after_seconds=None):
        super().__init__("synthetic private request token must not be persisted")
        self.retry_after_seconds = retry_after_seconds


class RequestPolicyTests(unittest.TestCase):
    def make_policy(self):
        clock = FakeClock()
        return policy.RequestPolicy(clock=clock, sleeper=clock.sleep), clock

    def test_memory_branch_has_at_least_half_a_second_between_starts(self):
        scheduler, clock = self.make_policy()
        starts = []
        with patch.object(policy.sys, "platform", "win32"), patch.object(
                scheduler, "_open_shared", side_effect=AssertionError("No file access on memory path")):
            for _ in range(3):
                with scheduler.request_slot():
                    starts.append(clock())
        self.assertEqual(starts, [100.0, 100.5, 101.0])
        self.assertEqual(clock.sleeps, [0.5, 0.5])

    def test_slow_response_does_not_add_unnecessary_extra_interval(self):
        scheduler, clock = self.make_policy()
        with patch.object(policy.sys, "platform", "win32"):
            with scheduler.request_slot():
                clock.now += 25.0
            with scheduler.request_slot():
                self.assertEqual(clock(), 125.0)
        self.assertEqual(clock.sleeps, [])

    def test_429_is_not_retried_and_long_retry_after_defers_next_call(self):
        scheduler, clock = self.make_policy()
        attempts = []
        error = SyntheticHTTP429(65.5)
        with patch.object(policy.sys, "platform", "win32"):
            with self.assertRaises(SyntheticHTTP429) as raised:
                with scheduler.request_slot():
                    attempts.append(clock())
                    raise error
            self.assertIs(raised.exception, error)
            with self.assertRaises(policy.RequestDeferred) as deferred:
                with scheduler.request_slot():
                    self.fail("Deferred request must not run")
        self.assertEqual(attempts, [100.0])
        self.assertEqual(deferred.exception.retry_after_seconds, 66)
        self.assertEqual(clock.sleeps, [])

    def test_429_short_cooldown_applies_to_a_separate_explicit_call(self):
        scheduler, clock = self.make_policy()
        attempts = []
        with patch.object(policy.sys, "platform", "win32"):
            with self.assertRaises(SyntheticHTTP429):
                with scheduler.request_slot():
                    attempts.append(clock())
                    raise SyntheticHTTP429(11)
            self.assertEqual(attempts, [100.0])
            with scheduler.request_slot():
                attempts.append(clock())
        self.assertEqual(attempts, [100.0, 111.0])
        self.assertEqual(clock.sleeps, [11.0])

    def test_invalid_or_absent_retry_after_uses_conservative_cooldown(self):
        for duration in (None, False, True, "10", -1, 0, float("inf"), float("nan")):
            with self.subTest(duration=duration):
                scheduler, clock = self.make_policy()
                with patch.object(policy.sys, "platform", "win32"):
                    with self.assertRaises(SyntheticHTTP429):
                        with scheduler.request_slot():
                            raise SyntheticHTTP429(duration)
                    with self.assertRaises(policy.RequestDeferred) as raised:
                        with scheduler.request_slot():
                            self.fail("Cooldown must defer request")
                self.assertEqual(raised.exception.retry_after_seconds,
                                 int(policy.DEFAULT_RATE_LIMIT_COOLDOWN))
                self.assertEqual(clock.sleeps, [])

    def test_transport_failure_propagates_once_and_keeps_spacing(self):
        scheduler, clock = self.make_policy()
        calls = []
        failure = TimeoutError("synthetic transport failure")
        with patch.object(policy.sys, "platform", "win32"):
            with self.assertRaises(TimeoutError) as raised:
                with scheduler.request_slot():
                    calls.append(clock())
                    raise failure
            self.assertIs(raised.exception, failure)
            self.assertEqual(calls, [100.0])
            with scheduler.request_slot():
                calls.append(clock())
        self.assertEqual(calls, [100.0, 100.5])

    def test_corrupt_state_fails_closed_with_fixed_diagnostic(self):
        scheduler, _ = self.make_policy()
        samples = [
            b"not JSON", b"null", b"true", b"1", b'"a"', b"[]", b"{}",
            # Regression: an array with both key names is not a state object.
            b'["next_start","cooldown_until"]',
            b'{"next_start":0,"cooldown_until":0,"token":"synthetic"}',
            b'{"next_start":true,"cooldown_until":0}',
            b'{"next_start":-1,"cooldown_until":0}',
            b'{"next_start":"10","cooldown_until":0}',
            b'{"next_start":NaN,"cooldown_until":0}',
            b'{"next_start":Infinity,"cooldown_until":0}',
            b'{"next_start":0,"cooldown_until":0}' + b" " * 1024,
        ]
        for raw in samples:
            with self.subTest(raw=raw[:100]), tempfile.TemporaryFile() as stream:
                stream.write(raw)
                stream.flush()
                with self.assertRaises(policy.RequestPolicyUnavailable) as raised:
                    scheduler._read(stream.fileno())
                self.assertEqual(str(raised.exception),
                                 "The shared API request scheduler is unavailable.")

    def test_invalid_interval_is_not_accepted(self):
        for interval in (True, False, 0, -0.1, -1, float("inf"), float("nan"), "10", None, 10**1000):
            with self.subTest(interval=interval):
                with self.assertRaises(ValueError):
                    policy.RequestPolicy(interval=interval)

    def test_custom_positive_interval_controls_spacing(self):
        clock = FakeClock()
        scheduler = policy.RequestPolicy(interval=0.125, clock=clock, sleeper=clock.sleep)
        with patch.object(policy.sys, "platform", "win32"):
            with scheduler.request_slot():
                self.assertEqual(clock(), 100.0)
            with scheduler.request_slot():
                self.assertEqual(clock(), 100.125)
        self.assertEqual(clock.sleeps, [0.125])

    def test_shared_default_loads_config_once_before_first_request(self):
        from magnum_config import Settings
        slot = object()
        with patch.object(policy, "_default_policy", None), patch.object(
                policy, "load_settings", return_value=Settings(0.75)) as load, patch.object(
                policy, "RequestPolicy") as factory:
            factory.return_value.request_slot.return_value = slot
            self.assertIs(policy.request_slot(), slot)
            self.assertIs(policy.request_slot(), slot)
            load.assert_called_once_with()
            factory.assert_called_once_with(interval=0.75)

    def test_invalid_config_does_not_create_scheduler_or_request(self):
        from magnum_config import ConfigurationError
        with patch.object(policy, "_default_policy", None), patch.object(
                policy, "load_settings", side_effect=ConfigurationError()), patch.object(
                policy, "RequestPolicy") as factory:
            with self.assertRaises(policy.RequestPolicyUnavailable):
                policy.request_slot()
            self.assertIsNone(policy._default_policy)
            factory.assert_not_called()


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux private-runtime/flock tests")
class LinuxRequestPolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="magnum-policy-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        os.chmod(self.root, 0o700)
        self.clock = FakeClock()

    def make_policy(self, root=None):
        return policy.RequestPolicy(clock=self.clock, sleeper=self.clock.sleep,
                                    runtime_dir=self.root if root is None else root)

    def file(self):
        return self.root / "magnumgo-http.lock"

    def seed(self, raw, *, mode=0o600):
        self.file().write_bytes(raw)
        os.chmod(self.file(), mode)

    def assert_unavailable(self, scheduler=None):
        with self.assertRaises(policy.RequestPolicyUnavailable):
            with (scheduler or self.make_policy()).request_slot():
                self.fail("Unsafe scheduler must never yield a request slot")

    def test_separate_instances_serialize_the_entire_request_and_share_spacing(self):
        first, second = self.make_policy(), self.make_policy()
        contended = threading.Event()
        first_finished = threading.Event()
        second_entered = threading.Event()
        failures = []
        starts = []

        def lock_wait(duration):
            self.assertEqual(duration, 0.05)
            contended.set()
            if not first_finished.wait(timeout=5):
                raise AssertionError("First request did not finish")

        def run_second():
            try:
                with second.request_slot():
                    starts.append(self.clock())
                    second_entered.set()
            except BaseException as error:
                failures.append(error)

        thread = threading.Thread(target=run_second, daemon=True)
        with patch.object(policy.time, "sleep", side_effect=lock_wait):
            try:
                with first.request_slot():
                    starts.append(self.clock())
                    thread.start()
                    self.assertTrue(contended.wait(timeout=5), "Second instance did not attempt the shared lock")
                    self.assertFalse(second_entered.is_set(), "Requests overlapped")
            finally:
                first_finished.set()
                if thread.ident is not None:
                    thread.join(timeout=5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(failures, [])
        self.assertTrue(second_entered.is_set())
        self.assertEqual(starts, [100.0, 100.5])
        self.assertEqual(self.clock.sleeps, [0.5])

    def test_shared_file_contains_only_timestamps_and_429_is_shared(self):
        first, second = self.make_policy(), self.make_policy()
        with self.assertRaises(SyntheticHTTP429):
            with first.request_slot():
                raise SyntheticHTTP429(123)
        with self.assertRaises(policy.RequestDeferred) as raised:
            with second.request_slot():
                self.fail("Another instance must respect the shared cooldown")
        self.assertEqual(raised.exception.retry_after_seconds, 123)
        raw = self.file().read_bytes()
        state = json.loads(raw)
        self.assertEqual(set(state), {"next_start", "cooldown_until"})
        self.assertEqual(state, {"next_start": 100.5, "cooldown_until": 223.0})
        self.assertTrue(all(type(value) in (int, float) for value in state.values()))
        self.assertNotIn(b"token", raw)
        self.assertNotIn(b"request", raw)
        self.assertEqual(self.file().stat().st_mode & 0o777, 0o600)

    def test_corrupt_shared_file_does_not_run_request_or_get_overwritten(self):
        raw = b'["next_start","cooldown_until"]'
        self.seed(raw)
        self.assert_unavailable()
        self.assertEqual(self.file().read_bytes(), raw)

    def test_runtime_directory_shared_permissions_fail_closed(self):
        os.chmod(self.root, 0o755)
        self.assert_unavailable()
        self.assertFalse(self.file().exists())

    def test_lock_shared_permissions_fail_closed(self):
        self.seed(b"", mode=0o644)
        self.assert_unavailable()
        self.assertEqual(self.file().read_bytes(), b"")

    def test_symlink_lock_fails_closed_without_touching_target(self):
        target = self.root / "other-file"
        target.write_bytes(b"synthetic sentinel")
        os.chmod(target, 0o600)
        self.file().symlink_to(target)
        self.assert_unavailable()
        self.assertEqual(target.read_bytes(), b"synthetic sentinel")

    def test_symlink_runtime_directory_fails_closed(self):
        link = self.root / "runtime-link"
        actual = self.root / "actual-runtime"
        actual.mkdir(mode=0o700)
        link.symlink_to(actual, target_is_directory=True)
        self.assert_unavailable(self.make_policy(root=link))
        self.assertFalse((actual / self.file().name).exists())

    def test_hardlinked_lock_fails_closed_without_touching_either_link(self):
        target = self.root / "other-file"
        target.write_bytes(b"synthetic sentinel")
        os.chmod(target, 0o600)
        os.link(target, self.file())
        self.assert_unavailable()
        self.assertEqual(target.read_bytes(), b"synthetic sentinel")

    def test_non_regular_lock_fails_closed(self):
        self.file().mkdir(mode=0o700)
        self.assert_unavailable()

    def test_another_owner_fails_closed(self):
        with patch.object(policy.os, "getuid", return_value=os.getuid() + 1):
            self.assert_unavailable()
        self.assertFalse(self.file().exists())


if __name__ == "__main__":
    unittest.main()
