"""Offline auth tests. No network, real prompts, or OS credential access."""

import base64
import contextlib
import getpass
import io
import json
import pathlib
import sys
import time
import types
import unittest
import warnings
from unittest.mock import Mock, patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import magnum_auth as auth
from magnum_vault import SessionRecord, VaultError
_REAL_MUTATION_LOCK = auth._mutation_lock


def token(expiry):
    payload = base64.urlsafe_b64encode(json.dumps({"exp": expiry}).encode()).decode().rstrip("=")
    return "eyJhbGciOiJub25lIn0." + payload + ".test-signature"


class MemoryStore:
    def __init__(self, record=None, available=True):
        self.record = record
        self.available = available
        self.writes = []
        self.deleted = False

    def check(self):
        return types.SimpleNamespace(available=self.available, backend="mock", reason=None)

    def read(self):
        return self.record

    def write(self, record):
        self.record = record
        self.writes.append(record)

    def delete(self):
        existed = self.record is not None
        self.record = None
        self.deleted = True
        return existed


class AuthTests(unittest.TestCase):
    def setUp(self):
        self.store = MemoryStore()
        self.probe = MemoryStore()
        self.phone = "+70000000000"
        self.wire_phone = self.phone[1:]
        self.code = "001234"
        self.expiry = int(time.time()) + 3600
        self.access = token(self.expiry)
        self.refresh = "test-refresh-token-never-print"
        self.network = patch.object(auth, "_http_request", side_effect=AssertionError("No real network"))
        self.network.start()
        self.addCleanup(self.network.stop)
        self.lock = patch.object(auth, "_mutation_lock", return_value=contextlib.nullcontext())
        self.lock.start()
        self.addCleanup(self.lock.stop)

    def factory(self, **kwargs):
        return self.probe if "target" in kwargs else self.store

    def response(self):
        return {"token": self.access, "refreshToken": self.refresh}

    def test_status_without_network_and_without_secrets(self):
        self.store.record = SessionRecord(self.access, self.refresh, kind="user", expires_at=int(time.time()) + 3600)
        status = auth.auth_status(self.store)
        serialized = json.dumps(status)
        self.assertTrue(status["local_session_present"])
        self.assertTrue(status["ready_user"])
        self.assertEqual(status["server_validation"], "not_checked")
        self.assertTrue(status["expires_at"].endswith("Z"))
        for secret in (self.access, self.refresh, self.phone, self.code):
            self.assertNotIn(secret, serialized)

    def test_missing_guest_and_expired_do_not_silently_log_in(self):
        provider = auth.AuthSession(self.store)
        with self.assertRaises(auth.AuthError) as missing:
            provider.get_access_token()
        self.assertEqual(missing.exception.code, "needs_login")
        self.store.record = SessionRecord(self.access, kind="guest")
        with self.assertRaises(auth.AuthError) as guest:
            provider.get_access_token()
        self.assertEqual(guest.exception.code, "guest_only")
        self.assertEqual(provider.get_access_token(require_user=False), self.access)
        self.store.record = SessionRecord(self.access, kind="user", expires_at=1)
        with self.assertRaises(auth.AuthError) as expired:
            provider.get_access_token()
        self.assertEqual(expired.exception.reason, "expired")
        self.assertTrue(auth.auth_status(self.store)["needs_login"])

    def test_user_token_provider_is_local(self):
        self.store.record = SessionRecord(self.access, kind="user", expires_at=int(time.time()) + 3600)
        self.assertEqual(auth.AuthSession(self.store).get_access_token(), self.access)
        self.assertNotIn(self.access, repr(auth.AuthSession(self.store)))
        self.assertNotIn(self.access, repr(self.store.record))

    def test_login_no_echo_no_auth_headers_and_exactly_two_requests(self):
        calls = []
        def request(method, url, headers, body):
            calls.append((method, url, headers, json.loads(body)))
            self.assertNotIn("Authorization", headers)
            self.assertEqual(method, "POST")
            if url.endswith("/first"):
                self.assertEqual(json.loads(body), {"phone": self.wire_phone})
                return b"{}"
            self.assertTrue(url.endswith("/second"))
            self.assertEqual(json.loads(body), {"phone": self.wire_phone, "pin": "0123", "smsCode": self.code})
            return json.dumps(self.response()).encode()
        output, errors = io.StringIO(), io.StringIO()
        with patch.object(auth, "SecretStore", side_effect=self.factory), \
             patch.object(auth, "_require_local_tty"), \
             patch.object(auth.getpass, "getpass", side_effect=[self.phone, self.code]) as prompt, \
             patch.object(auth, "_http_request", side_effect=request), \
             contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            self.assertEqual(auth.main(["login", "--terminal"]), 0)
        self.assertEqual(len(calls), 2)
        self.assertEqual(prompt.call_count, 2)
        self.assertTrue(self.probe.deleted)
        self.assertEqual(self.store.record.kind, "user")
        self.assertEqual(self.store.record.refresh_token, self.refresh)
        for secret in (self.phone, self.code, self.access, self.refresh):
            self.assertNotIn(secret, output.getvalue() + errors.getvalue())

    def test_headless_login_refused_before_network(self):
        stream = io.StringIO()
        with patch.object(auth.sys, "stdin", stream), patch.object(auth.sys, "stderr", stream):
            with self.assertRaises(auth.AuthError) as failure:
                auth._interactive_login(self.store)
        self.assertEqual(failure.exception.code, "local_terminal_required")

    def test_getpass_fallback_is_error_before_reading_value(self):
        def unsupported(*args, **kwargs):
            warnings.warn("Cannot control echo", getpass.GetPassWarning)
            raise AssertionError("Fallback must never be reached")
        with patch.object(auth, "_require_local_tty"), patch.object(auth.getpass, "getpass", side_effect=unsupported):
            with self.assertRaises(auth.AuthError) as failure:
                auth._secure_prompt("Hidden: ")
        self.assertEqual(failure.exception.code, "secure_prompt_unavailable")

    def test_flow_requires_preflight_and_pins_normalized_phone(self):
        flow = auth.LoginFlow(self.store)
        with self.assertRaises(auth.AuthError):
            flow.request_sms(self.phone)
        with patch.object(auth, "_preflight_store") as preflight, patch.object(auth, "_post_auth", return_value=None) as post:
            flow.preflight()
            flow.preflight()
            preflight.assert_called_once_with(self.store)
            flow.request_sms("+7(000) 000-00-00")
            post.assert_called_once_with("first", {"phone": self.wire_phone}, parse_json=False)
            with self.assertRaises(auth.AuthError) as mismatch:
                flow.verify_sms("+71111111111", self.code)
            self.assertEqual(mismatch.exception.code, "invalid_phone")
            self.assertEqual(post.call_count, 1)
        self.assertNotIn(self.phone, repr(flow))

    def test_auth_wire_schema_matches_apk_pin_phone_and_sms_code(self):
        requests = []
        def request(method, url, headers, body):
            payload = json.loads(body)
            requests.append((url, payload))
            self.assertEqual(method, "POST")
            self.assertNotIn("Authorization", headers)
            self.assertRegex(payload["phone"], r"^7[0-9]{10}$")
            self.assertNotIn("+", payload["phone"])
            return b"{}" if url.endswith("/first") else json.dumps(self.response()).encode()
        flow = auth.LoginFlow(self.store)
        with patch.object(auth, "_preflight_store"), patch.object(auth, "_http_request", side_effect=request):
            flow.preflight()
            flow.request_sms("+7 (000) 000-00-00")
            self.assertEqual(flow._phone, self.phone)
            status = flow.verify_sms(self.phone, self.code)
        self.assertEqual(len(requests), 2)
        self.assertTrue(requests[0][0].endswith("/first"))
        self.assertTrue(requests[1][0].endswith("/second"))
        self.assertEqual(requests[0][1], {"phone": self.wire_phone})
        self.assertEqual(requests[1][1], {"phone": self.wire_phone, "pin": "0123", "smsCode": self.code})
        self.assertEqual(set(requests[1][1]), {"phone", "pin", "smsCode"})
        self.assertEqual(auth._APP_LOGIN_PIN, "0123")
        self.assertTrue(status["ready_user"])
        self.assertEqual(auth._normalize_phone("+7 (000) 000-00-00"), self.phone)

    def test_second_step_without_apk_pin_is_rejected_before_transport(self):
        with patch.object(auth, "_http_request") as network:
            with self.assertRaises(auth.AuthError) as failure:
                auth._post_auth("second", {"phone": self.wire_phone, "smsCode": self.code})
        self.assertEqual(failure.exception.code, "invalid_response")
        network.assert_not_called()

    def test_flow_never_resends_sms_after_failed_request(self):
        flow = auth.LoginFlow(self.store)
        with patch.object(auth, "_preflight_store"), patch.object(auth, "_post_auth", side_effect=auth.AuthError("request_failed")) as post:
            flow.preflight()
            with self.assertRaises(auth.AuthError):
                flow.request_sms(self.phone)
            with self.assertRaises(auth.AuthError) as repeated:
                flow.request_sms(self.phone)
        self.assertEqual(repeated.exception.code, "sms_already_requested")
        self.assertEqual(post.call_count, 1)

    def test_flow_verification_requires_explicit_submits_and_stops_after_three(self):
        flow = auth.LoginFlow(self.store)
        with patch.object(auth, "_preflight_store"), patch.object(auth, "_post_auth", return_value=None) as post:
            flow.preflight()
            flow.request_sms(self.phone)
            post.side_effect = auth.AuthError("request_failed")
            for _ in range(3):
                with self.assertRaises(auth.AuthError) as failure:
                    flow.verify_sms(self.phone, self.code)
                self.assertEqual(failure.exception.code, "request_failed")
            with self.assertRaises(auth.AuthError) as limit:
                flow.verify_sms(self.phone, self.code)
        self.assertEqual(limit.exception.code, "verification_limit")
        self.assertEqual(post.call_count, 4)

    def test_browser_is_default_and_emits_only_safe_ready_url_and_status(self):
        class WebError(Exception):
            pass
        def serve(backend, **options):
            self.assertEqual(options["port"], 0)
            self.assertIsNone(options["timeout"])
            self.assertFalse(options["open_browser"])
            backend.preflight()
            options["on_ready"]("http://127.0.0.1:8765/bootstrap?nonce=test-nonce")
            backend.request_sms(self.phone)
            return backend.verify_sms(self.phone, self.code)
        web = types.SimpleNamespace(LoginWebError=WebError, serve_login=serve)
        output, errors = io.StringIO(), io.StringIO()
        with patch.dict(sys.modules, {"magnum_login_web": web}), \
             patch.object(auth, "SecretStore", side_effect=self.factory), \
             patch.object(auth, "_http_request", side_effect=[b"{}", json.dumps(self.response()).encode()]), \
             patch.object(auth, "_require_local_tty", side_effect=AssertionError("Browser must not require TTY")), \
             contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            self.assertEqual(auth.main(["login", "--no-open", "--port", "0"]), 0)
        self.assertTrue(json.loads(output.getvalue().splitlines()[0])["login_url"].startswith("http://127.0.0.1:"))
        for secret in (self.phone, self.code, self.access, self.refresh):
            self.assertNotIn(secret, output.getvalue() + errors.getvalue())
        self.assertEqual(self.store.record.kind, "user")

    def test_vault_unavailable_or_read_denied_prevents_sms_and_prompts(self):
        for unavailable in (True, False):
            store = MemoryStore(available=not unavailable)
            if not unavailable:
                store.read = lambda: (_ for _ in ()).throw(VaultError("vault_access_denied"))
            with patch.object(auth, "_require_local_tty"), patch.object(auth.getpass, "getpass") as prompt:
                with self.assertRaises(auth.AuthError):
                    auth._interactive_login(store)
                prompt.assert_not_called()

    def test_probe_write_failure_prevents_sms(self):
        self.probe.write = lambda record: (_ for _ in ()).throw(VaultError("vault_write_failed"))
        with patch.object(auth, "_require_local_tty"), patch.object(auth, "SecretStore", side_effect=self.factory), \
             patch.object(auth.getpass, "getpass") as prompt:
            with self.assertRaises(auth.AuthError) as failure:
                auth._interactive_login(self.store)
            prompt.assert_not_called()
        self.assertEqual(failure.exception.code, "vault_preflight_failed")

    def test_first_failure_not_retried_and_code_not_requested(self):
        with patch.object(auth, "_require_local_tty"), patch.object(auth, "SecretStore", side_effect=self.factory), \
             patch.object(auth.getpass, "getpass", return_value=self.phone) as prompt, \
             patch.object(auth, "_http_request", side_effect=auth.MagnumAPIError("HTTP 429.")) as network:
            with self.assertRaises(auth.AuthError) as failure:
                auth._interactive_login(self.store)
        self.assertEqual(failure.exception.http_status, 429)
        self.assertEqual(network.call_count, 1)
        self.assertEqual(prompt.call_count, 1)
        self.assertIsNone(self.store.record)

    def test_second_failure_not_retried_or_logged(self):
        with patch.object(auth, "SecretStore", side_effect=self.factory), \
             patch.object(auth, "_require_local_tty"), \
             patch.object(auth.getpass, "getpass", side_effect=[self.phone, self.code]), \
             patch.object(auth, "_http_request", side_effect=[b"{}", auth.MagnumAPIError(self.phone + self.code + self.access)]) as network:
            output, errors = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                self.assertEqual(auth.main(["login", "--terminal"]), 1)
        self.assertEqual(network.call_count, 2)
        for secret in (self.phone, self.code, self.access):
            self.assertNotIn(secret, output.getvalue() + errors.getvalue())
        self.assertIsNone(self.store.record)

    def test_unexpected_response_fails_closed(self):
        invalid = [{}, {"token": self.access}, {"token": 1, "refreshToken": self.refresh},
                   {"token": self.access, "refreshToken": "123456"}, [self.access],
                   {"token": self.access + "\n", "refreshToken": self.refresh}]
        for value in invalid:
            with self.assertRaises(auth.AuthError):
                auth._save_session(self.store, value, "user")
        self.assertFalse(self.store.writes)

    def test_guest_login_cannot_replace_user(self):
        self.store.record = SessionRecord(self.access, kind="user")
        with self.assertRaises(auth.AuthError) as failure:
            auth._guest_login(self.store)
        self.assertEqual(failure.exception.code, "guest_would_replace_user")
        self.assertFalse(self.store.writes)

    def test_bearer_prefix_normalized_exactly_once(self):
        record = auth._session_record({"token": "Bearer " + self.access, "refreshToken": "Bearer " + self.refresh}, "guest")
        self.assertEqual(record.token, self.access)
        self.assertEqual(record.refresh_token, self.refresh)
        self.assertEqual(record.expires_at, self.expiry)
        for value in (" Bearer " + self.access, "Bearer  " + self.access, "Bearer Bearer " + self.access,
                      self.access + " ", "bearer " + self.access, self.access + "\n"):
            with self.assertRaises(auth.AuthError):
                auth._normalize_token(value)

    def test_guest_login_saved_as_guest(self):
        with patch.object(auth, "SecretStore", side_effect=self.factory), \
             patch.object(auth, "_http_request", return_value=json.dumps(self.response()).encode()) as network:
            status = auth._guest_login(self.store)
        self.assertEqual(self.store.record.kind, "guest")
        self.assertTrue(status["needs_login"])
        self.assertFalse(status["ready_user"])
        self.assertEqual(network.call_count, 1)

    def test_guest_login_rechecks_user_after_network(self):
        def concurrent_login(*args):
            self.store.record = SessionRecord(self.access, kind="user")
            return json.dumps(self.response()).encode()
        with patch.object(auth, "SecretStore", side_effect=self.factory), \
             patch.object(auth, "_http_request", side_effect=concurrent_login):
            with self.assertRaises(auth.AuthError) as failure:
                auth._guest_login(self.store)
        self.assertEqual(failure.exception.code, "guest_would_replace_user")
        self.assertEqual(self.store.record.kind, "user")
        self.assertFalse(self.store.writes)

    def test_mutating_cli_requires_lock_before_network(self):
        with patch.object(auth, "SecretStore", side_effect=self.factory), \
             patch.object(auth, "_mutation_lock", side_effect=auth.AuthError("auth_busy")), \
             patch.object(auth.getpass, "getpass") as prompt:
            errors = io.StringIO()
            with contextlib.redirect_stderr(errors):
                self.assertEqual(auth.main(["login", "--terminal"]), 1)
            prompt.assert_not_called()
            self.assertIn("auth_busy", errors.getvalue())

    def test_posix_lock_is_private_and_released_without_a_real_file(self):
        fcntl = types.SimpleNamespace(LOCK_EX=2, LOCK_NB=4, flock=Mock())
        metadata = types.SimpleNamespace(st_mode=auth.stat.S_IFREG | 0o600, st_uid=1000)
        runtime = types.SimpleNamespace(st_mode=auth.stat.S_IFDIR | 0o700, st_uid=1000)
        with patch.dict(sys.modules, {"fcntl": fcntl}), patch.object(auth.sys, "platform", "linux"), \
             patch.object(auth.os, "getuid", return_value=1000, create=True), \
             patch.object(auth.os, "lstat", return_value=runtime), \
             patch.object(auth.os, "open", return_value=77) as opened, \
             patch.object(auth.os, "fstat", return_value=metadata), patch.object(auth.os, "close") as closed:
            with _REAL_MUTATION_LOCK():
                pass
        self.assertEqual(opened.call_args.args[0].replace("\\", "/"), "/run/user/1000/magnumgo-auth.lock")
        self.assertEqual(opened.call_args.args[2], 0o600)
        fcntl.flock.assert_called_once_with(77, 6)
        closed.assert_called_once_with(77)

    def test_posix_lock_rejects_other_owner_without_a_real_file(self):
        fcntl = types.SimpleNamespace(LOCK_EX=2, LOCK_NB=4, flock=Mock())
        metadata = types.SimpleNamespace(st_mode=auth.stat.S_IFREG | 0o600, st_uid=1001)
        runtime = types.SimpleNamespace(st_mode=auth.stat.S_IFDIR | 0o700, st_uid=1000)
        with patch.dict(sys.modules, {"fcntl": fcntl}), patch.object(auth.sys, "platform", "linux"), \
             patch.object(auth.os, "getuid", return_value=1000, create=True), \
             patch.object(auth.os, "lstat", return_value=runtime), \
             patch.object(auth.os, "open", return_value=77), patch.object(auth.os, "fstat", return_value=metadata), \
             patch.object(auth.os, "close") as closed:
            with self.assertRaises(auth.AuthError) as failure:
                with _REAL_MUTATION_LOCK():
                    self.fail("Unsafe lock was acquired")
        self.assertEqual(failure.exception.code, "auth_lock_unavailable")
        fcntl.flock.assert_not_called()
        closed.assert_called_once_with(77)

    def test_posix_lock_refuses_unsafe_runtime_directory(self):
        fcntl = types.SimpleNamespace(LOCK_EX=2, LOCK_NB=4, flock=Mock())
        unsafe = [
            types.SimpleNamespace(st_mode=auth.stat.S_IFLNK | 0o700, st_uid=1000),
            types.SimpleNamespace(st_mode=auth.stat.S_IFDIR | 0o755, st_uid=1000),
            types.SimpleNamespace(st_mode=auth.stat.S_IFDIR | 0o700, st_uid=1001),
        ]
        for metadata in unsafe:
            with patch.dict(sys.modules, {"fcntl": fcntl}), patch.object(auth.sys, "platform", "linux"), \
                 patch.object(auth.os, "getuid", return_value=1000, create=True), \
                 patch.object(auth.os, "lstat", return_value=metadata), patch.object(auth.os, "open") as opened:
                with self.assertRaises(auth.AuthError) as failure:
                    with _REAL_MUTATION_LOCK():
                        self.fail("Unsafe runtime directory was accepted")
                self.assertEqual(failure.exception.code, "auth_lock_unavailable")
                opened.assert_not_called()

    def test_windows_mutex_released_without_real_os_calls(self):
        import ctypes
        dll = types.SimpleNamespace(CreateMutexW=Mock(return_value=99), WaitForSingleObject=Mock(return_value=0),
                                    ReleaseMutex=Mock(), CloseHandle=Mock())
        with patch.object(auth.sys, "platform", "win32"), patch.object(ctypes, "WinDLL", return_value=dll, create=True):
            with _REAL_MUTATION_LOCK():
                pass
        dll.ReleaseMutex.assert_called_once_with(99)
        dll.CloseHandle.assert_called_once_with(99)

    def test_arguments_never_echo_mistaken_secrets(self):
        output, errors = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            code = auth.main(["login", "--phone", self.phone, "--code", self.code, "--token", self.access])
        self.assertEqual(code, 1)
        for secret in (self.phone, self.code, self.access):
            self.assertNotIn(secret, output.getvalue() + errors.getvalue())

    def test_logout_is_local_only(self):
        self.store.record = SessionRecord(self.access, kind="user")
        output = io.StringIO()
        with patch.object(auth, "SecretStore", side_effect=self.factory), contextlib.redirect_stdout(output):
            self.assertEqual(auth.main(["logout"]), 0)
        result = json.loads(output.getvalue())
        self.assertTrue(result["local_session_deleted"])
        self.assertFalse(result["server_revocation_performed"])
        self.assertIsNone(self.store.record)

    def test_jwt_exp_is_only_hint_and_malformed_hint_is_safe(self):
        self.assertEqual(auth._expiry_hint(self.access), self.expiry)
        self.assertIsNone(auth._expiry_hint("opaque-token-not-a-jwt"))
        self.assertIsNone(auth._expiry_hint("x.bad!.z"))
        self.assertIsNone(auth._expiry_hint(token(True)))
        self.assertIsNone(auth._expiry_hint(token(2**60)))

    def test_status_vault_error_is_sanitized(self):
        self.store.read = lambda: (_ for _ in ()).throw(RuntimeError(self.access))
        result = auth.auth_status(self.store)
        self.assertEqual(result["state"], "vault_unavailable")
        self.assertNotIn(self.access, json.dumps(result))


if __name__ == "__main__":
    unittest.main()

