"""Loopback-only browser security tests; no Magnum API or real vault is used."""
import contextlib
import http.client
import html
import io
import json
from pathlib import Path
import re
import socket
import sys
import threading
import time
import unittest
from unittest.mock import patch
import urllib.parse

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import magnum_login_web as web


PHONE = "+77011234567"
CODE = "001234"
BACKEND_SECRET = "synthetic-backend-token-never-render"


class Backend:
    def __init__(self):
        self.calls = []
        self.fail_send = False
        self.fail_verify = False

    def preflight(self):
        self.calls.append(("preflight",))

    def request_sms(self, phone):
        self.calls.append(("send", phone))
        if self.fail_send:
            raise RuntimeError(BACKEND_SECRET + PHONE)

    def verify_sms(self, phone, code):
        self.calls.append(("verify", phone, code))
        if self.fail_verify:
            error = RuntimeError(BACKEND_SECRET + PHONE + CODE)
            error.reason = "sms_code_invalid"
            raise error
        return {
            "ready_user": True, "kind": "user", "needs_login": False,
            "backend": "linux_systemd_credentials", "expires_at": "2030-01-01T00:00:00Z",
            "token": BACKEND_SECRET, "phone": phone, "smsCode": code,
        }


class WebTests(unittest.TestCase):
    def setUp(self):
        self.backend = Backend()
        self.server = web._LoginServer(self.backend, 0, 10)
        self.results = []
        self.failures = []
        self.stderr = io.StringIO()

        def run():
            try:
                with contextlib.redirect_stderr(self.stderr):
                    self.results.append(self.server.run())
            except web.LoginWebError as error:
                self.failures.append(error.code)
            finally:
                self.server.server_close()

        self.thread = threading.Thread(target=run, daemon=True)
        self.thread.start()
        self.cookie = None
        self.csrf = None

    def tearDown(self):
        self.server.finished = True
        self.thread.join(2)
        self.assertFalse(self.thread.is_alive())
        self.assertNotIn(PHONE, self.stderr.getvalue())
        self.assertNotIn(CODE, self.stderr.getvalue())
        self.assertNotIn(BACKEND_SECRET, self.stderr.getvalue())

    def request(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_address[1], timeout=2)
        try:
            connection.request(method, path, body=body, headers=headers or {})
            response = connection.getresponse()
            data = response.read().decode("utf-8")
            result = (response.status, dict(response.getheaders()), data)
            for secret in (PHONE, CODE, BACKEND_SECRET):
                self.assertNotIn(secret, data)
            return result
        finally:
            connection.close()

    def bootstrap(self):
        status, headers, body = self.request("GET", self.server.bootstrap)
        self.assertEqual(status, 303)
        self.assertEqual(headers["Location"], "/login")
        self.assertEqual(body, "")
        self.cookie = headers["Set-Cookie"].split(";", 1)[0]
        self.assertIn("HttpOnly", headers["Set-Cookie"])
        self.assertIn("SameSite=Strict", headers["Set-Cookie"])
        status, headers, body = self.request("GET", "/login", headers={"Cookie": self.cookie})
        self.assertEqual(status, 200)
        self.csrf = re.search(r'name="csrf" value="([A-Za-z0-9_-]+)"', body).group(1)
        return headers, body

    def post(self, path, fields, extra_headers=None):
        headers = {
            "Origin": self.server.origin, "Cookie": self.cookie,
            "Content-Type": "application/x-www-form-urlencoded",
        }
        headers.update(extra_headers or {})
        return self.request("POST", path, urllib.parse.urlencode(fields), headers)

    def send(self):
        self.bootstrap()
        return self.post("/send", {"csrf": self.csrf, "phone": PHONE})

    def test_bind_bootstrap_cookie_and_security_headers(self):
        self.assertEqual(self.server.server_address[0], "127.0.0.1")
        bootstrap_path = self.server.bootstrap
        headers, body = self.bootstrap()
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(headers["Referrer-Policy"], "same-origin")
        policy = headers["Content-Security-Policy"]
        for directive in ("default-src 'none'", "frame-ancestors 'none'", "base-uri 'none'", "form-action 'self'"):
            self.assertIn(directive, policy)
        self.assertNotIn("<script", body)
        self.assertNotIn(bootstrap_path, body)
        self.assertEqual(self.request("GET", bootstrap_path)[0], 403)
        self.assertEqual(self.request("GET", "/login")[0], 403)
        self.assertEqual(self.backend.calls, [])

    def test_host_origin_cookie_and_csrf_forgery_never_calls_backend(self):
        self.bootstrap()
        valid = {"csrf": self.csrf, "phone": PHONE}
        self.assertEqual(self.post("/send", valid, {"Host": "evil.example"})[0], 403)
        self.assertEqual(self.post("/send", valid, {"Origin": "https://evil.example"})[0], 403)
        self.assertEqual(self.post("/send", valid, {"Cookie": "magnum_login_session=wrong"})[0], 403)
        self.assertEqual(self.post("/send", {"csrf": "wrong", "phone": PHONE})[0], 403)
        headers = {"Cookie": self.cookie, "Content-Type": "application/x-www-form-urlencoded"}
        self.assertEqual(self.request("POST", "/send", urllib.parse.urlencode(valid), headers)[0], 403)
        self.assertEqual(self.backend.calls, [])

    def test_form_referrer_policy_preserves_origin_without_accepting_null(self):
        headers, _ = self.bootstrap()
        # Fetch's append-a-request-origin-header algorithm maps no-referrer to
        # Origin:null for native form POSTs. Keep same-origin instead, while
        # preserving the strict guard rather than accepting null origins.
        self.assertEqual(headers["Referrer-Policy"], "same-origin")
        fields = {"csrf": self.csrf, "phone": PHONE}
        self.assertEqual(self.post("/send", fields, {"Origin": "null"})[0], 403)
        self.assertEqual(self.backend.calls, [])
        self.assertEqual(self.post("/send", fields)[0], 303)
        self.assertEqual(self.backend.calls, [("send", PHONE)])

    def test_body_cap_duplicate_fields_and_content_type(self):
        self.bootstrap()
        headers = {"Origin": self.server.origin, "Cookie": self.cookie, "Content-Type": "application/x-www-form-urlencoded"}
        self.assertEqual(self.request("POST", "/send", b"x" * 4097, headers)[0], 403)
        raw = urllib.parse.urlencode({"csrf": self.csrf, "phone": PHONE}) + "&phone=duplicate"
        self.assertEqual(self.request("POST", "/send", raw, headers)[0], 403)
        self.assertEqual(self.post("/send", {"csrf": self.csrf, "phone": PHONE}, {"Content-Type": "text/plain"})[0], 403)
        self.assertEqual(self.backend.calls, [])

    def test_invalid_phone_and_code_do_not_reach_backend(self):
        self.bootstrap()
        self.assertEqual(self.post("/send", {"csrf": self.csrf, "phone": "bad"})[0], 303)
        self.assertEqual(self.backend.calls, [])
        self.assertEqual(self.post("/verify", {"csrf": self.csrf, "smsCode": CODE})[0], 409)
        self.assertEqual(self.post("/send", {"csrf": self.csrf, "phone": "+7 (701) 123-45-67"})[0], 303)
        self.assertEqual(self.post("/verify", {"csrf": self.csrf, "smsCode": "bad"})[0], 303)
        self.assertEqual(self.backend.calls, [("send", PHONE)])

    def test_one_send_success_preserves_zeroes_and_returns_no_secrets(self):
        self.assertEqual(self.send()[0], 303)
        self.assertEqual(self.post("/send", {"csrf": self.csrf, "phone": PHONE})[0], 409)
        self.assertEqual(self.post("/verify", {"csrf": self.csrf, "smsCode": CODE})[0], 200)
        self.thread.join(2)
        self.assertEqual(self.backend.calls, [("send", PHONE), ("verify", PHONE, CODE)])
        self.assertEqual(len(self.results), 1)
        encoded = repr(self.results)
        for secret in (PHONE, CODE, BACKEND_SECRET):
            self.assertNotIn(secret, encoded)
        self.assertTrue(self.results[0]["ready_user"])
        self.assertEqual(self.results[0]["backend"], "linux_systemd_credentials")

    def test_failed_send_is_once_and_exception_text_is_hidden(self):
        self.backend.fail_send = True
        status, _, body = self.send()
        self.assertEqual(status, 503)
        self.thread.join(2)
        self.assertEqual(self.failures, ["sms_request_failed"])
        self.assertEqual(self.backend.calls, [("send", PHONE)])
        self.assertEqual(self.results, [])

    def test_explicit_code_attempt_limit_and_no_automatic_retries(self):
        self.backend.fail_verify = True
        self.send()
        for expected in (303, 303, 429):
            self.assertEqual(self.post("/verify", {"csrf": self.csrf, "smsCode": CODE})[0], expected)
        self.thread.join(2)
        self.assertEqual(self.failures, ["code_attempts_exhausted"])
        self.assertEqual(self.backend.calls, [("send", PHONE)] + [("verify", PHONE, CODE)] * 3)

    def test_unknown_upstream_error_stops_after_one_without_wrong_code_prompt(self):
        self.send()
        error = RuntimeError(BACKEND_SECRET + PHONE + CODE)
        error.reason = "unknown"
        error.http_status = 400
        error.service_error_code = -1114
        with patch.object(self.backend, "verify_sms", side_effect=error) as verify:
            status, _, body = self.post("/verify", {"csrf": self.csrf, "smsCode": CODE})
            self.assertEqual(status, 502)
            verify.assert_called_once_with(PHONE, CODE)
        self.thread.join(2)
        self.assertFalse(self.thread.is_alive())
        self.assertTrue(self.server.finished)
        self.assertEqual(self.server.code_attempts, 1)
        self.assertNotIn("Проверьте код", body)
        self.assertNotIn("осталось попыток", body)
        self.assertNotIn("Неверный", body)

    def test_redacted_response_details_are_html_escaped_and_bounded(self):
        error = RuntimeError(BACKEND_SECRET + PHONE + CODE)
        markup = '<script>alert("synthetic-xss")</script>&<b>detail</b>'
        error.redacted_response_body = markup
        details = web._LoginHandler._error_details(error)
        self.assertIn(html.escape(markup), details)
        self.assertNotIn("<script", details)
        self.assertNotIn("<b>detail</b>", details)
        for secret in (PHONE, CODE, BACKEND_SECRET):
            self.assertNotIn(secret, details)
        long_body = "A" * 65536 + "TRUNCATED_DIAGNOSTIC_TAIL"
        error.redacted_response_body = long_body
        details = web._LoginHandler._error_details(error)
        self.assertIn("A" * 65536, details)
        self.assertNotIn("TRUNCATED_DIAGNOSTIC_TAIL", details)
        self.assertLess(len(details), 66000)
        error.redacted_response_body = None
        self.assertEqual(web._LoginHandler._error_details(error), "")

    def test_unknown_error_displays_complete_redacted_body_without_logging_it(self):
        self.send()
        error = RuntimeError(BACKEND_SECRET + PHONE + CODE)
        error.code = "request_failed"
        error.reason = "unknown"
        error.http_status = 400
        error.service_error_code = -1114
        redacted = json.dumps({
            "errorCode": -1114,
            "errorDescr": "Unknown failure [REDACTED]",
            "details": '<script>alert("synthetic-xss")</script>',
            "diagnosticTail": "complete-redacted-response-marker",
        }, indent=2)
        error.redacted_response_body = redacted
        # Deliberately hostile extra attributes must never be reflected or logged.
        error.raw_response_body = PHONE + CODE + BACKEND_SECRET
        error.authorization = "Bearer " + BACKEND_SECRET
        with patch.object(self.backend, "verify_sms", side_effect=error) as verify:
            status, _, body = self.post("/verify", {"csrf": self.csrf, "smsCode": CODE})
            self.assertEqual(status, 502)
            verify.assert_called_once_with(PHONE, CODE)
        self.thread.join(2)
        self.assertIn("Полный ответ Magnum", body)
        self.assertIn(html.escape(redacted), body)
        self.assertIn("complete-redacted-response-marker", body)
        self.assertNotIn("<script", body)
        self.assertNotIn("Проверьте код", body)
        for secret in (PHONE, CODE, BACKEND_SECRET):
            self.assertNotIn(secret, body)
            self.assertNotIn(secret, self.stderr.getvalue())
        rows = [json.loads(row) for row in self.stderr.getvalue().splitlines()]
        self.assertEqual(rows, [{
            "event": "login_backend_failure", "stage": "verify",
            "code": "request_failed", "http_status": 400,
            "service_error_code": -1114, "reason": "unknown",
        }])
        self.assertNotIn("complete-redacted-response-marker", self.stderr.getvalue())
        self.assertNotIn("redacted_response_body", self.stderr.getvalue())
        self.assertNotIn("raw_response_body", self.stderr.getvalue())

    def test_timeout_closes_without_sending_anything(self):
        self.server.deadline = time.monotonic() + 0.03
        self.thread.join(2)
        self.assertEqual(self.failures, ["login_timeout"])
        self.assertEqual(self.backend.calls, [])

    def test_default_has_no_total_expiry_and_uses_a_session_cookie(self):
        self.server.deadline = None
        with patch.object(web.time, "monotonic", return_value=time.monotonic() + 7200):
            self.assertFalse(self.server.expired())
            status, headers, _ = self.request("GET", self.server.bootstrap)
            self.assertEqual(status, 303)
            self.assertNotIn("Max-Age", headers["Set-Cookie"])
            self.cookie = headers["Set-Cookie"].split(";", 1)[0]
            status, _, body = self.request("GET", "/login", headers={"Cookie": self.cookie})
            self.assertEqual(status, 200)
            self.assertNotIn("Локальная страница", body)
            self.assertNotIn("Заказ и оплата", body)
            self.assertNotIn("10 минут", body)
        self.assertEqual(self.backend.calls, [])

    def test_public_default_is_unlimited_and_explicit_long_timeout_is_supported(self):
        with patch.object(web, "_LoginServer") as factory:
            factory.return_value.login_url = "http://127.0.0.1:12345/start/synthetic"
            web.serve_login(self.backend, open_browser=False, on_ready=lambda url: None)
            factory.assert_called_once_with(self.backend, 0, None)
        with patch.object(web, "_LoginServer") as factory:
            factory.return_value.login_url = "http://127.0.0.1:12345/start/synthetic"
            web.serve_login(self.backend, timeout=7200, open_browser=False, on_ready=lambda url: None)
            factory.assert_called_once_with(self.backend, 0, 7200)

    def test_backend_diagnostics_contain_only_allowlisted_metadata(self):
        error = RuntimeError(BACKEND_SECRET + PHONE + CODE)
        error.code = "request_failed"
        error.http_status = 429
        captured = io.StringIO()
        with contextlib.redirect_stderr(captured):
            web._log_backend_failure("verify", error)
            error.code = BACKEND_SECRET
            error.http_status = PHONE
            web._log_backend_failure(PHONE, error)
        rows = [json.loads(row) for row in captured.getvalue().splitlines()]
        self.assertEqual(rows[0], {"event": "login_backend_failure", "stage": "verify", "code": "request_failed", "http_status": 429})
        self.assertEqual(rows[1], {"event": "login_backend_failure", "stage": "unknown", "code": "backend_error"})
        for secret in (PHONE, CODE, BACKEND_SECRET):
            self.assertNotIn(secret, captured.getvalue())

    def test_trickled_headers_cannot_keep_flow_alive_past_deadline(self):
        self.server.deadline = time.monotonic() + 0.15
        connection = socket.create_connection(self.server.server_address, timeout=1)
        try:
            connection.sendall(b"GET /login HTTP/1.1\r\nHost: " + self.server.host.encode() + b"\r\nX-Slow: ")
            for _ in range(5):
                time.sleep(0.05)
                try:
                    connection.sendall(b"a")
                except OSError:
                    break
            self.thread.join(1)
            self.assertFalse(self.thread.is_alive())
            self.assertEqual(self.failures, ["login_timeout"])
            self.assertEqual(self.backend.calls, [])
        finally:
            connection.close()

    def test_preflight_failure_happens_before_listener_and_url(self):
        backend = Backend()
        backend.preflight = lambda: (_ for _ in ()).throw(RuntimeError(BACKEND_SECRET))
        with patch.object(web, "_LoginServer") as factory, patch("builtins.print") as display:
            with self.assertRaises(web.LoginWebError) as result:
                web.serve_login(backend, open_browser=False)
            self.assertEqual(result.exception.code, "preflight_failed")
            self.assertNotIn(BACKEND_SECRET, str(result.exception))
            factory.assert_not_called()
            display.assert_not_called()


if __name__ == "__main__":
    unittest.main()
