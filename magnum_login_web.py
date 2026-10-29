"""One-shot loopback login page; no account credentials are logged or returned.

The caller holds its authentication mutation lock for the entire call. A backend
provides preflight(), request_sms(phone), and verify_sms(phone, code). The last
method saves the session and returns safe auth_status metadata. This module does
not import the authentication client and never handles access/refresh tokens.
"""

from __future__ import annotations

import hmac
import html
import json
import math
import re
import secrets
import socket
import sys
import threading
import time
import urllib.parse
import webbrowser
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, HTTPServer


MAX_BODY_BYTES = 4096
MAX_CODE_ATTEMPTS = 3
_COOKIE = "magnum_login_session"
_BACKEND_ERROR_CODES = frozenset({
    "invalid_phone", "invalid_sms_code", "flow_not_ready", "sms_already_requested",
    "verification_limit", "vault_unavailable", "vault_read_failed", "vault_preflight_failed",
    "vault_write_failed", "request_failed", "invalid_response", "internal_error",
})
_SERVICE_ERROR_REASONS = frozenset({"sms_code_invalid", "expired", "rate_limited", "phone_format", "authorization_header", "unknown"})
_VALIDATION_FIELDS = frozenset({"phone", "pin", "smsCode", "token", "refreshToken", "deviceId", "appVersion"})
_ERRORS = {
    "invalid_settings": "Invalid local login settings.",
    "preflight_failed": "Secure local session storage is unavailable; no SMS was requested.",
    "listen_failed": "The loopback login page could not be started.",
    "ready_callback_failed": "The local login page address could not be displayed.",
    "login_timeout": "The local login page expired; start a new login explicitly.",
    "sms_request_failed": "The SMS request could not be confirmed. No automatic retry was made.",
    "code_attempts_exhausted": "The local verification attempt limit was reached.",
    "login_failed": "The local login did not complete.",
}


class LoginWebError(RuntimeError):
    """A fixed error message without request bodies or backend exception text."""

    def __init__(self, code):
        self.code = code if code in _ERRORS else "login_failed"
        super().__init__(_ERRORS[self.code])


def _log_backend_failure(stage, error):
    """Emit only allowlisted diagnostic metadata, never exception text or inputs."""
    try:
        code = getattr(error, "code", None)
        event = {
            "event": "login_backend_failure",
            "stage": stage if stage in ("send", "verify") else "unknown",
            "code": code if code in _BACKEND_ERROR_CODES else "backend_error",
        }
        status = getattr(error, "http_status", None)
        if type(status) is int and 100 <= status <= 599:
            event["http_status"] = status
        service_code = getattr(error, "service_error_code", None)
        if type(service_code) is int and -(2**31) <= service_code < 2**31:
            event["service_error_code"] = service_code
        fields = getattr(error, "validation_fields", ())
        if isinstance(fields, (list, tuple)):
            fields = sorted({field for field in fields if isinstance(field, str) and field in _VALIDATION_FIELDS})
            if fields:
                event["validation_fields"] = fields
        reason = getattr(error, "reason", None)
        if isinstance(reason, str) and reason in _SERVICE_ERROR_REASONS:
            event["reason"] = reason
        print(json.dumps(event, separators=(",", ":")), file=sys.stderr, flush=True)
    except Exception:
        pass


def _safe_status(value):
    if not isinstance(value, dict) or not (
        value.get("ready_user") is True
        and value.get("kind") == "user"
        and value.get("needs_login") is False
    ):
        return None
    expiry = value.get("expires_at")
    if not isinstance(expiry, str) or not re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z", expiry
    ):
        expiry = None
    backend = value.get("backend")
    if backend != "linux_systemd_credentials":
        backend = None
    return {
        "local_session_present": True, "kind": "user", "expires_at": expiry,
        "needs_login": False, "server_validation": "not_checked", "backend": backend,
        "ready_user": True, "state": "ready_user",
    }


class _LoginServer(HTTPServer):
    allow_reuse_address = False

    def __init__(self, backend, port, timeout):
        self.backend = backend
        self.deadline = None if timeout is None else time.monotonic() + timeout
        self.bootstrap = "/start/" + secrets.token_urlsafe(32)
        self.session = secrets.token_urlsafe(32)
        self.csrf = secrets.token_urlsafe(32)
        self.style_nonce = secrets.token_urlsafe(24)
        self.bootstrap_used = False
        self.send_attempted = False
        self.code_attempts = 0
        self.phone = None
        self.notice = None
        self.error_details = ""
        self.finished = False
        self.failure = None
        self.result = None
        super().__init__(("127.0.0.1", port), _LoginHandler)
        self.timeout = 0.2
        self.host = "127.0.0.1:{}".format(self.server_address[1])
        self.origin = "http://" + self.host
        self.login_url = self.origin + self.bootstrap

    def get_request(self):
        connection, address = super().get_request()
        remaining = 5.0 if self.deadline is None else max(0.1, self.deadline - time.monotonic())
        connection.settimeout(min(5.0, remaining))
        return connection, address

    def expired(self):
        return self.deadline is not None and time.monotonic() >= self.deadline

    def handle_error(self, request, client_address):
        # HTTPServer normally prints a traceback, which could retain form data.
        pass

    def run(self):
        while not self.finished and not self.expired():
            self.handle_request()
        if self.result is not None:
            return self.result
        raise LoginWebError(self.failure or "login_timeout")

    def server_close(self):
        self.phone = None
        self.session = self.csrf = self.bootstrap = ""
        super().server_close()


class _LoginHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def setup(self):
        super().setup()
        # A per-read socket timeout alone can be kept alive by trickling bytes.
        # Bound the complete header/body read without timing out an upstream call.
        remaining = (5.0 if self.server.deadline is None else
                     max(0.01, self.server.deadline - time.monotonic()))
        self._read_timer = threading.Timer(min(5.0, remaining), self._abort_read)
        self._read_timer.daemon = True
        self._read_timer.start()

    def _abort_read(self):
        try:
            self.connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    def finish(self):
        try:
            super().finish()
        finally:
            self._read_timer.cancel()

    def log_message(self, format, *args):
        pass

    def version_string(self):
        return "Local Login"

    def _respond(self, code, body="", *, location=None, cookie=False):
        self._read_timer.cancel()
        content = body.encode("utf-8")
        self.close_connection = True
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Connection", "close")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Pragma", "no-cache")
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; style-src 'nonce-{}'; form-action 'self'; "
            "base-uri 'none'; frame-ancestors 'none'".format(self.server.style_nonce),
        )
        if location is not None:
            self.send_header("Location", location)
        if cookie:
            lifetime = ("" if self.server.deadline is None else "; Max-Age={}".format(
                max(1, int(self.server.deadline - time.monotonic()))))
            self.send_header(
                "Set-Cookie", "{}={}; Path=/; HttpOnly; SameSite=Strict{}".format(
                    _COOKIE, self.server.session, lifetime,
                ),
            )
        self.end_headers()
        if content:
            self.wfile.write(content)
            self.wfile.flush()

    def _page(self, heading, message="", form=""):
        # All text comes from fixed application messages, never a backend reply.
        return """<!doctype html><html lang="ru"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Вход в Magnum Go</title><style nonce="{}">
body{{font:17px system-ui,sans-serif;background:#f5f6f8;color:#20262d;margin:0;padding:24px}}
main{{max-width:440px;margin:8vh auto;background:white;padding:30px;border-radius:18px}}
h1{{font-size:27px;margin:0 0 18px}}p{{line-height:1.5}}label{{display:block;margin:20px 0 8px}}
input{{box-sizing:border-box;width:100%;font:inherit;padding:12px;border:1px solid #a6afb9;border-radius:8px}}
button{{font:inherit;padding:12px 20px;margin-top:18px;border:0;border-radius:8px;background:#b10e50;color:white;cursor:pointer}}
pre{{white-space:pre-wrap;overflow-wrap:anywhere;font-size:13px;background:#f5f6f8;padding:12px;border-radius:8px}}
</style><main><h1>{}</h1><p>{}</p>{}</main></html>""".format(
            self.server.style_nonce, html.escape(heading), html.escape(message), form
        )

    def send_error(self, code, message=None, explain=None):
        self._respond(code, self._page("Запрос отклонён", "Откройте ссылку, выданную при запуске входа."))

    @staticmethod
    def _error_details(error):
        # Only transport-redacted text may reach this local page. Never use str(error).
        body = getattr(error, "redacted_response_body", None)
        if not isinstance(body, str) or not body:
            return ""
        return '<details open><summary>Полный ответ Magnum (секреты скрыты)</summary><pre>{}</pre></details>'.format(
            html.escape(body[:65536])
        )

    def _guard(self, *, post=False):
        if self.server.expired() or self.server.finished:
            self._respond(410, self._page("Время входа истекло", "Запустите вход заново."))
            return False
        hosts = self.headers.get_all("Host", [])
        if hosts != [self.server.host]:
            self._respond(403, self._page("Запрос отклонён"))
            return False
        if post and self.headers.get_all("Origin", []) != [self.server.origin]:
            self._respond(403, self._page("Запрос отклонён"))
            return False
        return True

    def _has_session(self):
        values = self.headers.get_all("Cookie", [])
        if len(values) != 1 or len(values[0]) > MAX_BODY_BYTES:
            return False
        try:
            cookie = SimpleCookie()
            cookie.load(values[0])
            value = cookie[_COOKIE].value
            return value.isascii() and hmac.compare_digest(value, self.server.session)
        except Exception:
            return False

    def _path(self):
        try:
            parsed = urllib.parse.urlsplit(self.path)
            if parsed.scheme or parsed.netloc or parsed.query or parsed.fragment:
                return None
            return parsed.path
        except ValueError:
            return None

    def do_GET(self):
        self._read_timer.cancel()
        if not self._guard():
            return
        path = self._path()
        if path == self.server.bootstrap and not self.server.bootstrap_used:
            self.server.bootstrap_used = True
            self._respond(303, location="/login", cookie=True)
            return
        if path != "/login" or not self._has_session():
            self._respond(403, self._page("Доступ к входу закрыт", "Используйте одноразовую ссылку из терминала."))
            return
        csrf = '<input type="hidden" name="csrf" value="{}">'.format(self.server.csrf)
        if not self.server.send_attempted:
            form = '<form method="post" action="/send">{}<label for="phone">Номер телефона</label><input id="phone" name="phone" type="tel" inputmode="tel" autocomplete="tel" maxlength="64" placeholder="+7XXXXXXXXXX" required><button type="submit">Получить SMS-код</button></form>'.format(csrf)
            self._respond(200, self._page("Вход в Magnum Go", self.server.notice or "Введите номер, чтобы запросить один SMS-код.", form))
        else:
            form = '<form method="post" action="/verify">{}<label for="code">Код из SMS</label><input id="code" name="smsCode" type="password" inputmode="numeric" autocomplete="one-time-code" maxlength="128" required><button type="submit">Подтвердить вход</button></form>'.format(csrf)
            self._respond(200, self._page("Введите SMS-код", self.server.notice or "Код запрошен. Автоматической повторной отправки нет.", self.server.error_details + form))

    def _form(self, required):
        if not self._has_session():
            return None
        if self.headers.get_all("Transfer-Encoding"):
            return None
        lengths = self.headers.get_all("Content-Length", [])
        if len(lengths) != 1 or not re.fullmatch(r"[0-9]{1,5}", lengths[0]):
            return None
        length = int(lengths[0])
        if not 0 < length <= MAX_BODY_BYTES:
            return None
        content_type = self.headers.get_all("Content-Type", [])
        if len(content_type) != 1 or content_type[0].split(";", 1)[0].strip().lower() != "application/x-www-form-urlencoded":
            return None
        try:
            raw = self.rfile.read(length)
            if len(raw) != length:
                return None
            values = urllib.parse.parse_qs(
                raw.decode("utf-8"), keep_blank_values=True, strict_parsing=True,
                encoding="utf-8", errors="strict", max_num_fields=4,
            )
            if set(values) != required or any(len(value) != 1 for value in values.values()):
                return None
            form = {key: value[0] for key, value in values.items()}
            if not form["csrf"].isascii() or not hmac.compare_digest(form["csrf"], self.server.csrf):
                return None
            return form
        except (ValueError, UnicodeError, OSError):
            return None

    def do_POST(self):
        if not self._guard(post=True):
            return
        path = self._path()
        fields = {"csrf", "phone"} if path == "/send" else {"csrf", "smsCode"}
        if path not in ("/send", "/verify"):
            self._respond(404, self._page("Запрос отклонён"))
            return
        form = self._form(fields)
        self._read_timer.cancel()
        if form is None:
            self._respond(403, self._page("Запрос отклонён"))
            return
        if self.server.expired():
            self.server.failure = "login_timeout"
            self.server.finished = True
            self._respond(410, self._page("Время входа истекло", "Запустите вход заново."))
            return
        if path == "/send":
            if self.server.send_attempted:
                self._respond(409, self._page("Код уже запрошен", "Повторная отправка отключена."))
                return
            phone = re.sub(r"[ ()\-]", "", form["phone"].strip())
            if not re.fullmatch(r"\+7[0-9]{10}", phone):
                self.server.notice = "Введите номер в формате +7 и 10 цифр."
                self._respond(303, location="/login")
                return
            self.server.send_attempted = True
            self.server.phone = phone
            try:
                self.server.backend.request_sms(phone)
            except Exception as error:
                _log_backend_failure("send", error)
                self.server.failure = "sms_request_failed"
                self.server.finished = True
                self._respond(503, self._page("Отправку не удалось подтвердить", "Автоповтора нет. Ниже — ответ сервиса для диагностики.", self._error_details(error)))
                return
            self.server.notice = None
            self._respond(303, location="/login")
            return
        if not self.server.send_attempted or self.server.phone is None:
            self._respond(409, self._page("Сначала запросите SMS-код"))
            return
        if self.server.code_attempts >= MAX_CODE_ATTEMPTS:
            self._respond(429, self._page("Попытки подтверждения закончились"))
            return
        code = form["smsCode"].strip()
        if not re.fullmatch(r"[0-9]{1,128}", code):
            self.server.notice = "Код должен содержать только цифры."
            self._respond(303, location="/login")
            return
        self.server.code_attempts += 1
        try:
            result = _safe_status(self.server.backend.verify_sms(self.server.phone, code))
        except Exception as error:
            _log_backend_failure("verify", error)
            self.server.error_details = self._error_details(error)
            if getattr(error, "reason", None) != "sms_code_invalid":
                error_code = getattr(error, "code", None)
                reason = getattr(error, "reason", None)
                if error_code == "invalid_response":
                    message = "Magnum вернул неожиданный ответ. Нужно проверить формат ответа клиента; повторять SMS-код сейчас не следует."
                elif error_code == "vault_write_failed":
                    message = "Сессия получена, но её не удалось сохранить. Нужно проверить хранилище; повторять SMS-код сейчас не следует."
                elif reason == "expired":
                    message = "Magnum сообщил, что срок подтверждения истёк. Потребуется новый вход."
                elif reason == "rate_limited":
                    message = "Magnum ограничил попытки входа. Автоматических повторов не будет."
                else:
                    message = "Не удалось подтвердить вход у Magnum. Требуется проверить ответ API; повторять SMS-код сейчас не следует."
                status = getattr(error, "http_status", None)
                service_code = getattr(error, "service_error_code", None)
                if type(status) is int and 100 <= status <= 599:
                    message += " HTTP {}.".format(status)
                if type(service_code) is int and -(2**31) <= service_code < 2**31:
                    message += " Код сервиса: {}.".format(service_code)
                self.server.failure = "login_failed"
                self.server.finished = True
                self._respond(502, self._page("Не удалось завершить вход", message, self.server.error_details))
                return
            result = None
        if result is not None:
            self.server.result = result
            self.server.finished = True
            self.server.phone = None
            self._respond(200, self._page("Вход выполнен", "Сессия сохранена в защищённом локальном хранилище. Эту вкладку можно закрыть."))
        elif self.server.code_attempts >= MAX_CODE_ATTEMPTS:
            self.server.failure = "code_attempts_exhausted"
            self.server.finished = True
            self._respond(429, self._page("Попытки подтверждения закончились", "Автоматических повторов не было. При необходимости запустите новый вход вручную."))
        else:
            self.server.notice = "Вход не подтверждён. Проверьте код; осталось попыток: {}.".format(MAX_CODE_ATTEMPTS - self.server.code_attempts)
            self._respond(303, location="/login")


def serve_login(backend, *, port=0, timeout=None, open_browser=True, on_ready=None):
    """Serve one login with no total expiry by default; return safe metadata.

    on_ready(url: str) receives the random, single-use bootstrap URL. The caller
    must not log HTTP requests or proxy their bodies. No SMS is requested until
    the user submits the browser form. Binding is always IPv4 loopback.
    A positive finite timeout may be set explicitly for administration or tests.
    """
    if (type(port) is not int or not 0 <= port <= 65535 or
            (timeout is not None and (type(timeout) not in (int, float) or
                                     not math.isfinite(timeout) or timeout <= 0))):
        raise LoginWebError("invalid_settings")
    try:
        backend.preflight()
    except Exception:
        raise LoginWebError("preflight_failed") from None
    try:
        server = _LoginServer(backend, port, timeout)
    except Exception:
        raise LoginWebError("listen_failed") from None
    try:
        try:
            if on_ready is None:
                print(server.login_url, flush=True)
            else:
                on_ready(server.login_url)
        except Exception:
            raise LoginWebError("ready_callback_failed") from None
        if open_browser:
            try:
                webbrowser.open(server.login_url, new=1)
            except Exception:
                # The displayed bootstrap URL remains usable without an opener.
                pass
        return server.run()
    finally:
        server.server_close()


__all__ = ["serve_login", "LoginWebError"]
