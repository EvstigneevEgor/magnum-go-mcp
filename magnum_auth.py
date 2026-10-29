#!/usr/bin/env python3
"""Local MagnumGO SMS login and OS-backed session access.

``python magnum_auth.py login`` opens a single-use loopback login page.
On a server use ``login --no-open --port 8765`` with an SSH tunnel. Phone and
SMS code enter only through this protected local page, or getpass with
``login --terminal``. They never enter CLI arguments, environment variables,
pipes, MCP arguments, or logs. One SMS is requested; verification is manual.

``status`` checks local storage only; it does not verify server authentication.
``logout`` removes the local record only. Refresh is an explicit operation in
magnum_client.py; a rejected refresh requires a new local login. Unexpected
response schemas fail closed.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import getpass
import json
import os
import re
import stat
import sys
import time
import uuid
import warnings
from datetime import datetime, timezone

from magnum_api import BASE_URL, CLIENT_VERSION, MAX_RESPONSE_BYTES, MagnumAPIError, _http_request
from magnum_vault import SecretStore, SessionRecord, VaultError


_AUTH_PATHS = {
    "first": "/auth/server/api/v1/security/customers/registration/move/first",
    "second": "/auth/server/api/v1/security/customers/registration/move/second",
    "guest": "/auth/server/api/v1/security/guest/login",
}
# Extracted from MagnumGO 4.3.15 AuthApi's ARM64 map construction:
# 0x8bb9d4..0x8bb9e8 loads the protocol field pin and constant string "0123".
# This is an app protocol constant, not an additional PIN requested from a user.
_APP_LOGIN_PIN = "0123"
_AUTH_FIELDS = {"first": {"phone"}, "second": {"phone", "pin", "smsCode"}, "guest": set()}
_MESSAGES = {
    "invalid_arguments": "Invalid arguments. Use --help; secrets are accepted only by local prompts.",
    "local_terminal_required": "Run login yourself in a local terminal with interactive input and output.",
    "secure_prompt_unavailable": "A prompt with echo disabled is unavailable; login was stopped.",
    "invalid_phone": "Phone must have the form +7 followed by exactly 10 digits.",
    "invalid_sms_code": "SMS code must contain digits; leading zeroes are preserved.",
    "flow_not_ready": "The local login flow is not ready for this operation.",
    "sms_already_requested": "This login flow has already requested its one SMS.",
    "verification_limit": "The verification attempt limit was reached. Start a new local login.",
    "browser_login_failed": "The local login page stopped without completing login.",
    "login_page_unavailable": "The loopback login page could not start. Close another login or choose another --port.",
    "login_timeout": "The local login page expired. Start a new local login.",
    "cancelled": "Login was cancelled.",
    "vault_unavailable": "The OS credential store is unavailable; no SMS was requested.",
    "vault_read_failed": "The local session could not be read securely; no SMS was requested.",
    "vault_preflight_failed": "The OS credential store write check failed; no SMS was requested.",
    "vault_write_failed": "The session could not be saved securely. Login was not completed locally.",
    "vault_delete_failed": "The local session could not be removed securely.",
    "request_failed": "Authentication request failed. No automatic retry was made.",
    "invalid_response": "Authentication response has an unexpected format; no session was saved.",
    "needs_login": "A local user login is required. Run python magnum_auth.py login yourself.",
    "session_expired": "The local session has expired. Log in locally again; automatic refresh is disabled.",
    "guest_only": "The saved session is a guest. A local user login is required.",
    "guest_would_replace_user": "A user session is already saved. Run logout before guest-login.",
    "auth_busy": "Another local authentication operation is in progress.",
    "auth_lock_unavailable": "Local authentication lock is unavailable. Linux requires an owned mode-0700 /run/user/<uid> directory; start the user manager and retry.",
    "internal_error": "The local authentication operation failed; no diagnostic secrets were displayed.",
}


class AuthError(RuntimeError):
    """A sanitized error with a stable machine-readable code."""

    def __init__(self, code: str, *, reason: str | None = None):
        self.code = code if code in _MESSAGES else "internal_error"
        self.reason = reason if reason in {"expired", "missing", "guest"} else None
        super().__init__(_MESSAGES[self.code])


@contextlib.contextmanager
def _mutation_lock():
    """Serialize local CLI mutations. The POSIX lock file contains no secrets."""
    if sys.platform == "win32":
        handle = None
        acquired = False
        try:
            import ctypes
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.CreateMutexW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_wchar_p]
            kernel32.CreateMutexW.restype = ctypes.c_void_p
            kernel32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
            kernel32.WaitForSingleObject.restype = ctypes.c_uint32
            kernel32.ReleaseMutex.argtypes = [ctypes.c_void_p]
            kernel32.ReleaseMutex.restype = ctypes.c_int
            kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
            kernel32.CloseHandle.restype = ctypes.c_int
            handle = kernel32.CreateMutexW(None, False, "Local\\MagnumGoMCP-v1-auth-mutation")
            if not handle:
                raise AuthError("auth_lock_unavailable")
            result = kernel32.WaitForSingleObject(handle, 0)
            if result == 258:
                raise AuthError("auth_busy")
            if result not in (0, 128):  # acquired or acquired after abandoned owner
                raise AuthError("auth_lock_unavailable")
            acquired = True
        except AuthError:
            if handle:
                kernel32.CloseHandle(handle)
            raise
        except Exception:
            if handle:
                kernel32.CloseHandle(handle)
            raise AuthError("auth_lock_unavailable") from None
        try:
            yield
        finally:
            if acquired:
                kernel32.ReleaseMutex(handle)
            kernel32.CloseHandle(handle)
        return

    descriptor = None
    try:
        import fcntl
        uid = os.getuid()
        runtime_path = "/run/user/{}".format(uid)
        runtime_metadata = os.lstat(runtime_path)  # lstat rejects a symlink below.
        if (not stat.S_ISDIR(runtime_metadata.st_mode) or runtime_metadata.st_uid != uid
                or stat.S_IMODE(runtime_metadata.st_mode) != 0o700):
            raise AuthError("auth_lock_unavailable")
        lock_path = os.path.join(runtime_path, "magnumgo-auth.lock")
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(lock_path, flags, 0o600)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != uid or metadata.st_mode & 0o077:
            raise AuthError("auth_lock_unavailable")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise AuthError("auth_busy") from None
    except AuthError:
        if descriptor is not None:
            os.close(descriptor)
        raise
    except Exception:
        if descriptor is not None:
            os.close(descriptor)
        raise AuthError("auth_lock_unavailable") from None
    try:
        yield
    finally:
        # Do not unlink: a waiter could still hold the existing inode.
        os.close(descriptor)


def _check_store(store):
    try:
        availability = store.check()
        if not availability.available:
            raise AuthError("vault_unavailable")
        return availability
    except AuthError:
        raise
    except Exception:
        raise AuthError("vault_unavailable") from None


def _read_store(store):
    try:
        return store.read()
    except Exception:
        raise AuthError("vault_read_failed") from None


def _preflight_store(store):
    """Check real access before an SMS, without replacing the session record."""
    _check_store(store)
    existing = _read_store(store)
    probe = None
    wrote = False
    failure = False
    marker = "preflight-not-a-session-" + uuid.uuid4().hex
    try:
        probe = SecretStore(target="MagnumGoMCP/v1/preflight/" + uuid.uuid4().hex)
        _check_store(probe)
        probe.write(SessionRecord(token=marker, kind="guest", expires_at=int(time.time()) + 60))
        wrote = True
        saved = probe.read()
        if saved is None or saved.token != marker or saved.kind != "guest":
            failure = True
    except Exception:
        failure = True
    finally:
        if probe is not None and wrote:
            try:
                if not probe.delete():
                    failure = True
            except Exception:
                failure = True
    if failure:
        raise AuthError("vault_preflight_failed") from None
    return existing


def _require_local_tty():
    try:
        if not sys.stdin.isatty() or not sys.stderr.isatty():
            raise AuthError("local_terminal_required")
        # isatty alone can describe a pipe-like emulation on Windows. Require
        # actual Console handles for the console-specific no-echo prompt.
        if sys.platform == "win32":
            import ctypes
            import msvcrt
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.GetConsoleMode.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
            kernel32.GetConsoleMode.restype = ctypes.c_int
            for stream in (sys.stdin, sys.stderr):
                mode = ctypes.c_uint32()
                handle = msvcrt.get_osfhandle(stream.fileno())
                if not kernel32.GetConsoleMode(ctypes.c_void_p(handle), ctypes.byref(mode)):
                    raise AuthError("local_terminal_required")
        else:
            import termios
            termios.tcgetattr(sys.stdin.fileno())
    except AuthError:
        raise
    except Exception:
        raise AuthError("local_terminal_required") from None


def _secure_prompt(prompt):
    _require_local_tty()
    try:
        with warnings.catch_warnings():
            # getpass normally falls back to echoed stdin when disabling echo
            # fails. Converting this warning to an error prevents the fallback.
            warnings.simplefilter("error", getpass.GetPassWarning)
            return getpass.getpass(prompt, stream=sys.stderr)
    except (EOFError, KeyboardInterrupt):
        raise AuthError("cancelled") from None
    except Exception:
        raise AuthError("secure_prompt_unavailable") from None


def _log_auth_response_shape(step, raw):
    """Report only response schema, without any scalar value or nested content."""
    if step != "first":
        return
    try:
        event = {"event": "auth_response_shape", "step": "first"}
        if not raw:
            event["json_type"] = "empty"
        elif not isinstance(raw, bytes) or len(raw) > 16 * 1024:
            event["json_type"] = "uninspected"
        else:
            try:
                value = json.loads(raw.decode("utf-8-sig"))
            except Exception:
                event["json_type"] = "non_json"
            else:
                def kind(item):
                    if item is None:
                        return "null"
                    return {dict: "object", list: "array", str: "string", bool: "boolean",
                            int: "number", float: "number"}.get(type(item), "unknown")
                event["json_type"] = kind(value)
                if isinstance(value, dict):
                    keys = sorted(key for key in value if isinstance(key, str) and
                                  re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,63}", key))[:30]
                    event["keys"] = keys
                    event["field_types"] = {key: kind(value[key]) for key in keys}
        print(json.dumps(event, separators=(",", ":")), file=sys.stderr, flush=True)
    except Exception:
        pass


def _post_auth(step, payload, *, parse_json=True):
    if step not in _AUTH_PATHS or set(payload) != _AUTH_FIELDS[step]:
        raise AuthError("invalid_response")
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "X-Client-Version": CLIENT_VERSION,
    }
    # These endpoints explicitly reject an Authorization header. All secrets
    # stay in the request body; Windows curl receives its configuration on stdin.
    body = json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    try:
        raw = _http_request("POST", BASE_URL + _AUTH_PATHS[step], headers, body)
    except MagnumAPIError as error:
        # Transport exposes only allowlisted metadata, never the upstream body.
        failure = AuthError("request_failed")
        metadata = error.safe_metadata()
        status = metadata.get("http_status")
        if status is None:
            # Keep compatibility with injected/synthetic legacy transport errors.
            match = re.fullmatch(r"HTTP ([1-5][0-9]{2})\.", str(error))
            status = int(match.group(1)) if match else None
        if status is not None:
            failure.http_status = status
        if "service_error_code" in metadata:
            failure.service_error_code = metadata["service_error_code"]
        if "validation_fields" in metadata:
            failure.validation_fields = metadata["validation_fields"]
        failure.reason = metadata["reason"]
        # Only the local landing may display this context-redacted body.
        # It is intentionally absent from exception messages and diagnostics.
        failure.redacted_response_body = error.redacted_response_body
        raise failure from None
    except Exception:
        raise AuthError("request_failed") from None
    if not parse_json:
        _log_auth_response_shape(step, raw)
        return None
    if not isinstance(raw, bytes) or len(raw) > MAX_RESPONSE_BYTES:
        raise AuthError("invalid_response")
    try:
        result = json.loads(raw.decode("utf-8-sig"))
    except Exception:
        raise AuthError("invalid_response") from None
    return result


def _expiry_hint(token):
    """Decode only exp as a scheduling hint. This DOES NOT verify the JWT."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        segment = parts[1]
        decoded = base64.b64decode(segment + "=" * (-len(segment) % 4), altchars=b"-_", validate=True)
        claims = json.loads(decoded.decode("utf-8"))
        expiry = claims.get("exp") if isinstance(claims, dict) else None
        return expiry if type(expiry) is int and 0 < expiry <= 253402300799 else None
    except Exception:
        return None


def _normalize_token(value):
    # The observed guest response prefixes both tokens with exactly "Bearer ".
    # Store only the token, accepting neither repeated prefixes nor whitespace.
    if not isinstance(value, str):
        raise AuthError("invalid_response")
    if value.startswith("Bearer "):
        value = value[len("Bearer "):]
    if not 16 <= len(value) <= 4096 or value.isdecimal() or not re.fullmatch(r"[A-Za-z0-9._~+/-]+=*", value):
        raise AuthError("invalid_response")
    return value


def _session_record(response, kind):
    if not isinstance(response, dict):
        raise AuthError("invalid_response")
    token = _normalize_token(response.get("token"))
    refresh_token = _normalize_token(response.get("refreshToken"))
    try:
        return SessionRecord(
            token=token, refresh_token=refresh_token, kind=kind, expires_at=_expiry_hint(token)
        )
    except VaultError:
        raise AuthError("invalid_response") from None


def _save_session(store, response, kind):
    record = _session_record(response, kind)
    try:
        store.write(record)
    except Exception:
        raise AuthError("vault_write_failed") from None


def _normalize_phone(value):
    if not isinstance(value, str) or len(value) > 64:
        raise AuthError("invalid_phone")
    phone = re.sub(r"[ ()-]", "", value.strip())
    if not re.fullmatch(r"\+7[0-9]{10}", phone):
        raise AuthError("invalid_phone")
    return phone


def _normalize_sms_code(value):
    if not isinstance(value, str):
        raise AuthError("invalid_sms_code")
    code = value.strip()
    if not re.fullmatch(r"[0-9]{1,128}", code):
        raise AuthError("invalid_sms_code")
    return code


class LoginFlow:
    """Callbacks for a local login UI; caller holds the mutation lock throughout.

    Only these methods receive secrets in memory. Do not expose them as MCP
    tools. The phone is pinned to the one SMS request, and verification requires
    an explicit user submission each time (at most three submissions).
    """

    def __init__(self, store=None):
        self.store = store if store is not None else SecretStore()
        self._prepared = False
        self._requested = False
        self._completed = False
        self._attempts = 0
        self._phone = None

    def __repr__(self):
        return "LoginFlow(secrets=<redacted>)"

    def preflight(self):
        if self._requested or self._completed:
            raise AuthError("flow_not_ready")
        if not self._prepared:
            _preflight_store(self.store)
            self._prepared = True

    def request_sms(self, phone):
        if not self._prepared or self._completed:
            raise AuthError("flow_not_ready")
        if self._requested:
            raise AuthError("sms_already_requested")
        self._phone = _normalize_phone(phone)
        self._requested = True  # Failure or timeout never causes an SMS retry.
        # The UI accepts E.164, while Magnum's DTO requires 11 digits, no '+'.
        _post_auth("first", {"phone": self._phone[1:]}, parse_json=False)

    def verify_sms(self, phone, code):
        if not self._prepared or not self._requested or self._completed:
            raise AuthError("flow_not_ready")
        if self._attempts >= 3:
            raise AuthError("verification_limit")
        self._attempts += 1
        if _normalize_phone(phone) != self._phone:
            raise AuthError("invalid_phone")
        code = _normalize_sms_code(code)
        response = _post_auth("second", {"phone": self._phone[1:], "pin": _APP_LOGIN_PIN, "smsCode": code})
        record = _session_record(response, "user")
        if record.expires_at is not None and record.expires_at <= time.time():
            raise AuthError("invalid_response")
        try:
            self.store.write(record)
        except Exception:
            raise AuthError("vault_write_failed") from None
        self._completed = True
        self._phone = None
        return auth_status(self.store)

    def close(self):
        # Python strings cannot be reliably zeroized; do not retain extra copies.
        self._phone = None
        self._completed = True


def _interactive_login(store):
    _require_local_tty()
    flow = LoginFlow(store)
    phone = code = None
    try:
        flow.preflight()
        phone = _secure_prompt("Phone (+7XXXXXXXXXX, hidden): ")
        flow.request_sms(phone)
        code = _secure_prompt("SMS code (hidden): ")
        return flow.verify_sms(phone, code)
    finally:
        flow.close()
        phone = code = None


def _browser_login(store, *, port=8765, open_browser=True):
    from magnum_login_web import LoginWebError, serve_login
    flow = LoginFlow(store)
    def on_ready(url):
        # Only a one-use local bootstrap URL is emitted, never phone/OTP/tokens.
        print(json.dumps({"login_url": url}, separators=(",", ":")), flush=True)
    try:
        return serve_login(flow, port=port, timeout=None, open_browser=open_browser, on_ready=on_ready)
    except LoginWebError as error:
        code = {
            "timeout": "login_timeout",
            "login_timeout": "login_timeout",
            "preflight_failed": "vault_preflight_failed",
            "listen_failed": "login_page_unavailable",
            "sms_request_failed": "request_failed",
            "code_attempts_exhausted": "verification_limit",
        }.get(error.code, "browser_login_failed")
        raise AuthError(code) from None
    finally:
        flow.close()


def _guest_login(store):
    _check_store(store)
    existing = _read_store(store)
    if existing is not None and existing.kind == "user":
        raise AuthError("guest_would_replace_user")
    _preflight_store(store)
    response = _post_auth("guest", {})
    # Recheck after the network call in case another credential writer ran.
    latest = _read_store(store)
    if latest is not None and latest.kind == "user":
        raise AuthError("guest_would_replace_user")
    _save_session(store, response, "guest")
    return auth_status(store)


def _utc_timestamp(value):
    if value is None:
        return None
    try:
        return datetime.fromtimestamp(value, timezone.utc).isoformat().replace("+00:00", "Z")
    except (ValueError, OverflowError, OSError):
        return None


def auth_status(store=None):
    """Return safe local metadata, without a request or server-authentication claim."""
    store = store if store is not None else SecretStore()
    status = {
        "local_session_present": False,
        "kind": None,
        "expires_at": None,
        "needs_login": True,
        "server_validation": "not_checked",
        "backend": None,
        "ready_user": False,
        "state": "needs_login",
    }
    try:
        availability = _check_store(store)
        status["backend"] = availability.backend
        record = _read_store(store)
    except AuthError as error:
        status["state"] = "vault_unavailable"
        status["reason"] = error.code
        return status
    if record is None:
        return status
    status["local_session_present"] = True
    status["kind"] = record.kind
    status["expires_at"] = _utc_timestamp(record.expires_at)
    if record.expires_at is not None and record.expires_at <= time.time():
        status["reason"] = "expired"
    elif record.kind == "user":
        status.update(ready_user=True, needs_login=False, state="ready_user")
    else:
        status["state"] = "guest"
        status["reason"] = "guest"
    return status


class AuthSession:
    """Token provider for local callers; never performs login or refresh silently."""

    def __init__(self, store=None):
        self.store = store if store is not None else SecretStore()

    def __repr__(self):
        return "AuthSession(secrets=<OS credential store>)"

    def auth_status(self):
        return auth_status(self.store)

    def get_access_token(self, require_user=True):
        _check_store(self.store)
        record = _read_store(self.store)
        if record is None:
            raise AuthError("needs_login", reason="missing")
        if record.expires_at is not None and record.expires_at <= time.time():
            raise AuthError("session_expired", reason="expired")
        if require_user and record.kind != "user":
            raise AuthError("guest_only", reason="guest")
        return record.token


class _SafeParser(argparse.ArgumentParser):
    def error(self, message):
        # argparse's default error echoes unknown arguments, which could include
        # a user mistakenly supplying a phone/code/token on the command line.
        raise AuthError("invalid_arguments")


def _parser():
    parser = _SafeParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    login = commands.add_parser("login", help="Open a single-use local browser page for SMS login.")
    login.add_argument("--terminal", action="store_true", help="Use a local terminal's no-echo prompts instead.")
    login.add_argument("--no-open", action="store_true", help="Print the local browser URL without opening a browser.")
    login.add_argument("--port", type=_port, default=8765, help="Loopback port (default: 8765; 0 selects an unused port).")
    commands.add_parser("status", help="Show safe local session metadata without a network call.")
    commands.add_parser("logout", help="Delete the local session; no server revocation is performed.")
    commands.add_parser("guest-login", help="Save a guest session for testing; refuses to replace a user.")
    return parser


def _port(value):
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("Expected a port number.") from None
    if not 0 <= number <= 65535:
        raise argparse.ArgumentTypeError("Port is outside the allowed range.")
    return number


def main(argv=None):
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    try:
        arguments = _parser().parse_args(argv)
        store = SecretStore()
        if arguments.command == "status":
            result = auth_status(store)
        else:
            with _mutation_lock():
                if arguments.command == "login":
                    result = (_interactive_login(store) if arguments.terminal else
                              _browser_login(store, port=arguments.port, open_browser=not arguments.no_open))
                elif arguments.command == "guest-login":
                    result = _guest_login(store)
                else:
                    _check_store(store)
                    try:
                        removed = store.delete()
                    except Exception:
                        raise AuthError("vault_delete_failed") from None
                    result = {"local_session_deleted": removed, "server_revocation_performed": False}
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except AuthError as error:
        result = {"error": error.code, "message": str(error)}
        if getattr(error, "http_status", None) is not None:
            result["http_status"] = error.http_status
        print(json.dumps(result, ensure_ascii=False), file=sys.stderr)
        return 1
    except (EOFError, KeyboardInterrupt):
        print(json.dumps({"error": "cancelled", "message": _MESSAGES["cancelled"]}), file=sys.stderr)
        return 130
    except BrokenPipeError:
        return 1
    except Exception:
        print(json.dumps({"error": "internal_error", "message": _MESSAGES["internal_error"]}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
