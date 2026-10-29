#!/usr/bin/env python3
"""Small read-only MagnumGO API client using a fresh in-memory guest session.

Python 3.9+; standard library only. On Windows, curl.exe is preferred so HTTPS
uses the system certificate store. Certificate verification is always enabled.
No login token is written to disk or printed; the refresh token is discarded.

Examples:
  python magnum_api.py geo --latitude 43.238949 --longitude 76.889709
  python magnum_api.py categories --platform-id 5002
  python magnum_api.py suggest --platform-id 5002 --query "хлеб"
  python magnum_api.py demo --latitude 43.238949 --longitude 76.889709 --query "хлеб"

This module also supplies the shared transport. The authenticated client and
MCP tools are in magnum_client.py and magnum_mcp.py.
"""

import argparse
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import json
import math
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request


BASE_URL = "https://mgo-gw1.e-magnum.kz"
CLIENT_VERSION = "4.3.15"
TIMEOUT = 20
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_ERROR_BYTES = 64 * 1024
_VALIDATION_FIELDS = frozenset({"phone", "pin", "smsCode", "token", "refreshToken", "deviceId", "appVersion"})
_ERROR_REASONS = frozenset({"sms_code_invalid", "expired", "rate_limited", "phone_format", "authorization_header", "unknown"})
_SENSITIVE_KEYS = frozenset({
    "phone", "mobile", "cellphone", "phonenumber", "contactcellphone", "smscode", "otp",
    "verificationcode", "token", "accesstoken", "refreshtoken", "idtoken", "password", "passwd",
    "passphrase", "pin", "cookie", "setcookie", "authorization", "secret", "clientsecret", "apikey",
})
_STATUS_MARKER = b"\nMAGNUM_HTTP_STATUS:"
_ENDPOINTS = {
    "guest": ("POST", "/auth/server/api/v1/security/guest/login", ()),
    "geo": (
        "GET", "/productstore/geo/api/v1/type/all/attributes",
        ("latitude", "longitude"),
    ),
    "categories": ("GET", "/catalog/client/catalog", ("includeChildNodes", "parentId", "platformId")),
    "suggest": (
        "GET", "/catalog/client/search/lean/items",
        ("searchWord",),
    ),
}


class MagnumAPIError(Exception):
    """An error safe to display without response bodies or credentials."""

    def __init__(self, message, *, http_status=None, service_error_code=None,
                 validation_fields=(), reason="unknown", redacted_response_body=None,
                 retry_after_seconds=None):
        super().__init__(message)
        self.http_status = http_status if type(http_status) is int and 100 <= http_status <= 599 else None
        self.service_error_code = (service_error_code if type(service_error_code) is int and
                                   -(2**31) <= service_error_code < 2**31 else None)
        validation_fields = validation_fields if isinstance(validation_fields, (list, tuple)) else ()
        self.validation_fields = tuple(sorted({field for field in validation_fields
                                                if isinstance(field, str) and field in _VALIDATION_FIELDS}))
        self.reason = reason if isinstance(reason, str) and reason in _ERROR_REASONS else "unknown"
        # This is exclusively the local UI's already-redacted diagnostic body.
        # Exception args/repr and safe_metadata deliberately omit it.
        self.redacted_response_body = (redacted_response_body if isinstance(redacted_response_body, str) else None)
        self.retry_after_seconds = (float(retry_after_seconds) if type(retry_after_seconds) in (int, float)
                                    and math.isfinite(retry_after_seconds) and 0 <= retry_after_seconds <= 604800 else None)

    def safe_metadata(self):
        """Return only fixed categories, numeric codes and known field names."""
        result = {"reason": self.reason}
        if self.http_status is not None:
            result["http_status"] = self.http_status
        if self.service_error_code is not None:
            result["service_error_code"] = self.service_error_code
        if self.validation_fields:
            result["validation_fields"] = self.validation_fields
        if self.retry_after_seconds is not None:
            result["retry_after_seconds"] = self.retry_after_seconds
        return result


def _safe_error_metadata(data, status):
    """Classify a bounded reply in memory; never return or retain reply text."""
    result = {"reason": "rate_limited" if status == 429 else "unknown"}
    if not isinstance(data, bytes) or len(data) > MAX_ERROR_BYTES:
        return result
    try:
        payload = json.loads(data.decode("utf-8-sig"))
    except (ValueError, UnicodeError, RecursionError):
        return result
    if not isinstance(payload, dict):
        return result
    code = payload.get("errorCode")
    if type(code) is int and -(2**31) <= code < 2**31:
        result["service_error_code"] = code
    descriptions = [payload.get(key) for key in ("errorDescr", "message", "error")]
    text = " ".join(value for value in descriptions if isinstance(value, str)).lower()
    fields = {match.group(1) for match in re.finditer(r"(?:^|[,{;\s])([A-Za-z][A-Za-z0-9]*)\s*=", text)}
    # Preserve the API's exact camelCase field spelling without exposing values.
    fields = {field for field in _VALIDATION_FIELDS if field.lower() in fields}
    errors = payload.get("errors")
    if isinstance(errors, dict):
        fields.update(key for key in errors if key in _VALIDATION_FIELDS)
    if fields:
        result["validation_fields"] = tuple(sorted(fields))
    if status == 429 or any(word in text for word in ("too many", "rate limit", "слишком много", "превышен лимит", "попыток исчерпан", "заблокирован")):
        result["reason"] = "rate_limited"
    elif "authorization header specified" in text:
        result["reason"] = "authorization_header"
    elif any(word in text for word in ("expired", "истек", "истёк", "просроч")):
        result["reason"] = "expired"
    elif ("phone" in fields and any(word in text for word in ("должен начинаться", "без знака", "номер телефона", "phone must", "invalid phone"))):
        result["reason"] = "phone_format"
    elif any(word in text for word in ("неверный код", "неверный смс", "некорректный код", "invalid sms", "incorrect code", "invalid verification code", "wrong code")):
        result["reason"] = "sms_code_invalid"
    return result


def _sensitive_key(key):
    return isinstance(key, str) and re.sub(r"[^a-z0-9]", "", key.lower()) in _SENSITIVE_KEYS


def _redacted_error_body(data, request_headers=None, request_body=None):
    """Keep a bounded diagnostic for the local UI, masking request secrets first."""
    if not isinstance(data, bytes) or not data:
        return ""
    truncated = len(data) > MAX_ERROR_BYTES
    raw = data[:MAX_ERROR_BYTES]
    text = raw.decode("utf-8-sig", errors="replace")
    secrets = set()

    def collect(value, sensitive=False):
        if isinstance(value, dict):
            for key, item in value.items():
                collect(item, sensitive or _sensitive_key(key))
        elif isinstance(value, list):
            for item in value:
                collect(item, sensitive)
        elif sensitive and isinstance(value, (str, int, float)) and not isinstance(value, bool):
            scalar = str(value)
            if scalar:
                secrets.add(scalar)
                if scalar[:7].lower() == "bearer ":
                    secrets.add(scalar[7:])
                digits = re.sub(r"[ ()+-]", "", scalar)
                if re.fullmatch(r"7[0-9]{10}", digits):
                    secrets.update((digits, "+" + digits))

    if isinstance(request_headers, dict):
        for key, value in request_headers.items():
            if _sensitive_key(key):
                collect(value, True)
    if isinstance(request_body, bytes) and len(request_body) <= MAX_ERROR_BYTES:
        try:
            collect(json.loads(request_body.decode("utf-8-sig")))
        except (ValueError, UnicodeError, RecursionError):
            pass
    try:
        payload = json.loads(text)
    except (ValueError, RecursionError):
        payload = None
        valid_json = False
    else:
        valid_json = True
        collect(payload)

    def redact_string(value):
        for secret in sorted(secrets, key=len, reverse=True):
            if secret:
                value = value.replace(secret, "[REDACTED]")
        value = re.sub(r"(?i)\bBearer[ \t]+[A-Za-z0-9._~+/=-]+", "Bearer [REDACTED]", value)
        value = re.sub(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b", "[REDACTED]", value)
        value = re.sub(r"(?<![A-Za-z0-9])\+?7(?:[ ()-]*[0-9]){10}(?![0-9])", "[REDACTED]", value)
        return value

    def clean(value):
        if isinstance(value, dict):
            return {redact_string(key): ("[REDACTED]" if _sensitive_key(key) else clean(item))
                    for key, item in value.items()}
        if isinstance(value, list):
            return [clean(item) for item in value]
        if isinstance(value, str):
            return redact_string(value)
        if isinstance(value, (int, float)) and not isinstance(value, bool) and str(value) in secrets:
            return "[REDACTED]"
        return value

    if valid_json:
        rendered = json.dumps(clean(payload), ensure_ascii=False, indent=2)
    else:
        rendered = redact_string(text)
        # Also cover quoted sensitive fields in a truncated/non-JSON reply.
        field_names = "|".join(sorted(_SENSITIVE_KEYS, key=len, reverse=True))
        rendered = re.sub(
            r'(?i)(["\']?(?:' + field_names + r')["\']?\s*[:=]\s*)("[^"\r\n]*"|\'[^\'\r\n]*\'|[^\s,;}&<]+)',
            lambda match: match.group(1) + '"[REDACTED]"', rendered,
        )
    encoded = rendered.encode("utf-8")
    marker = b"\n[response truncated]"
    if truncated or len(encoded) > MAX_ERROR_BYTES:
        encoded = encoded[:MAX_ERROR_BYTES - len(marker)]
        rendered = encoded.decode("utf-8", errors="ignore") + marker.decode()
    return rendered


def _retry_after(value):
    if not isinstance(value, str) or len(value) > 128:
        return None
    try:
        if value.isascii() and value.isdecimal():
            seconds = int(value)
        else:
            when = parsedate_to_datetime(value)
            if when.tzinfo is None:
                return None
            seconds = (when - datetime.now(timezone.utc)).total_seconds()
        return min(604800, max(0, seconds))
    except (ValueError, TypeError, OverflowError):
        return None


def _http_error(status, data=b"", *, request_headers=None, request_body=None, response_headers=None):
    return MagnumAPIError("HTTP {}.".format(status), http_status=status,
                          retry_after_seconds=_retry_after(response_headers.get("Retry-After")) if response_headers else None,
                          redacted_response_body=_redacted_error_body(data, request_headers, request_body),
                          **_safe_error_metadata(data, status))


def _read_error_reply(stream):
    try:
        data = stream.read(MAX_ERROR_BYTES + 1)
        return data if isinstance(data, bytes) else b""
    except Exception:
        return b""


def _normalize_bearer(value):
    """Magnum returns a Bearer-prefixed value; keep only the token in memory."""
    if not isinstance(value, str):
        raise MagnumAPIError("Login returned no valid token.")
    if value[:7].lower() == "bearer ":
        value = value[7:]
    if not 16 <= len(value) <= 4096 or not re.fullmatch(r"[A-Za-z0-9._~+/-]+=*", value):
        raise MagnumAPIError("Login returned no valid token.")
    return value


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Keep requests and the Authorization header on the allowlisted URL.
        return None


def _read_limited(stream, limit):
    parts = []
    size = 0
    while True:
        chunk = stream.read(min(65536, limit + 1 - size))
        if not chunk:
            return b"".join(parts)
        size += len(chunk)
        if size > limit:
            raise MagnumAPIError("Response exceeds the 8 MiB size limit.")
        parts.append(chunk)


def _urllib_request(method, url, headers, body):
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    context = ssl.create_default_context()
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=context), _NoRedirect()
    )
    try:
        with opener.open(request, timeout=TIMEOUT) as response:
            status = response.status
            if not 200 <= status < 300:
                raise _http_error(status, _read_error_reply(response), request_headers=headers, request_body=body, response_headers=response.headers)
            return _read_limited(response, MAX_RESPONSE_BYTES)
    except urllib.error.HTTPError as error:
        status = error.code
        try:
            failure = _http_error(status, _read_error_reply(error), request_headers=headers, request_body=body, response_headers=error.headers)
        finally:
            error.close()
        raise failure from None
    except urllib.error.URLError as error:
        if isinstance(error.reason, ssl.SSLCertVerificationError):
            message = "TLS certificate verification failed."
        elif isinstance(error.reason, (socket.timeout, TimeoutError)):
            message = "Request timed out after {} seconds.".format(TIMEOUT)
        else:
            message = "HTTPS connection failed."
        raise MagnumAPIError(message) from None
    except (socket.timeout, TimeoutError):
        raise MagnumAPIError(
            "Request timed out after {} seconds.".format(TIMEOUT)
        ) from None
    except ssl.SSLError:
        raise MagnumAPIError("TLS connection failed.") from None
    except OSError:
        raise MagnumAPIError("HTTPS connection failed.") from None


def _curl_quote(value):
    if any(character in value for character in "\r\n\x00"):
        raise MagnumAPIError("Invalid HTTP header.")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _curl_request(executable, method, url, headers, body):
    # Authorization is supplied through stdin, never the process command line.
    config = "".join(
        "header = {}\n".format(_curl_quote(name + ": " + value))
        for name, value in headers.items()
    )
    if body is not None:
        config += "data = {}\n".format(_curl_quote(body.decode("ascii")))
    arguments = [
        executable, "--disable", "--silent", "--show-error",
        "--proto", "=https", "--connect-timeout", str(TIMEOUT),
        "--max-time", str(TIMEOUT), "--max-filesize", str(MAX_RESPONSE_BYTES),
        "--request", method, "--url", url, "--config", "-",
        "--write-out", _STATUS_MARKER.decode("ascii") + "%{http_code}",
    ]
    process = None
    try:
        process = subprocess.Popen(
            arguments,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        try:
            process.stdin.write(config.encode("utf-8"))
            process.stdin.close()
        except BrokenPipeError:
            pass
        # curl enforces a total timeout; the read cap also applies to old curl
        # versions that enforce --max-filesize only against Content-Length.
        output = _read_limited(process.stdout, MAX_RESPONSE_BYTES + 64)
        result = process.wait(timeout=TIMEOUT + 5)
        if result:
            descriptions = {
                28: "Request timed out after {} seconds.".format(TIMEOUT),
                35: "TLS connection failed.",
                60: "TLS certificate verification failed.",
                63: "Response exceeds the 8 MiB size limit.",
            }
            raise MagnumAPIError(
                descriptions.get(result, "HTTPS request failed (curl exit {}).".format(result))
            )
        data, separator, status_bytes = output.rpartition(_STATUS_MARKER)
        if not separator or not re.fullmatch(rb"[0-9]{3}", status_bytes):
            raise MagnumAPIError("Invalid HTTP transport response.")
        status = int(status_bytes)
        if not 200 <= status < 300:
            raise _http_error(status, data, request_headers=headers, request_body=body)
        if len(data) > MAX_RESPONSE_BYTES:
            raise MagnumAPIError("Response exceeds the 8 MiB size limit.")
        return data
    except subprocess.TimeoutExpired:
        raise MagnumAPIError(
            "Request timed out after {} seconds.".format(TIMEOUT)
        ) from None
    except OSError:
        raise MagnumAPIError("Could not execute the HTTPS transport.") from None
    finally:
        if process is not None:
            if process.poll() is None:
                process.kill()
            process.wait()
            for stream in (process.stdin, process.stdout):
                if stream is not None and not stream.closed:
                    stream.close()


def _http_request(method, url, headers, body):
    from magnum_http_policy import request_slot
    with request_slot():
        curl = shutil.which("curl.exe") if os.name == "nt" else None
        if curl:
            return _curl_request(curl, method, url, headers, body)
        return _urllib_request(method, url, headers, body)


class MagnumClient:
    def __init__(self):
        self._token = None

    def _request(self, endpoint, parameters=None):
        if endpoint not in _ENDPOINTS:
            raise MagnumAPIError("Endpoint is not allowlisted.")
        method, path, allowed_parameters = _ENDPOINTS[endpoint]
        parameters = parameters or {}
        if set(parameters) != set(allowed_parameters):
            raise MagnumAPIError("Unexpected endpoint parameters.")
        query = "&".join(
            urllib.parse.quote(str(key), safe="") + ("" if value is None else "=" +
                urllib.parse.quote("true" if value is True else "false" if value is False else str(value), safe=""))
            for key, value in parameters.items()
        )
        url = BASE_URL + path + ("?" + query if query else "")
        headers = {"Accept": "application/json", "Content-Type": "application/json", "X-Client-Version": CLIENT_VERSION}
        body = None
        if endpoint == "guest":
            headers["Content-Type"] = "application/json"
            body = b"{}"
        elif endpoint != "geo":
            if self._token is None:
                login = self._request("guest")
                token = login.get("token") if isinstance(login, dict) else None
                self._token = _normalize_bearer(token)
                del login  # The unused refresh token never leaves this method.
            headers["Authorization"] = "Bearer " + self._token
        try:
            raw = _http_request(method, url, headers, body)
        except MagnumAPIError as error:
            raise MagnumAPIError("{}: {}".format(endpoint, error),
                                 redacted_response_body=error.redacted_response_body,
                                 **error.safe_metadata()) from None
        try:
            return json.loads(raw.decode("utf-8-sig"))
        except (UnicodeError, ValueError, RecursionError):
            raise MagnumAPIError("{}: response is not valid UTF-8 JSON.".format(endpoint)) from None

    def geo(self, latitude, longitude):
        return self._request("geo", {
            "latitude": format(latitude, ".15g"),
            "longitude": format(longitude, ".15g"),
        })

    def categories(self, platform_id, parent_id=None):
        return self._request("categories", {"includeChildNodes": True, "parentId": parent_id, "platformId": platform_id})

    def suggest(self, platform_id, query):
        # Keep the older Python call signature, but mirror the exact app wire shape.
        return self._request("suggest", {"searchWord": query})


def _coordinate(value, minimum, maximum):
    try:
        number = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError("Expected a numeric coordinate.") from None
    if not math.isfinite(number) or not minimum <= number <= maximum:
        raise argparse.ArgumentTypeError(
            "Coordinate must be between {} and {}.".format(minimum, maximum)
        )
    return number


def _platform_id(value):
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("Expected an integer platform ID.") from None
    if not 0 < number <= 2147483647:
        raise argparse.ArgumentTypeError("Platform ID must be a positive 32-bit integer.")
    return number


def _query(value):
    value = value.strip()
    if not value or len(value) > 256 or any(ord(character) < 32 for character in value):
        raise argparse.ArgumentTypeError("Query must contain 1–256 printable characters.")
    return value


def _parser():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--compact", action="store_true", help="Emit compact UTF-8 JSON.")
    commands = parser.add_subparsers(dest="command", required=True)
    geo = commands.add_parser("geo", help="Resolve public delivery stores at coordinates.")
    categories = commands.add_parser("categories", help="Get categories for a platform.")
    suggest = commands.add_parser("suggest", help="Get up to five search suggestions.")
    demo = commands.add_parser("demo", help="Resolve location, then get categories and suggestions.")
    for command in (geo, demo):
        command.add_argument("--latitude", required=True, type=lambda value: _coordinate(value, -90, 90))
        command.add_argument("--longitude", required=True, type=lambda value: _coordinate(value, -180, 180))
    for command in (categories, suggest):
        command.add_argument("--platform-id", required=True, type=_platform_id)
    for command in (suggest, demo):
        command.add_argument("--query", required=True, type=_query)
    return parser


def _safe_output(value, token):
    # Guard against an unexpected response reflecting the current guest token.
    if isinstance(value, dict):
        return {
            key: ("[REDACTED]" if key.lower() in {"token", "refreshtoken", "authorization"}
                  else _safe_output(item, token))
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_safe_output(item, token) for item in value]
    if isinstance(value, str) and token:
        return value.replace(token, "[REDACTED]")
    return value


def main(argv=None):
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    arguments = _parser().parse_args(argv)
    client = MagnumClient()
    try:
        if arguments.command == "geo":
            result = client.geo(arguments.latitude, arguments.longitude)
        elif arguments.command == "categories":
            result = client.categories(arguments.platform_id)
        elif arguments.command == "suggest":
            result = client.suggest(arguments.platform_id, arguments.query)
        else:
            location = client.geo(arguments.latitude, arguments.longitude)
            store = location.get("darkStore") if isinstance(location, dict) else None
            platform_id = store.get("id") if isinstance(store, dict) else None
            if isinstance(platform_id, bool) or not isinstance(platform_id, int) or platform_id <= 0:
                raise MagnumAPIError("geo: no darkStore.id for these coordinates.")
            result = {
                "geo": location,
                "platformId": platform_id,
                "categories": client.categories(platform_id),
                "suggestions": client.suggest(platform_id, arguments.query),
            }
        result = _safe_output(result, client._token)
        if arguments.compact:
            output = json.dumps(result, ensure_ascii=False, separators=(",", ":"))
        else:
            output = json.dumps(result, ensure_ascii=False, indent=2)
        print(output)
        return 0
    except MagnumAPIError as error:
        print("Error: {}".format(error), file=sys.stderr)
        return 1
    except (BrokenPipeError, KeyboardInterrupt):
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
