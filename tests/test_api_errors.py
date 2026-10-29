"""Safe error diagnostics with synthetic replies; no network or user data."""
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch
import urllib.error

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import magnum_api as api
import magnum_auth as auth
import magnum_login_web as web

PHONE = "+77011234567"
OTP = "009876"
TOKEN = "synthetic-token-that-must-never-leak"


def reply(description, code=-1101, **extra):
    return json.dumps({"errorDescr": description, "errorCode": code, **extra}, ensure_ascii=False).encode()


class ErrorTests(unittest.TestCase):
    def make_error(self, status, raw):
        return api._http_error(status, raw,
                               request_headers={"Authorization": "Bearer " + TOKEN},
                               request_body=json.dumps({"phone": PHONE, "smsCode": OTP}).encode())

    def assert_no_secrets(self, value):
        text = str(value)
        for secret in (PHONE, OTP, TOKEN):
            self.assertNotIn(secret, text)

    def test_validation_values_and_raw_body_never_escape_metadata(self):
        raw = reply("{phone=Номер должен начинаться с цифры 7 без знака +, smsCode=неверный код} " + PHONE + OTP + TOKEN,
                    token=TOKEN, phone=PHONE, smsCode=OTP)
        error = self.make_error(400, raw)
        self.assertEqual(str(error), "HTTP 400.")
        self.assertEqual(error.safe_metadata(), {
            "http_status": 400, "service_error_code": -1101,
            "validation_fields": ("phone", "smsCode"), "reason": "phone_format",
        })
        self.assert_no_secrets(repr(error))
        self.assert_no_secrets(error.__dict__)
        self.assertNotIn("errorDescr", error.__dict__)

    def test_reason_categories_are_fixed_and_unknown_text_is_discarded(self):
        for status, description, reason in (
            (400, "Неверный код " + OTP, "sms_code_invalid"),
            (401, "SMS code expired " + PHONE, "expired"),
            (429, TOKEN, "rate_limited"),
            (400, "Authorization header specified " + TOKEN, "authorization_header"),
            (401, PHONE + OTP + TOKEN, "unknown"),
        ):
            with self.subTest(reason=reason):
                error = self.make_error(status, reply(description))
                self.assertEqual(error.reason, reason)
                self.assert_no_secrets(error.__dict__)

    def test_malformed_or_oversized_reply_and_non_numeric_codes_are_dropped(self):
        for raw in (b"not JSON " + TOKEN.encode(), b"x" * (api.MAX_ERROR_BYTES + 1)):
            error = self.make_error(401, raw)
            self.assertEqual(error.safe_metadata(), {"http_status": 401, "reason": "unknown"})
        for code in (TOKEN, True, 77011234567):
            error = self.make_error(400, reply("{untrustedField=" + TOKEN + "}", code=code))
            self.assertIsNone(error.service_error_code)
            self.assertEqual(error.validation_fields, ())
            self.assert_no_secrets(error.__dict__)

    def test_urllib_http_error_is_read_bounded_and_sanitized(self):
        raw = reply("Неверный код " + PHONE + OTP + TOKEN)
        stream = io.BytesIO(raw)
        upstream = urllib.error.HTTPError("https://mgo-gw1.e-magnum.kz/test", 401, TOKEN, {}, stream)
        opener = Mock()
        opener.open.side_effect = upstream
        with patch.object(api.urllib.request, "build_opener", return_value=opener):
            with self.assertRaises(api.MagnumAPIError) as result:
                api._urllib_request("POST", api.BASE_URL + "/test", {"Authorization": "Bearer " + TOKEN},
                                    json.dumps({"phone": PHONE, "smsCode": OTP}).encode())
        error = result.exception
        self.assertEqual(error.http_status, 401)
        self.assertEqual(error.reason, "sms_code_invalid")
        self.assertTrue(stream.closed)
        self.assert_no_secrets(error.__dict__)
        self.assert_no_secrets(str(error))

    def test_curl_http_error_has_same_safe_metadata(self):
        raw = reply("SMS code expired " + PHONE + OTP + TOKEN)
        process = Mock()
        process.stdin = io.BytesIO()
        process.stdout = io.BytesIO(raw + api._STATUS_MARKER + b"401")
        process.wait.return_value = 0
        process.poll.return_value = 0
        with patch.object(api.subprocess, "Popen", return_value=process):
            with self.assertRaises(api.MagnumAPIError) as result:
                api._curl_request("curl.exe", "POST", api.BASE_URL + "/test", {"Authorization": "Bearer " + TOKEN},
                                  json.dumps({"phone": PHONE, "smsCode": OTP}).encode())
        self.assertEqual(result.exception.http_status, 401)
        self.assertEqual(result.exception.reason, "expired")
        self.assert_no_secrets(result.exception.__dict__)

    def test_auth_and_web_preserve_only_safe_error_metadata(self):
        error = self.make_error(400, reply("{smsCode=Неверный код " + OTP + "} " + PHONE + TOKEN))
        with patch.object(auth, "_http_request", side_effect=error):
            with self.assertRaises(auth.AuthError) as result:
                auth._post_auth("second", {"phone": PHONE[1:], "pin": "0123", "smsCode": OTP})
        failure = result.exception
        self.assertEqual(failure.http_status, 400)
        self.assertEqual(failure.service_error_code, -1101)
        self.assertEqual(failure.validation_fields, ("smsCode",))
        self.assertEqual(failure.reason, "sms_code_invalid")
        captured = io.StringIO()
        with patch.object(web.sys, "stderr", captured):
            web._log_backend_failure("verify", failure)
        event = json.loads(captured.getvalue())
        self.assertEqual(event["reason"], "sms_code_invalid")
        self.assertEqual(event["validation_fields"], ["smsCode"])
        self.assertEqual(event["service_error_code"], -1101)
        self.assert_no_secrets(failure.__dict__)
        self.assert_no_secrets(captured.getvalue())

    def test_local_body_preserves_error_details_but_masks_context_and_nested_keys(self):
        raw = reply("Validation failed for " + PHONE + " / " + PHONE[1:] + " / " + OTP + " / " + TOKEN,
                    details={"cellPhone": PHONE, "access_token": TOKEN, "refreshToken": TOKEN,
                             "password": "synthetic-password", "publicNote": "retain this exact detail"})
        error = self.make_error(400, raw)
        parsed = json.loads(error.redacted_response_body)
        self.assertEqual(parsed["errorCode"], -1101)
        self.assertEqual(parsed["details"]["publicNote"], "retain this exact detail")
        for key in ("cellPhone", "access_token", "refreshToken", "password"):
            self.assertEqual(parsed["details"][key], "[REDACTED]")
        self.assert_no_secrets(error.redacted_response_body)
        self.assertNotIn(PHONE[1:], error.redacted_response_body)
        self.assertNotIn("synthetic-password", error.redacted_response_body)
        self.assertNotIn("retain this exact detail", str(error))
        self.assertNotIn("retain this exact detail", repr(error))
        self.assertNotIn("redacted_response_body", error.safe_metadata())
        captured = io.StringIO()
        with patch.object(web.sys, "stderr", captured):
            web._log_backend_failure("verify", error)
        self.assertNotIn("retain this exact detail", captured.getvalue())
        self.assertNotIn("errorDescr", captured.getvalue())

    def test_factory_without_context_masks_sensitive_keys_jwt_and_bearer(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzeW50aGV0aWMifQ.signatureSynthetic123"
        error = api._http_error(401, reply("JWT " + jwt + " Bearer opaqueSecret123", token=TOKEN,
                                           data={"sms_code": OTP, "authorization": "Bearer " + TOKEN}))
        for secret in (jwt, "opaqueSecret123", TOKEN, OTP):
            self.assertNotIn(secret, error.redacted_response_body)

    def test_body_is_bounded_to_64_kib(self):
        error = self.make_error(400, b"x" * (api.MAX_ERROR_BYTES + 1000))
        self.assertLessEqual(len(error.redacted_response_body.encode()), 64 * 1024)
        self.assertTrue(error.redacted_response_body.endswith("[response truncated]"))

    def test_pin_is_redacted_but_validation_field_name_is_safe(self):
        raw = reply("{pin=Rejected value 0123}", pin="0123")
        error = api._http_error(400, raw, request_body=json.dumps({"pin": "0123"}).encode())
        self.assertEqual(error.validation_fields, ("pin",))
        self.assertNotIn("0123", error.redacted_response_body)
        self.assertEqual(json.loads(error.redacted_response_body)["pin"], "[REDACTED]")

    def test_first_response_shape_contains_identifiers_and_types_only(self):
        raw = json.dumps({"challengeId": TOKEN, "phone": PHONE, "smsCode": OTP,
                          "nested": {"token": TOKEN}, "items": [PHONE, OTP],
                          PHONE: TOKEN, OTP: PHONE, TOKEN: OTP}).encode()
        captured = io.StringIO()
        with patch.object(auth.sys, "stderr", captured):
            auth._log_auth_response_shape("first", raw)
            auth._log_auth_response_shape("first", b"")
            auth._log_auth_response_shape("first", TOKEN.encode())
            auth._log_auth_response_shape("second", raw)
        rows = [json.loads(row) for row in captured.getvalue().splitlines()]
        self.assertEqual(len(rows), 3)
        self.assertEqual(rows[0]["json_type"], "object")
        self.assertEqual(rows[0]["keys"], ["challengeId", "items", "nested", "phone", "smsCode"])
        self.assertEqual(rows[0]["field_types"], {"challengeId": "string", "items": "array", "nested": "object", "phone": "string", "smsCode": "string"})
        self.assertEqual(rows[1]["json_type"], "empty")
        self.assertEqual(rows[2]["json_type"], "non_json")
        self.assert_no_secrets(captured.getvalue())


if __name__ == "__main__":
    unittest.main()
