"""Offline integration checks of contract routing, account scope and token rotation.

Every client uses an in-memory vault and an injected transport. Real HTTP,
credential-store construction and authentication locks are blocked/mocked.
"""

import base64
import contextlib
import io
import json
import pathlib
import sys
import time
import types
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import magnum_auth as auth
import magnum_client as core
from magnum_vault import SessionRecord


def jwt(*, subject="+70000000000", expiry=None, user_id=912345, marker="original"):
    claims = {"exp": expiry or int(time.time()) + 3600, "userId": user_id, "marker": marker}
    if subject is not None:
        claims["sub"] = subject
    encoded = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return "eyJhbGciOiJub25lIn0." + encoded + ".synthetic-signature"


def record(*, subject="+70000000000", kind="user", marker="original", expiry=None):
    expiry = expiry or int(time.time()) + 3600
    return SessionRecord(token=jwt(subject=subject, marker=marker, expiry=expiry),
                         refresh_token="synthetic-refresh-" + marker,
                         expires_at=expiry, kind=kind)


def jwt_claims(claims):
    """Encode synthetic routing data, including deliberately invalid JWT JSON."""
    encoded = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return "eyJhbGciOiJub25lIn0." + encoded + ".synthetic-signature"


class MemoryStore:
    def __init__(self, value=None):
        self.value = value
        self.writes = []

    def check(self):
        return types.SimpleNamespace(available=True, backend="memory-test", reason=None)

    def read(self):
        return self.value

    def write(self, value):
        self.writes.append(value)
        self.value = value


class Transport:
    def __init__(self):
        self.calls = []
        self.responses = []

    def __call__(self, method, url, headers, body):
        self.calls.append((method, url, dict(headers), body))
        response = self.responses.pop(0) if self.responses else {"content": [{"itemId": 42}], "totalElements": 1}
        if isinstance(response, Exception):
            raise response
        return response if isinstance(response, bytes) else json.dumps(response).encode()


class ClientTests(unittest.TestCase):
    def setUp(self):
        self.now = 100.0
        self.store = MemoryStore(record())
        self.transport = Transport()
        for module, name in ((core.wire, "_http_request"), (auth, "_http_request"), (core, "SecretStore")):
            guard = patch.object(module, name, side_effect=AssertionError("Real network or vault is forbidden"))
            guard.start()
            self.addCleanup(guard.stop)
        lock = patch.object(core, "_mutation_lock", side_effect=lambda: contextlib.nullcontext())
        lock.start()
        self.addCleanup(lock.stop)
        self.client = core.MagnumAPI(store=self.store, transport=self.transport, clock=lambda: self.now)

    def test_profile_routes_own_subject_phone_never_numeric_user_id(self):
        self.client.read_profile()
        method, url, headers, body = self.transport.calls[0]
        self.assertEqual(method, "GET")
        self.assertEqual(url, core.wire.BASE_URL + "/auth/server/api/v1/customers/customer/70000000000")
        self.assertNotIn("912345", url)
        self.assertEqual(headers["Authorization"], "Bearer " + self.store.value.token)
        self.assertEqual(headers["Accept"], "application/json")
        self.assertEqual(headers["Content-Type"], "application/json")
        self.assertEqual(headers["X-Client-Version"], "4.3.15")
        self.assertIsNone(body)

    def test_profile_cannot_override_subject_via_internal_contract(self):
        with self.assertRaises((ValueError, auth.AuthError)):
            self.client._call("profile", path_params={"phone": "71111111111"})
        self.assertEqual(self.transport.calls, [])

    def test_profile_rejects_account_change_between_phone_routing_and_header(self):
        original = self.store.value.token
        changed = record(subject="+71111111111", marker="changed-during-routing").token
        with patch.object(self.client.session, "get_access_token", side_effect=[original, changed]):
            with self.assertRaises(auth.AuthError):
                self.client.read_profile()
        self.assertEqual(self.transport.calls, [])

    def test_product_cli_uses_current_item_detail_without_platform_argument(self):
        self.transport.responses.append({"itemId": 42, "name": "Synthetic product"})
        with patch.object(core, "MagnumAPI", return_value=self.client), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(core.main(["product", "--item-id", "42"]), 0)
        method, url, _, body = self.transport.calls[0]
        self.assertEqual(method, "GET")
        self.assertEqual(url, core.wire.BASE_URL + "/catalog/client/platformItem/42")
        self.assertIsNone(body)

    def test_categories_encode_boolean_lowercase_and_null_as_bare_key(self):
        self.client.categories()
        self.assertEqual(self.transport.calls[0][1], core.wire.BASE_URL +
                         "/catalog/client/catalog?includeChildNodes=true&parentId&platformId=5002")
        self.assertIsNone(self.transport.calls[0][3])
        self.assertEqual(core.encode_query({"flag": False, "empty": None, "term": "хлеб & 10%+"}),
                         "flag=false&empty&term=%D1%85%D0%BB%D0%B5%D0%B1%20%26%2010%25%2B")

    def test_only_verified_contract_and_exact_parameter_names_reach_transport(self):
        cases = (
            ("not_an_endpoint", {}),
            ("catalog_suggest_products", {"query": {"searchWord": "milk", "merchantId": 5002}}),
            ("catalog_search_products", {"query": {"platformId": 5002, "searchWord": "milk", "page": 0, "pageSize": 20}}),
            ("catalog_categories", {"query": {"platformId": 5002}}),
            ("catalog_product_detail", {"path_params": {"platform_item_id": 42, "host": "example.invalid"}}),
            ("cart_set_item", {"body": {"itemId": 42, "quantity": 1, "platformId": 5002}}),
            ("cart_set_item", {}),
            ("cart_remove_item", {"body": {"itemId": 42, "quantity": 0}}),
            ("refresh_session", {"body": {"token": "synthetic-secret"}}),
        )
        for name, kwargs in cases:
            with self.subTest(name=name, kwargs=kwargs), self.assertRaises(ValueError):
                self.client._call(name, **kwargs)
        self.assertEqual(self.transport.calls, [])

    def test_public_store_resolver_never_reads_user_vault_or_sends_auth(self):
        self.store.value = None
        with patch.object(self.store, "read", side_effect=AssertionError("Public request read vault")):
            self.client.resolve_stores(43.2, 76.9)
        method, url, headers, body = self.transport.calls[0]
        self.assertEqual(method, "GET")
        self.assertTrue(url.endswith("/productstore/geo/api/v1/type/all/attributes?latitude=43.2&longitude=76.9"))
        self.assertNotIn("Authorization", headers)
        self.assertIsNone(body)

    def test_authenticated_methods_never_silently_login_guest_or_refresh(self):
        expired = int(time.time()) - 10
        for value in (None, record(kind="guest"), record(expiry=expired)):
            self.store.value = value
            with self.subTest(value=repr(value)), self.assertRaises(auth.AuthError):
                self.client.search_products("milk", 5002)
        self.assertEqual(self.transport.calls, [])
        self.assertEqual(self.store.writes, [])

    def test_identical_reads_are_cached_with_independent_return_values(self):
        first = self.client.search_products("milk", 5002)
        first["content"][0]["itemId"] = 999
        second = self.client.search_products("milk", 5002)
        second["content"].clear()
        third = self.client.search_products("milk", 5002)
        self.assertEqual(third["content"], [{"itemId": 42}])
        self.assertEqual(len(self.transport.calls), 1)
        self.assertTrue(self.client.last_request["cached"])

    def test_cache_separates_platform_page_term_and_operation(self):
        self.client.search_products("milk", 5002, page=0)
        self.client.search_products("milk", 5003, page=0)
        self.client.search_products("milk", 5002, page=1)
        self.client.search_products("bread", 5002, page=0)
        self.client.suggest_products("milk")
        self.assertEqual(len(self.transport.calls), 5)
        self.client.search_products("milk", 5003, page=0)
        self.assertEqual(len(self.transport.calls), 5)

    def test_cache_expires_at_search_ttl(self):
        self.client.search_products("milk", 5002)
        self.now += 29.9
        self.client.search_products("milk", 5002)
        self.assertEqual(len(self.transport.calls), 1)
        self.now += 0.1
        self.client.search_products("milk", 5002)
        self.assertEqual(len(self.transport.calls), 2)
        self.assertFalse(self.client.last_request["cached"])

    def test_cart_reads_always_reach_transport(self):
        self.client.read_cart(5002)
        self.client.read_cart(5002)
        self.assertEqual(len(self.transport.calls), 2)
        self.assertFalse(self.client.last_request["cached"])

    def test_cart_write_invalidates_previous_reads(self):
        self.client.search_products("milk", 5002)
        self.transport.responses.append({"status": True, "message": "ok"})
        self.client.set_item_quantity(42, 1)
        self.client.search_products("milk", 5002)
        self.assertEqual([call[0] for call in self.transport.calls], ["GET", "PUT", "GET"])
        self.assertEqual(json.loads(self.transport.calls[1][3]), {"itemId": 42, "quantity": 1})
        self.assertEqual(self.store.writes, [])

    def test_cart_zero_uses_delete_with_item_id_only(self):
        self.transport.responses.append(b"")
        self.assertEqual(self.client.set_item_quantity(42, 0), {"status": True})
        method, url, _, body = self.transport.calls[0]
        self.assertEqual(method, "DELETE")
        self.assertTrue(url.endswith("/cart/item"))
        self.assertEqual(json.loads(body), {"itemId": 42})

    def test_cache_separates_distinct_signed_in_subjects(self):
        self.client.search_products("milk", 5002)
        self.store.value = record(subject="+71111111111", marker="second-user")
        self.client.search_products("milk", 5002)
        self.assertEqual(len(self.transport.calls), 2)

    def test_missing_subject_cannot_reuse_another_user_cache(self):
        # A malformed routing hint must fail closed or get its own token scope.
        self.store.value = record(subject=None, marker="first-no-sub")
        try:
            self.client.search_products("milk", 5002)
        except auth.AuthError:
            self.assertEqual(self.transport.calls, [])
            return
        self.store.value = record(subject=None, marker="second-no-sub")
        self.client.search_products("milk", 5002)
        self.assertEqual(len(self.transport.calls), 2)

    def test_cached_private_read_cannot_survive_local_logout(self):
        self.client.search_products("milk", 5002)
        self.store.value = None
        with self.assertRaises(auth.AuthError):
            self.client.search_products("milk", 5002)
        self.assertEqual(len(self.transport.calls), 1)

    def test_refresh_sends_both_bearer_fields_no_auth_and_stores_rotated_pair(self):
        previous = self.store.value
        replacement = record(marker="rotated")
        self.client.search_products("milk", 5002)
        self.transport.responses.append({"token": "Bearer " + replacement.token,
                                         "refreshToken": "Bearer " + replacement.refresh_token})
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            status = self.client.refresh_session()
        method, url, headers, body = self.transport.calls[-1]
        self.assertEqual(method, "POST")
        self.assertEqual(url, core.wire.BASE_URL + "/auth/server/api/v1/security/tokens/refresh")
        self.assertNotIn("Authorization", headers)
        self.assertEqual(json.loads(body), {"refreshToken": "Bearer " + previous.refresh_token,
                                          "token": "Bearer " + previous.token})
        self.assertEqual(len(self.store.writes), 1)
        self.assertEqual(self.store.value.token, replacement.token)
        self.assertEqual(self.store.value.refresh_token, replacement.refresh_token)
        self.assertTrue(status["ready_user"])
        diagnostics = stdout.getvalue() + stderr.getvalue() + repr(status) + repr(self.client)
        for secret in (previous.token, previous.refresh_token, replacement.token, replacement.refresh_token):
            self.assertNotIn(secret, diagnostics)
        self.client.search_products("milk", 5002)
        self.assertEqual(len(self.transport.calls), 3)

    def test_refresh_requires_user_pair_and_never_creates_guest(self):
        for value in (None, record(kind="guest"), SessionRecord(token=jwt(), kind="user")):
            self.store.value = value
            with self.subTest(value=repr(value)), self.assertRaises(auth.AuthError):
                self.client.refresh_session()
        self.assertEqual(self.transport.calls, [])
        self.assertEqual(self.store.writes, [])

    def test_malformed_refresh_keeps_both_previous_fields_without_leaks(self):
        previous = self.store.value
        self.transport.responses.append({"token": "Bearer " + jwt(marker="partial")})
        with self.assertRaises(auth.AuthError) as failure:
            self.client.refresh_session()
        self.assertIs(self.store.value, previous)
        self.assertEqual(self.store.writes, [])
        self.assertEqual(len(self.transport.calls), 1)
        self.assertNotIn(previous.token, repr(failure.exception))
        self.assertNotIn(previous.refresh_token, repr(failure.exception))

    def test_expired_refresh_replacement_preserves_previous_session(self):
        previous = self.store.value
        self.transport.responses.append({"token": "Bearer " + jwt(expiry=int(time.time()) - 10),
                                         "refreshToken": "Bearer synthetic-expired-refresh"})
        with self.assertRaises(auth.AuthError):
            self.client.refresh_session()
        self.assertIs(self.store.value, previous)
        self.assertEqual(self.store.writes, [])

    def test_refresh_rejects_unusable_or_different_account_tokens_before_write(self):
        future = int(time.time()) + 3600
        payload = {"sub": "+70000000000", "exp": future}
        invalid_tokens = {
            "opaque_token": "opaque-access-token-123456789",
            "invalid_claims_encoding": "eyJhbGciOiJub25lIn0.invalid.synthetic-signature",
            "claims_not_object": jwt_claims(["sub", "exp"]),
            "missing_subject": jwt_claims({"exp": future}),
            "invalid_subject": jwt_claims({**payload, "sub": "synthetic-private-phone-invalid"}),
            "different_subject": jwt_claims({**payload, "sub": "+71111111111"}),
            "missing_expiry": jwt_claims({"sub": "+70000000000"}),
            "null_expiry": jwt_claims({**payload, "exp": None}),
            "string_expiry": jwt_claims({**payload, "exp": str(future)}),
            "bool_expiry": jwt_claims({**payload, "exp": True}),
            "nan_expiry": jwt_claims({**payload, "exp": float("nan")}),
            "infinite_expiry": jwt_claims({**payload, "exp": float("inf")}),
            "negative_infinite_expiry": jwt_claims({**payload, "exp": -float("inf")}),
            "huge_expiry": jwt_claims({**payload, "exp": 10 ** 400}),
            "out_of_storage_range_expiry": jwt_claims({**payload, "exp": 253402300800}),
        }
        for label, token in invalid_tokens.items():
            with self.subTest(case=label):
                previous = record()
                self.store.value = previous
                self.store.writes.clear()
                self.transport.calls.clear()
                self.transport.responses[:] = [{"token": "Bearer " + token,
                                                "refreshToken": "Bearer synthetic-rejected-refresh"}]
                with self.assertRaises(auth.AuthError) as failure:
                    self.client.refresh_session()
                self.assertEqual(failure.exception.code, "invalid_response")
                self.assertIs(self.store.value, previous)
                self.assertEqual(self.store.writes, [])
                self.assertEqual(len(self.transport.calls), 1)
                for secret in (token, previous.token, previous.refresh_token):
                    self.assertNotIn(secret, repr(failure.exception))

    def test_refresh_validates_old_identity_before_any_network_request(self):
        for previous in (
            SessionRecord(token="opaque-access-token-123456789", refresh_token="synthetic-refresh-original", kind="user"),
            record(subject=None), record(subject="synthetic-invalid-subject"),
        ):
            with self.subTest(kind=type(previous).__name__):
                self.store.value = previous
                with self.assertRaises(auth.AuthError) as failure:
                    self.client.refresh_session()
                self.assertEqual(failure.exception.code, "invalid_response")
                self.assertIs(self.store.value, previous)
                self.assertEqual(self.store.writes, [])
                self.assertEqual(self.transport.calls, [])

    def test_refresh_accepts_same_canonical_subject_and_fractional_numeric_expiry(self):
        future = int(time.time()) + 3600.25
        token = jwt_claims({"sub": "70000000000", "exp": future})
        self.transport.responses.append({"token": "Bearer " + token,
                                         "refreshToken": "Bearer synthetic-rotated-refresh"})
        status = self.client.refresh_session()
        self.assertEqual(len(self.store.writes), 1)
        self.assertEqual(self.store.value.token, token)
        self.assertEqual(self.store.value.expires_at, int(future) + 1)
        self.assertTrue(status["ready_user"])

    def test_refresh_can_replace_expired_access_token_for_same_account(self):
        self.store.value = record(expiry=int(time.time()) - 20)
        replacement = record(marker="after-expiry")
        self.transport.responses.append({"token": "Bearer " + replacement.token,
                                         "refreshToken": "Bearer " + replacement.refresh_token})
        status = self.client.refresh_session()
        self.assertEqual(len(self.store.writes), 1)
        self.assertEqual(self.store.value.token, replacement.token)
        self.assertTrue(status["ready_user"])

    def test_refresh_transport_uncertainty_keeps_pair_and_never_retries(self):
        previous = self.store.value
        self.transport.responses.append(TimeoutError("synthetic-private-network-diagnostic"))
        with self.assertRaises(TimeoutError):
            self.client.refresh_session()
        self.assertIs(self.store.value, previous)
        self.assertEqual(self.store.writes, [])
        self.assertEqual(len(self.transport.calls), 1)

    def test_failed_read_is_not_cached_or_retried(self):
        self.transport.responses.append(core.wire.MagnumAPIError("HTTP 429.", http_status=429))
        with self.assertRaises(core.wire.MagnumAPIError):
            self.client.search_products("milk", 5002)
        self.assertEqual(len(self.transport.calls), 1)
        self.client.search_products("milk", 5002)
        self.assertEqual(len(self.transport.calls), 2)

    def test_invalid_json_read_is_not_cached(self):
        self.transport.responses.append(b"{not-json}")
        with self.assertRaises(core.wire.MagnumAPIError):
            self.client.search_products("milk", 5002)
        self.client.search_products("milk", 5002)
        self.assertEqual(len(self.transport.calls), 2)


if __name__ == "__main__":
    unittest.main()
