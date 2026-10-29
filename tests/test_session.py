"""Synthetic session contract tests: no network, vault, tokens or user data."""

from pathlib import Path
import sys
import unittest
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from magnum_session import SESSION_CONTRACTS, SessionMethods


class Client(SessionMethods):
    def __init__(self, reply=None, phone="70000000000"):
        self._call = Mock(return_value=reply)
        self._current_phone = Mock(return_value=phone)


class SessionTests(unittest.TestCase):
    def test_profile_uses_own_login_phone_not_customer_id(self):
        reply = {"id": 123, "name": "Synthetic", "cellPhone": "70000000000"}
        client = Client(reply)
        self.assertIs(client.read_profile(), reply)
        client._current_phone.assert_called_once_with()
        client._call.assert_called_once_with("profile", path_params={"phone": "70000000000"})
        self.assertEqual(SESSION_CONTRACTS["profile"]["path_keys"], ("phone",))

    def test_profile_cannot_target_another_account(self):
        client = Client()
        with self.assertRaises(TypeError):
            client.read_profile("71111111111")
        client._call.assert_not_called()
        client._current_phone.assert_not_called()

    def test_invalid_own_phone_is_rejected_without_reflection(self):
        for phone in (None, 70000000000, True, "123", "+70000000000", "synthetic-secret"):
            with self.subTest(phone=phone):
                client = Client(phone=phone)
                with self.assertRaises(ValueError) as raised:
                    client.read_profile()
                self.assertEqual(str(raised.exception), "The current session has no valid login phone.")
                client._call.assert_not_called()

    def test_address_reads_preserve_full_reply_and_have_no_parameters(self):
        for name, reply in (("last_delivery_address", {"location": {"id": 11}}),
                            ("delivery_addresses", [{"id": 11}, {"id": 12}])):
            with self.subTest(name=name):
                client = Client(reply)
                self.assertIs(getattr(client, name)(), reply)
                client._call.assert_called_once_with(name)
                self.assertEqual(SESSION_CONTRACTS[name]["query_keys"], ())
                self.assertEqual(SESSION_CONTRACTS[name]["body_keys"], ())
                self.assertTrue(SESSION_CONTRACTS[name]["auth_required"])

    def test_geo_uses_distinct_latitude_and_longitude_and_no_account(self):
        reply = {"darkStore": {"id": 5002}, "expressStore": None}
        client = Client(reply)
        self.assertIs(client.resolve_stores(43.238949, 76.889709), reply)
        client._call.assert_called_once_with(
            "resolve_stores", query={"latitude": 43.238949, "longitude": 76.889709})
        client._current_phone.assert_not_called()
        self.assertFalse(SESSION_CONTRACTS["resolve_stores"]["auth_required"])

    def test_bad_coordinates_never_call_transport(self):
        for value in (None, True, False, "43", float("nan"), float("inf"), -float("inf"), 10 ** 400):
            for axis in ("latitude", "longitude"):
                with self.subTest(value=value, axis=axis):
                    client = Client()
                    kwargs = {"latitude": 43, "longitude": 76, axis: value}
                    with self.assertRaises(ValueError):
                        client.resolve_stores(**kwargs)
                    client._call.assert_not_called()
        for latitude, longitude in ((-90.1, 0), (90.1, 0), (0, -180.1), (0, 180.1)):
            client = Client()
            with self.assertRaises(ValueError):
                client.resolve_stores(latitude, longitude)
            client._call.assert_not_called()

    def test_read_does_not_retry_uncertain_network_result(self):
        client = Client()
        client._call.side_effect = TimeoutError("synthetic timeout")
        with self.assertRaises(TimeoutError):
            client.delivery_addresses()
        self.assertEqual(client._call.call_count, 1)

    def test_refresh_is_only_a_registry_contract_with_both_raw_fields(self):
        contract = SESSION_CONTRACTS["refresh_session"]
        self.assertEqual((contract["method"], contract["path"]),
                         ("POST", "/auth/server/api/v1/security/tokens/refresh"))
        self.assertEqual(contract["body_keys"], ("refreshToken", "token"))
        self.assertEqual(contract["query_keys"], ())
        self.assertFalse(contract["auth_required"])
        self.assertFalse(hasattr(SessionMethods, "refresh_session"))


if __name__ == "__main__":
    unittest.main()
