"""Synthetic cart contract tests. No network, credentials or user cart."""

from pathlib import Path
import sys
import unittest
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from magnum_cart import CART_CONTRACTS, MAX_CART_QUANTITY, CartMethods, CartOperationRejected


class Client(CartMethods):
    def __init__(self, reply=None):
        self._call = Mock(return_value=reply)


class CartTests(unittest.TestCase):
    def test_read_preserves_full_server_cart_and_exact_platform_query(self):
        cart = {"availableItems": [], "deletedItems": [], "packagingPrice": 50,
                "minOrderPrice": 6000, "message": "service text"}
        client = Client(cart)
        self.assertIs(client.read_cart(5002), cart)
        client._call.assert_called_once_with("cart", query={"promoCode": "", "platformId": 5002})
        self.assertEqual(CART_CONTRACTS["cart"]["path"], "/cart/v2/bymerchant")

    def test_merchant_delivery_uses_distinct_identifier(self):
        client = Client({"deliveryPrice": 500})
        self.assertEqual(client.merchant_delivery(234), {"deliveryPrice": 500})
        client._call.assert_called_once_with("merchant_delivery", query={"merchantId": 234})

    def test_first_add_and_updates_send_absolute_integer_quantity_once(self):
        for quantity in (1, 500):
            with self.subTest(quantity=quantity):
                client = Client({"status": True, "message": "ok", "unknown": "omit"})
                self.assertEqual(client.set_item_quantity(1234, quantity), {"status": True, "message": "ok"})
                client._call.assert_called_once_with(
                    "cart_set_item", body={"itemId": 1234, "quantity": quantity})
                contract = CART_CONTRACTS["cart_set_item"]
                self.assertEqual((contract["method"], contract["path"]), ("PUT", "/cart/v2/item"))
                self.assertEqual(contract["query_keys"], ())

    def test_zero_routes_once_to_delete_json_body(self):
        client = Client(None)
        self.assertEqual(client.set_item_quantity(1234, 0), {"status": True})
        client._call.assert_called_once_with("cart_remove_item", body={"itemId": 1234})
        contract = CART_CONTRACTS["cart_remove_item"]
        self.assertEqual((contract["method"], contract["path"]), ("DELETE", "/cart/item"))
        self.assertEqual(contract["query_keys"], ())

    def test_remove_does_not_assume_json_reply(self):
        client = Client(None)
        self.assertEqual(client.remove_item(77), {"status": True})
        client._call.assert_called_once_with("cart_remove_item", body={"itemId": 77})

    def test_http_success_with_status_false_is_rejected_without_reply_secrets(self):
        secret = "synthetic-token-must-not-escape"
        client = Client({"status": False, "message": secret, "token": secret})
        with self.assertRaises(CartOperationRejected) as raised:
            client.set_item_quantity(123, 1)
        error = raised.exception
        self.assertEqual(error.safe_metadata(), {"reason": "cart_rejected"})
        for value in (str(error), repr(error), repr(error.__dict__), repr(error.args)):
            self.assertNotIn(secret, value)
        self.assertEqual(client._call.call_count, 1)

    def test_malformed_success_fails_closed_without_retry(self):
        for reply in (None, [], {}, {"status": 1, "message": "ok"},
                      {"status": "true", "message": "ok"}, {"status": True},
                      {"status": True, "message": None}):
            with self.subTest(reply=reply):
                client = Client(reply)
                with self.assertRaises(CartOperationRejected) as raised:
                    client.set_item_quantity(123, 1)
                self.assertEqual(raised.exception.safe_metadata(), {"reason": "cart_response_invalid"})
                self.assertEqual(client._call.call_count, 1)

    def test_no_transport_retry_after_uncertain_mutation(self):
        client = Client()
        client._call.side_effect = TimeoutError("synthetic transport failure")
        with self.assertRaises(TimeoutError):
            client.set_item_quantity(123, 1)
        self.assertEqual(client._call.call_count, 1)

    def test_invalid_identifiers_never_call_transport(self):
        for identifier in (None, True, False, 0, -1, 1.5, "123", 1 << 63):
            for operation in ("read_cart", "merchant_delivery", "remove_item"):
                with self.subTest(identifier=identifier, operation=operation):
                    client = Client()
                    with self.assertRaises(ValueError):
                        getattr(client, operation)(identifier)
                    client._call.assert_not_called()

    def test_invalid_quantities_never_call_transport(self):
        for quantity in (None, True, False, -1, 1.5, "500", MAX_CART_QUANTITY + 1):
            with self.subTest(quantity=quantity):
                client = Client()
                with self.assertRaises(ValueError):
                    client.set_item_quantity(123, quantity)
                client._call.assert_not_called()
        client = Client()
        with self.assertRaises(ValueError):
            client.set_item_quantity(None, 1)
        client._call.assert_not_called()

    def test_unverified_promo_code_never_calls_transport(self):
        for code in (None, True, 0, "SAVE10"):
            client = Client()
            with self.assertRaises(ValueError):
                client.read_cart(5002, promo_code=code)
            client._call.assert_not_called()


if __name__ == "__main__":
    unittest.main()
