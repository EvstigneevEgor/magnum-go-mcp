"""MCP boundaries with a memory-only API; no network, vault, prompts or login.

The SDK-dependent tests are skipped when the required MCP SDK is unavailable.
"""

from contextlib import contextmanager
import copy
import hashlib
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
if importlib.util.find_spec("mcp") is None:
    tools = None
else:
    import magnum_mcp as tools


SCOPE_A = hashlib.sha256(b"synthetic-account-a").hexdigest()
SCOPE_B = hashlib.sha256(b"synthetic-account-b").hexdigest()
SECRET = "synthetic-secret-must-never-escape"


class MemoryAPI:
    def __init__(self):
        self.cart = {"id": 1, "availableItems": [{"itemId": 77, "quantity": 1}],
                     "deletedItems": [], "packagingPrice": 100}
        self.scope = SCOPE_A
        self.calls = []
        self.last_request = {}
        self.timeout_after_write = False
        self.readback_failure = False
        self.clamp_quantity = False
        self.unknown_readback = False
        self.reads = 0

    def metadata(self, contract, cached=False):
        self.last_request = {"contract": contract, "cached": cached,
                             "age_seconds": 0, "token": SECRET}

    def account_scope(self):
        self.calls.append(("scope",))
        return self.scope

    def read_cart(self, platform_id):
        self.calls.append(("read", platform_id))
        self.reads += 1
        self.metadata("cart")
        if self.readback_failure and self.reads >= 2:
            raise TimeoutError(SECRET)
        if self.unknown_readback and self.reads >= 2:
            return {"unknown": "shape"}
        return copy.deepcopy(self.cart)

    def set_item_quantity(self, item_id, quantity):
        self.calls.append(("set", item_id, quantity))
        target = quantity + 1 if self.clamp_quantity else quantity
        self.cart["availableItems"] = [{"itemId": item_id, "quantity": target}]
        self.metadata("cart_set_item")
        if self.timeout_after_write:
            raise TimeoutError(SECRET)
        return {"status": True, "message": "ok"}

    def remove_item(self, item_id):
        self.calls.append(("remove", item_id))
        self.cart["availableItems"] = [row for row in self.cart["availableItems"] if row["itemId"] != item_id]
        self.metadata("cart_remove_item")
        return {"status": True}

    def read_profile(self):
        self.calls.append(("profile",))
        self.metadata("profile", cached=True)
        return {"id": 1234, "name": "synthetic-private-name", "phone": "+70000000000", "token": SECRET}

    def delivery_context(self):
        self.calls.append(("context",))
        self.metadata("resolve_stores")
        return {"platform_id": 5001, "stores": {"darkStore": {"id": 5001}}}

    def categories(self, **kwargs):
        self.calls.append(("categories", kwargs))
        self.metadata("catalog_categories", cached=True)
        return [{"id": 12, "name": "bread", "children": [{"id": 13, "name": "rolls"}]}]

    def search_products(self, query, platform_id, page):
        self.calls.append(("search", query, platform_id, page))
        self.metadata("catalog_search_products")
        return {"content": [{"itemId": 77, "platformId": platform_id,
                             "name": "bread", "price": 35000,
                             "measureUnit": {"step": 1, "nameML": {"ru": "шт"}},
                             "discount": {"percent": 5}, "itemLeftovers": 8,
                             "descr": "large omitted text", "token": SECRET}],
                "totalPages": 7, "number": page, "last": False}

    def list_products(self, *args, **kwargs):
        self.calls.append(("list", args, kwargs))
        self.metadata("catalog_list_products")
        return {"content": [], "totalElements": 0}

    def suggest_products(self, query):
        self.calls.append(("suggest", query))
        self.metadata("catalog_suggest_products")
        return [{"itemId": 77, "name": "bread", "descr": "omit"}]

    def product_detail(self, item_id):
        self.calls.append(("product", item_id))
        self.metadata("catalog_product_detail")
        return {"itemId": item_id, "name": "bread", "price": 35000}

    def merchant_delivery(self, merchant_id):
        self.calls.append(("delivery", merchant_id))
        self.metadata("merchant_delivery")
        return {"deliveryPrice": 10000, "token": SECRET}

    def refresh_session(self):
        self.calls.append(("refresh",))
        self.metadata("refresh_session")
        return {"state": "ready_user", "token": SECRET}


@unittest.skipIf(tools is None, "MCP SDK is not installed")
class MCPToolTests(unittest.TestCase):
    def setUp(self):
        self.api = MemoryAPI()
        self.lock_depth = 0
        self.lock_entries = 0

        @contextmanager
        def fake_lock():
            self.lock_entries += 1
            self.lock_depth += 1
            try:
                yield
            finally:
                self.lock_depth -= 1

        patches = [patch.object(tools, "_api_instance", self.api),
                   patch.object(tools, "_operations", {}),
                   patch.object(tools._auth, "_mutation_lock", side_effect=fake_lock)]
        for item in patches:
            item.start()
            self.addCleanup(item.stop)

    def revision(self, platform_id=5001):
        return tools._cart_revision(self.api.cart, self.api.scope, platform_id)

    def writes(self):
        return [call for call in self.api.calls if call[0] in ("set", "remove")]

    def test_profile_status_has_no_pii_or_account_identifier(self):
        result = tools.profile_status()
        self.assertTrue(result["ok"])
        self.assertEqual(result["data"], {"authenticated_api_read": True, "profile_available": True})
        self.assertTrue(result["request"]["cached"])
        for private in (SECRET, "synthetic-private-name", "+70000000000", "1234"):
            self.assertNotIn(private, repr(result))

    def test_products_keep_pagination_and_explicit_raw_price(self):
        result = tools.search("bread", 5001, page=2)
        self.assertTrue(result["ok"])
        data = result["data"]
        self.assertEqual((data["totalPages"], data["number"], data["last"]), (7, 2, False))
        product = data["content"][0]
        self.assertEqual(product["price_raw"], 35000)
        self.assertEqual(product["price_kzt"], "350")
        self.assertEqual(product["currency"], "₸")
        self.assertNotIn("price", product)
        self.assertEqual(product["measureUnit"], {"step": 1, "nameML": {"ru": "шт"}})
        self.assertEqual(product["discount"], {"percent": 5})
        self.assertEqual(product["itemLeftovers"], 8)
        self.assertNotIn("descr", product)
        self.assertNotIn(SECRET, repr(result))
        self.assertEqual(self.api.calls, [("search", "bread", 5001, 2)])

    def test_price_conversion_preserves_decimal_amount_and_checks_finiteness(self):
        self.assertEqual(tools._price_kzt(1), "0.01")
        self.assertEqual(tools._price_kzt(35000), "350")
        self.assertEqual(tools._price_kzt(35001), "350.01")
        for invalid in (None, True, False, "35000", float("inf"), float("nan")):
            self.assertIsNone(tools._price_kzt(invalid))

    def test_read_wrappers_call_only_selected_method_and_keep_cache_metadata(self):
        result = tools.categories(5001, parent_id=12)
        self.assertTrue(result["request"]["cached"])
        self.assertEqual(result["data"][0]["children"][0]["id"], 13)
        tools.delivery_context()
        tools.list_products(12, 5001, page=1, filter_ids=[5])
        tools.suggest("bread")
        tools.product(77)
        delivery = tools.merchant_delivery(5001)
        self.assertEqual([call[0] for call in self.api.calls],
                         ["categories", "context", "list", "suggest", "product", "delivery"])
        self.assertEqual(self.writes(), [])
        self.assertNotIn(SECRET, repr(delivery))

    def test_product_uses_primary_detail_with_item_id_and_no_platform_argument(self):
        result = tools.product(77)
        self.assertEqual(self.api.calls, [("product", 77)])
        self.assertEqual(result["request"]["contract"], "catalog_product_detail")
        self.assertEqual(result["data"]["itemId"], 77)
        self.assertEqual(result["data"]["price_kzt"], "350")
        self.assertFalse(hasattr(tools, "product_by_item"))

    def test_cart_read_preserves_raw_cart_fields_and_stable_secret_free_revision(self):
        self.api.cart["token"] = SECRET
        result = tools.read_cart(5001)
        self.assertTrue(result["ok"])
        self.assertEqual(result["data"]["packagingPrice"], 100)
        self.assertRegex(result["revision"], r"^[0-9a-f]{64}$")
        before = result["revision"]
        self.api.cart["token"] = "a different synthetic token"
        self.api.cart["phone"] = "+70000000000"
        self.api.cart["pinHash"] = "another synthetic secret"
        self.assertEqual(before, self.revision())
        reordered = dict(reversed(list(self.api.cart.items())))
        self.assertEqual(before, tools._cart_revision(reordered, self.api.scope, 5001))
        self.assertNotIn(SECRET, repr(result))

    def test_success_checks_fresh_revision_then_writes_and_reads_back_once(self):
        initial = self.revision()
        original_read = self.api.read_cart
        original_write = self.api.set_item_quantity

        def read_under_lock(platform_id):
            self.assertEqual(self.lock_depth, 1)
            return original_read(platform_id)

        def write_under_lock(item_id, quantity):
            self.assertEqual(self.lock_depth, 1)
            # The operation is already claimed before the mutation begins.
            self.assertIn((SCOPE_A, "operation-0001"), tools._operations)
            return original_write(item_id, quantity)

        with patch.object(self.api, "read_cart", side_effect=read_under_lock), patch.object(
                self.api, "set_item_quantity", side_effect=write_under_lock):
            result = tools.set_cart_quantity(5001, 77, 2, initial, "operation-0001")
        self.assertTrue(result["ok"])
        self.assertEqual(result["outcome"], "confirmed")
        self.assertEqual(result["state"], "completed")
        self.assertFalse(result["needs_read"])
        self.assertNotEqual(result["revision"], initial)
        self.assertEqual(self.api.calls, [("scope",), ("read", 5001), ("set", 77, 2), ("read", 5001)])
        self.assertEqual(self.lock_entries, 1)
        self.assertEqual(self.lock_depth, 0)

    def test_stale_revision_does_not_send_mutation(self):
        initial = self.revision()
        self.api.cart["packagingPrice"] = 200
        result = tools.set_cart_quantity(5001, 77, 2, initial, "operation-0002")
        self.assertEqual(result["state"], "revision_conflict")
        self.assertTrue(result["needs_read"])
        self.assertNotEqual(result["revision"], initial)
        self.assertEqual(self.writes(), [])
        self.assertEqual(tools._operations, {})

    def test_same_empty_cart_revision_cannot_cross_account_or_platform(self):
        self.api.cart = {"availableItems": [], "deletedItems": []}
        original = self.revision()
        self.api.scope = SCOPE_B
        result = tools.set_cart_quantity(5001, 77, 1, original, "operation-account-switch")
        self.assertEqual(result["state"], "revision_conflict")
        self.api.scope = SCOPE_A
        result = tools.set_cart_quantity(5002, 77, 1, original, "operation-store-switch")
        self.assertEqual(result["state"], "revision_conflict")
        self.assertEqual(self.writes(), [])

    def test_read_rejects_a_concurrent_account_change(self):
        with patch.object(self.api, "account_scope", side_effect=[SCOPE_A, SCOPE_B]):
            result = tools.read_cart(5001)
        self.assertFalse(result["ok"])
        self.assertNotIn("revision", result)

    def test_same_operation_id_returns_record_without_fresh_read_or_second_write(self):
        initial = self.revision()
        first = tools.set_cart_quantity(5001, 77, 2, initial, "operation-0003")
        before = list(self.api.calls)
        second = tools.set_cart_quantity(5001, 77, 2, initial, "operation-0003")
        self.assertTrue(second["replayed"])
        self.assertEqual(second["revision"], first["revision"])
        self.assertEqual(self.api.calls, before + [("scope",)])
        self.assertEqual(len(self.writes()), 1)

    def test_reusing_operation_id_with_different_parameters_is_rejected(self):
        initial = self.revision()
        tools.set_cart_quantity(5001, 77, 2, initial, "operation-0004")
        result = tools.set_cart_quantity(5001, 77, 3, initial, "operation-0004")
        self.assertEqual(result["state"], "operation_id_conflict")
        self.assertEqual(len(self.writes()), 1)
        self.assertEqual(self.api.reads, 2)

    def test_timeout_after_server_applied_write_remains_uncertain_and_never_replays(self):
        initial = self.revision()
        self.api.timeout_after_write = True
        first = tools.set_cart_quantity(5001, 77, 2, initial, "operation-0005")
        self.assertEqual(first["state"], "uncertain")
        self.assertTrue(first["needs_read"])
        self.assertNotIn(SECRET, repr(first))
        self.assertEqual(self.api.cart["availableItems"][0]["quantity"], 2)
        result = tools.set_cart_quantity(5001, 77, 2, initial, "operation-0005")
        self.assertEqual(result["state"], "uncertain")
        self.assertTrue(result["replayed"])
        self.assertEqual(len(self.writes()), 1)
        self.assertEqual(self.api.reads, 1)

    def test_readback_failure_or_unexpected_quantity_is_unverified_without_retry(self):
        for setting in ("readback_failure", "clamp_quantity", "unknown_readback"):
            with self.subTest(setting=setting):
                self.api = MemoryAPI()
                setattr(self.api, setting, True)
                with patch.object(tools, "_api_instance", self.api), patch.object(tools, "_operations", {}):
                    result = tools.set_cart_quantity(5001, 77, 2, self.revision(), "operation-0006")
                    self.assertEqual(result["state"], "needs_read")
                    self.assertEqual(result["outcome"], "unverified")
                    self.assertEqual(len(self.writes()), 1)
                    self.assertEqual(self.api.reads, 2)
                    self.assertNotIn(SECRET, repr(result))

    def test_remove_uses_zero_and_confirms_absence_in_both_cart_lists(self):
        result = tools.remove_cart_item(5001, 77, 0, self.revision(), "operation-0007")
        self.assertEqual(result["outcome"], "confirmed")
        self.assertEqual(self.writes(), [("remove", 77)])
        self.assertEqual(self.api.reads, 2)
        self.assertFalse(tools._confirmed_quantity({"availableItems": [], "deletedItems": [{"itemId": 77}]}, 77, 0))
        self.assertFalse(tools._confirmed_quantity({"availableItems": [], "deletedItems": [{}]}, 77, 0))

    def test_zero_set_quantity_also_uses_delete(self):
        result = tools.set_cart_quantity(5001, 77, 0, self.revision(), "operation-0008")
        self.assertTrue(result["ok"])
        self.assertEqual(self.writes(), [("remove", 77)])

    def test_operation_scope_changes_with_account_without_storing_phone(self):
        initial = self.revision()
        tools.set_cart_quantity(5001, 77, 2, initial, "operation-0009")
        self.api.scope = SCOPE_B
        second_revision = self.revision()
        result = tools.set_cart_quantity(5001, 77, 3, second_revision, "operation-0009")
        self.assertTrue(result["ok"])
        self.assertEqual(len(self.writes()), 2)
        self.assertEqual({key[0] for key in tools._operations}, {SCOPE_A, SCOPE_B})

    def test_unsafe_mutation_arguments_never_open_auth_lock_or_call_api(self):
        valid = [5001, 77, 2, self.revision(), "operation-0010"]
        for index, bad in ((0, True), (0, 0), (1, -1), (2, True), (2, 1.5),
                           (2, -1), (2, 100001), (3, "not a revision"), (4, "short"),
                           (4, "operation?unsafe"), (4, "x" * 81)):
            with self.subTest(index=index, bad=bad):
                arguments = list(valid)
                arguments[index] = bad
                result = tools.set_cart_quantity(*arguments)
                self.assertFalse(result["ok"])
        result = tools.remove_cart_item(5001, 77, 1, self.revision(), "operation-0011")
        self.assertFalse(result["ok"])
        self.assertEqual(self.api.calls, [])
        self.assertEqual(self.lock_entries, 0)

    def test_capacity_does_not_evict_ids_and_allow_duplicate_mutations(self):
        with patch.object(tools, "_MAX_OPERATIONS", 1):
            tools.set_cart_quantity(5001, 77, 2, self.revision(), "operation-0012")
            result = tools.set_cart_quantity(5001, 77, 3, self.revision(), "operation-0013")
        self.assertEqual(result["state"], "operation_capacity_reached")
        self.assertEqual(len(self.writes()), 1)
        self.assertEqual(len(tools._operations), 1)

    def test_refresh_does_not_double_acquire_auth_lock_and_redacts_tokens(self):
        result = tools.refresh_session()
        self.assertTrue(result["ok"])
        self.assertEqual(self.api.calls, [("refresh",)])
        self.assertEqual(self.lock_entries, 0)
        self.assertNotIn(SECRET, repr(result))

    def test_untrusted_exception_details_never_escape_error_envelope(self):
        from magnum_api import MagnumAPIError
        error = MagnumAPIError(SECRET, http_status=400, service_error_code=-1,
                               redacted_response_body=SECRET)
        with patch.object(self.api, "merchant_delivery", side_effect=error):
            result = tools.merchant_delivery(5001)
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"]["http_status"], 400)
        self.assertEqual(result["error"]["service_error_code"], -1)
        self.assertNotIn(SECRET, repr(result))
        with patch.object(self.api, "merchant_delivery", side_effect=RuntimeError(SECRET)):
            result = tools.merchant_delivery(5001)
        self.assertEqual(result, {"ok": False, "error": {"code": "internal_error"}})


if __name__ == "__main__":
    unittest.main()
