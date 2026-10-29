"""Offline regression fixtures for requests recovered from APK 4.3.15."""

import pathlib
import json
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from magnum_catalog import CATALOG_CONTRACTS, CatalogMethods, MAX_FILTERS, MAX_ID, MAX_PAGE, MAX_QUERY_LENGTH


class RecordingClient(CatalogMethods):
    def __init__(self):
        self.calls = []
        self.response = {"content": [{"itemId": 42}], "totalElements": 101, "last": False}

    def _call(self, name, *, query, body, path_params):
        self.calls.append((name, query, body, path_params))
        return self.response


class CatalogTests(unittest.TestCase):
    def setUp(self):
        self.client = RecordingClient()

    def assert_call(self, name, query, path_params=None):
        self.assertEqual(self.client.calls, [(name, query, None, path_params or {})])
        contract = CATALOG_CONTRACTS[name]
        self.assertEqual(set(query), set(contract["query_keys"]))
        self.assertEqual(set(path_params or {}), set(contract["path_keys"]))
        self.assertEqual(contract["method"], "GET")
        self.assertFalse(contract["mutates"])
        self.assertEqual(contract["body_keys"], ())

    def test_exported_contracts_match_packaged_static_evidence(self):
        evidence_path = pathlib.Path(__file__).resolve().parents[1] / "catalog-protocol-evidence.json"
        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
        for name, contract in CATALOG_CONTRACTS.items():
            with self.subTest(contract=name):
                verified = evidence["contracts"][name]
                self.assertEqual(contract["method"], verified["method"])
                self.assertEqual(contract["path"], verified["path"])
                self.assertEqual(set(contract["query_keys"]), set(verified["query"]))
                self.assertEqual(set(contract["path_keys"]), set(verified.get("path_parameters", {})))
                self.assertEqual(contract["evidence"], "catalog-protocol-evidence.json#/contracts/" + name)

    def test_categories_include_children_and_preserve_null_parent(self):
        self.client.categories()
        self.assert_call("catalog_categories", {"includeChildNodes": True, "parentId": None, "platformId": 5002})

    def test_subcategories_use_catalog_parent_not_category_name_endpoint(self):
        self.client.categories(parent_id=73, platform_id=5003)
        self.assert_call("catalog_categories", {"includeChildNodes": True, "parentId": 73, "platformId": 5003})
        self.assertEqual(CATALOG_CONTRACTS["catalog_categories"]["path"], "/catalog/client/catalog")

    def test_full_search_uses_page_id_zero_and_twenty_not_page(self):
        response = self.client.search_products("хлеб", platform_id=5002)
        self.assertIs(response, self.client.response)
        self.assert_call("catalog_search_products", {
            "platformId": 5002, "searchWord": "хлеб", "pageId": 0, "pageSize": 20})
        self.assertEqual(CATALOG_CONTRACTS["catalog_search_products"]["path"], "/catalog/client/search/platform/items")

    def test_suggestions_have_no_platform_or_merchant_or_pagination(self):
        self.client.suggest_products("молоко")
        self.assert_call("catalog_suggest_products", {"searchWord": "молоко"})
        self.assertEqual(CATALOG_CONTRACTS["catalog_suggest_products"]["path"], "/catalog/client/search/lean/items")

    def test_category_defaults_and_single_integer_category_id(self):
        self.client.list_products(73, 5002)
        self.assert_call("catalog_list_products", {
            "platformId": 5002, "categoryIds": 73, "sortTypeColumn": "price", "sortOrder": "DESC",
            "pageId": 0, "pageSize": 20, "filterIds": ""})

    def test_category_filters_use_csv_and_page_is_explicit(self):
        self.client.list_products(73, 5002, page=2, sort_order="ASC", filter_ids=[2, 19])
        self.assert_call("catalog_list_products", {
            "platformId": 5002, "categoryIds": 73, "sortTypeColumn": "price", "sortOrder": "ASC",
            "pageId": 2, "pageSize": 20, "filterIds": "2,19"})
        self.assertEqual(CATALOG_CONTRACTS["catalog_list_products"]["path"], "/catalog/client/platformItemV2")

    def test_normal_detail_uses_product_item_id_with_no_platform_query(self):
        product = {"itemId": 42, "availabilityId": 12001, "platformId": 5002}
        self.client.product_detail(item_id=product["itemId"])
        self.assert_call("catalog_product_detail", {}, {"item_id": 42})
        self.assertEqual(CATALOG_CONTRACTS["catalog_product_detail"]["path"], "/catalog/client/platformItem/{item_id}")

    def test_deeplink_detail_is_explicit_and_compatibility_name_calls_once(self):
        self.client.product_detail_from_deeplink(42, 5002)
        self.assert_call("catalog_product_by_item", {"platformId": 5002}, {"item_id": 42})
        self.client.calls.clear()
        self.client.product_by_item(42, 5002)
        self.assert_call("catalog_product_by_item", {"platformId": 5002}, {"item_id": 42})
        self.assertEqual(CATALOG_CONTRACTS["catalog_product_by_item"]["path"], "/catalog/client/platformItem/item/{item_id}")

    def test_invalid_ids_fail_before_request(self):
        for value in (True, False, 0, -1, 1.5, "42", None, MAX_ID + 1):
            for operation in (
                lambda: self.client.categories(platform_id=value),
                lambda: self.client.search_products("хлеб", value),
                lambda: self.client.list_products(value, 5002),
                lambda: self.client.product_detail(value),
                lambda: self.client.product_detail_from_deeplink(value, 5002),
                lambda: self.client.product_detail_from_deeplink(42, value),
                lambda: self.client.product_by_item(value, 5002),
                lambda: self.client.product_by_item(42, value),
            ):
                with self.subTest(value=value, operation=operation), self.assertRaises(ValueError):
                    operation()
            if value is not None:
                with self.subTest(parent_id=value), self.assertRaises(ValueError):
                    self.client.categories(parent_id=value)
        self.assertEqual(self.client.calls, [])

    def test_invalid_query_or_page_fails_before_request(self):
        for query in (None, "", "   ", 12, "a\nb", "x" * (MAX_QUERY_LENGTH + 1)):
            for operation in (lambda: self.client.suggest_products(query),
                              lambda: self.client.search_products(query, 5002)):
                with self.subTest(query=query), self.assertRaises(ValueError):
                    operation()
        for page in (True, -1, MAX_PAGE + 1, "0", 0.5):
            with self.subTest(page=page), self.assertRaises(ValueError):
                self.client.search_products("хлеб", 5002, page=page)
            with self.subTest(page=page), self.assertRaises(ValueError):
                self.client.list_products(73, 5002, page=page)
        self.assertEqual(self.client.calls, [])

    def test_unverified_sort_and_invalid_filters_fail_before_request(self):
        for kwargs in ({"sort_column": "popularity"}, {"sort_order": "desc"},
                       {"filter_ids": "2,19"}, {"filter_ids": [True]},
                       {"filter_ids": [0]}, {"filter_ids": [1] * (MAX_FILTERS + 1)}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                self.client.list_products(73, 5002, **kwargs)
        self.assertEqual(self.client.calls, [])

    def test_calls_are_single_page_with_unmodified_search(self):
        query = "  хлеб & молоко + 10%  "
        self.client.search_products(query, 5002, page=MAX_PAGE)
        self.assertEqual(len(self.client.calls), 1)
        self.assertEqual(self.client.calls[0][1]["searchWord"], query)
        self.assertEqual(self.client.calls[0][1]["pageId"], MAX_PAGE)


if __name__ == "__main__":
    unittest.main()
