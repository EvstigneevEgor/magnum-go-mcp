"""Catalog requests verified against MagnumGO 4.3.15 ARM64 application code.

This mixin delegates one request to ``_call``; it never retries or paginates.
Page and search bounds are local input limits, not claims about server limits.
"""

from __future__ import annotations


PAGE_SIZE = 20
MAX_PAGE = 10000
MAX_QUERY_LENGTH = 256
MAX_FILTERS = 100
MAX_ID = (1 << 63) - 1
_EVIDENCE = "catalog-protocol-evidence.json#/contracts/"


def _contract(name, path, query_keys=(), path_keys=()):
    return {
        "method": "GET", "path": path, "query_keys": tuple(query_keys),
        "body_keys": (), "path_keys": tuple(path_keys), "mutates": False,
        "evidence": _EVIDENCE + name,
    }


CATALOG_CONTRACTS = {
    "catalog_categories": _contract(
        "catalog_categories", "/catalog/client/catalog",
        ("includeChildNodes", "parentId", "platformId")),
    "catalog_search_products": _contract(
        "catalog_search_products", "/catalog/client/search/platform/items",
        ("platformId", "searchWord", "pageId", "pageSize")),
    "catalog_suggest_products": _contract(
        "catalog_suggest_products", "/catalog/client/search/lean/items", ("searchWord",)),
    "catalog_list_products": _contract(
        "catalog_list_products", "/catalog/client/platformItemV2",
        ("platformId", "categoryIds", "sortTypeColumn", "sortOrder", "pageId", "pageSize", "filterIds")),
    "catalog_product_detail": _contract(
        "catalog_product_detail", "/catalog/client/platformItem/{item_id}",
        path_keys=("item_id",)),
    "catalog_product_by_item": _contract(
        "catalog_product_by_item", "/catalog/client/platformItem/item/{item_id}",
        ("platformId",), ("item_id",)),
}


def _positive_id(value, name):
    if type(value) is not int or not 1 <= value <= MAX_ID:
        raise ValueError("{} must be a positive integer ID.".format(name))
    return value


def _page(value):
    if type(value) is not int or not 0 <= value <= MAX_PAGE:
        raise ValueError("page must be an integer from 0 to {}.".format(MAX_PAGE))
    return value


def _query(value):
    if (not isinstance(value, str) or not value.strip()
            or len(value) > MAX_QUERY_LENGTH
            or any(ord(character) < 32 or ord(character) == 127 for character in value)):
        raise ValueError("query must contain 1 to {} characters without control characters.".format(MAX_QUERY_LENGTH))
    return value


class CatalogMethods:
    """Methods return the original JSON response, including paging metadata."""

    def categories(self, parent_id=None, platform_id=5002):
        """Read root categories or children of parent_id, including nested nodes."""
        if parent_id is not None:
            _positive_id(parent_id, "parent_id")
        return self._call("catalog_categories", query={
            "includeChildNodes": True,
            "parentId": parent_id,
            "platformId": _positive_id(platform_id, "platform_id"),
        }, body=None, path_params={})

    def search_products(self, query, platform_id, page=0):
        """Read one zero-based page of 20 products matching a search term."""
        return self._call("catalog_search_products", query={
            "platformId": _positive_id(platform_id, "platform_id"),
            "searchWord": _query(query), "pageId": _page(page), "pageSize": PAGE_SIZE,
        }, body=None, path_params={})

    def suggest_products(self, query):
        """Read search suggestions; the app sends only searchWord."""
        return self._call("catalog_suggest_products", query={
            "searchWord": _query(query),
        }, body=None, path_params={})

    def list_products(self, category_id, platform_id, page=0,
                      sort_column="price", sort_order="DESC", filter_ids=()):
        """Read one category page; only the confirmed price sort is exposed."""
        if sort_column != "price":
            raise ValueError("sort_column must be price.")
        if not isinstance(sort_order, str) or sort_order not in ("ASC", "DESC"):
            raise ValueError("sort_order must be ASC or DESC.")
        if not isinstance(filter_ids, (list, tuple)) or len(filter_ids) > MAX_FILTERS:
            raise ValueError("filter_ids must be a list or tuple of at most {} IDs.".format(MAX_FILTERS))
        filters = ",".join(str(_positive_id(value, "filter_id")) for value in filter_ids)
        return self._call("catalog_list_products", query={
            "platformId": _positive_id(platform_id, "platform_id"),
            "categoryIds": _positive_id(category_id, "category_id"),
            "sortTypeColumn": sort_column, "sortOrder": sort_order,
            "pageId": _page(page), "pageSize": PAGE_SIZE, "filterIds": filters,
        }, body=None, path_params={})

    def product_detail(self, item_id):
        """Open Product.itemId exactly as normal search/catalog navigation does.

        The app passes the result object's itemId to this path despite the
        endpoint's platformItem name. It sends no platformId query parameter.
        availabilityId is a separate response field and is not substituted.
        """
        return self._call("catalog_product_detail", query={}, body=None,
                          path_params={"item_id": _positive_id(item_id, "item_id")})

    def product_detail_from_deeplink(self, item_id, platform_id):
        """Use the app's distinct deeplink detail branch for an explicit URL ID.

        Normal catalog/search results must use product_detail(item_id).
        This branch is statically verified but is not a fallback on API errors.
        """
        return self._call("catalog_product_by_item", query={
            "platformId": _positive_id(platform_id, "platform_id"),
        }, body=None, path_params={"item_id": _positive_id(item_id, "item_id")})

    def product_by_item(self, item_id, platform_id):
        """Compatibility name for the explicit deeplink branch, without retry."""
        return self.product_detail_from_deeplink(item_id, platform_id)
