"""Authenticated MagnumGO client using only APK-verified request contracts.

No retries, background polling, automatic pagination or silent guest login.
The shared transport spaces requests using the shared interval configuration.
"""

from __future__ import annotations

import argparse
import base64
import copy
from dataclasses import replace
import hashlib
import json
import math
from pathlib import Path
import re
import sys
import threading
import time
import urllib.parse

import magnum_api as wire
from magnum_auth import AuthError, AuthSession, _mutation_lock, _session_record, auth_status
from magnum_cart import CartMethods, CartOperationRejected, CART_CONTRACTS
from magnum_catalog import CatalogMethods, CATALOG_CONTRACTS
from magnum_http_policy import RequestDeferred, RequestPolicyUnavailable
from magnum_session import SessionMethods, SESSION_CONTRACTS
from magnum_vault import SecretStore, VaultError


CONTRACTS = {**CATALOG_CONTRACTS, **CART_CONTRACTS, **SESSION_CONTRACTS}
_CACHE_SECONDS = {
    "catalog_categories": 300, "catalog_search_products": 30,
    "catalog_suggest_products": 30, "catalog_list_products": 30,
    "catalog_product_detail": 60, "catalog_product_by_item": 60,
    "profile": 60, "last_delivery_address": 30, "delivery_addresses": 30,
    "resolve_stores": 300, "merchant_delivery": 30,
}


def encode_query(parameters):
    """Dio uses bare keys for null and lowercase booleans."""
    result = []
    for key, value in parameters.items():
        key = urllib.parse.quote(str(key), safe="")
        if value is None:
            result.append(key)
            continue
        if isinstance(value, bool):
            value = "true" if value else "false"
        elif type(value) in (int, float):
            if isinstance(value, float) and not math.isfinite(value):
                raise ValueError("Invalid numeric query value.")
            value = str(value)
        elif not isinstance(value, str):
            raise ValueError("Invalid query value type.")
        if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
            raise ValueError("Invalid query control character.")
        result.append(key + "=" + urllib.parse.quote(value, safe=""))
    return "&".join(result)


def _claims(token):
    # This is an identity-routing hint from an already stored service token.
    # Its claims are never used to authorize an MCP client or verify a login.
    try:
        parts = token.split(".")
        if len(parts) != 3 or any(re.fullmatch(r"[A-Za-z0-9_-]+", part) is None for part in parts):
            raise ValueError

        def reject_constant(_value):
            raise ValueError

        decoded = [base64.b64decode(part + "=" * (-len(part) % 4), altchars=b"-_", validate=True)
                   for part in parts]
        header = json.loads(decoded[0], parse_constant=reject_constant)
        value = json.loads(decoded[1], parse_constant=reject_constant)
        if not isinstance(header, dict) or not isinstance(value, dict):
            raise ValueError
        return value
    except Exception:
        raise AuthError("invalid_response") from None


def _subject_phone(claims):
    subject = claims.get("sub")
    if not isinstance(subject, str) or not re.fullmatch(r"\+?7[0-9]{10}", subject):
        raise AuthError("invalid_response")
    return subject.removeprefix("+")


def safe_result(value):
    """Remove credentials from returned JSON; never interpret server strings."""
    if isinstance(value, dict):
        return {key: ("[REDACTED]" if wire._sensitive_key(key) or key.lower() == "pinhash"
                      else safe_result(item)) for key, item in value.items()}
    if isinstance(value, list):
        return [safe_result(item) for item in value]
    return value


class MagnumAPI(CatalogMethods, CartMethods, SessionMethods):
    def __init__(self, *, store=None, transport=None, clock=None):
        self.store = store if store is not None else SecretStore()
        self.session = AuthSession(self.store)
        self.transport = transport or wire._http_request
        self.clock = clock or time.monotonic
        self._lock = threading.RLock()
        self._cache = {}
        self.last_request = {}

    def __repr__(self):
        return "MagnumAPI(credentials=<OS-encrypted session>)"

    def _current_phone(self):
        return _subject_phone(_claims(self.session.get_access_token()))

    def clear_cache(self):
        with self._lock:
            self._cache.clear()

    def account_scope(self):
        """Opaque cache/operation scope, never a phone number or token."""
        return hashlib.sha256(self._current_phone().encode()).hexdigest()

    def _call(self, name, *, query=None, body=None, path_params=None):
        with self._lock:
            if name not in CONTRACTS:
                raise ValueError("The endpoint has no verified APK contract.")
            contract = CONTRACTS[name]
            query, path_params = query or {}, path_params or {}
            if set(query) != set(contract["query_keys"]) or set(path_params) != set(contract["path_keys"]):
                raise ValueError("Request parameters differ from the verified APK contract.")
            if (body is None and contract["body_keys"]) or (body is not None and set(body) != set(contract["body_keys"])):
                raise ValueError("Request body differs from the verified APK contract.")
            values = {}
            for key, value in path_params.items():
                if key == "phone":
                    if not isinstance(value, str) or not re.fullmatch(r"7[0-9]{10}", value):
                        raise ValueError("Invalid own-account phone.")
                elif type(value) is not int or value <= 0:
                    raise ValueError("Invalid path item ID.")
                values[key] = urllib.parse.quote(str(value), safe="")
            path = contract["path"].format(**values)
            encoded = encode_query(query)
            url = wire.BASE_URL + path + ("?" + encoded if encoded else "")
            headers = {"Accept": "application/json", "Content-Type": "application/json", "X-Client-Version": wire.CLIENT_VERSION}
            scope = "public"
            if contract.get("auth_required", True):
                token = self.session.get_access_token()
                phone = _subject_phone(_claims(token))
                if name == "profile" and path_params.get("phone") != phone:
                    raise AuthError("invalid_response")
                headers["Authorization"] = "Bearer " + token
                scope = hashlib.sha256(phone.encode()).hexdigest()
            ttl = _CACHE_SECONDS.get(name, 0)
            digest = hashlib.sha256(json.dumps([query, path_params], sort_keys=True).encode()).hexdigest()
            cache_key = (name, scope, digest)
            now = self.clock()
            cached = self._cache.get(cache_key)
            if ttl and cached is not None and now - cached[0] < ttl:
                self.last_request = {"contract": name, "cached": True, "age_seconds": round(now - cached[0], 3)}
                return copy.deepcopy(cached[1])
            payload = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8") if body is not None else None
            self.last_request = {"contract": name, "cached": False, "age_seconds": 0}
            try:
                raw = self.transport(contract["method"], url, headers, payload)
            except Exception:
                self.last_request["failed"] = True
                raise
            self.last_request = {"contract": name, "cached": False, "age_seconds": 0}
            try:
                result = json.loads(raw.decode("utf-8-sig")) if raw else None
            except (ValueError, UnicodeError):
                raise wire.MagnumAPIError("The API response is not valid JSON.") from None
            if isinstance(result, dict) and type(result.get("errorCode")) is int and result["errorCode"] != 0:
                failure = wire._http_error(200, raw, request_headers=headers, request_body=payload)
                raise wire.MagnumAPIError("The service rejected the request.",
                                          redacted_response_body=failure.redacted_response_body,
                                          **failure.safe_metadata())
            if contract["mutates"]:
                self._cache.clear()
            elif ttl:
                self._cache[cache_key] = (self.clock(), copy.deepcopy(result))
            return result

    def refresh_session(self):
        """Make one app-equivalent refresh, then atomically replace both tokens."""
        with _mutation_lock():
            record = self.store.read()
            if record is None or record.kind != "user" or not record.refresh_token:
                raise AuthError("needs_login")
            previous_phone = _subject_phone(_claims(record.token))
            response = self._call("refresh_session", body={
                "refreshToken": "Bearer " + record.refresh_token,
                "token": "Bearer " + record.token,
            })
            replacement = _session_record(response, "user")
            claims = _claims(replacement.token)
            expiry = claims.get("exp")
            if (_subject_phone(claims) != previous_phone or type(expiry) not in (int, float)
                    or not time.time() < expiry <= 253402300799 or not math.isfinite(expiry)):
                raise AuthError("invalid_response")
            # SessionRecord stores integer timestamps. NumericDate can contain a
            # fraction; round upward so a validated future expiry stays future.
            replacement = replace(replacement, expires_at=math.ceil(expiry))
            self.store.write(replacement)
            self.clear_cache()
            return auth_status(self.store)

    def delivery_context(self):
        """Mirror the app's coordinate order; return store IDs without address text."""
        address = self.last_delivery_address()
        try:
            coordinates = address["location"]["geometry"]["coordinates"]
            if not isinstance(coordinates, list) or len(coordinates) < 2:
                raise ValueError
            stores = self.resolve_stores(coordinates[0], coordinates[-1])
        except (KeyError, TypeError, ValueError):
            raise ValueError("The saved delivery address has no app-compatible coordinates.") from None
        if not isinstance(stores, dict):
            raise ValueError("The store response is invalid.")
        options = {}
        for kind in ("darkStore", "expressStore", "b2bStore", "corpB2bStore"):
            store = stores.get(kind)
            if isinstance(store, dict) and type(store.get("id")) is int:
                options[kind] = {key: store[key] for key in ("id", "name", "typeId") if key in store}
        return {"stores": options, "default_mode": "main", "platform_id": options.get("darkStore", {}).get("id")}


def main(argv=None):
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("status", "profile-status", "context", "addresses", "refresh"):
        sub.add_parser(name)
    categories = sub.add_parser("categories"); categories.add_argument("--platform-id", type=int, required=True); categories.add_argument("--parent-id", type=int)
    search = sub.add_parser("search"); search.add_argument("--platform-id", type=int, required=True); search.add_argument("--query", required=True); search.add_argument("--page", type=int, default=0)
    suggest = sub.add_parser("suggest"); suggest.add_argument("--query", required=True)
    listing = sub.add_parser("products"); listing.add_argument("--platform-id", type=int, required=True); listing.add_argument("--category-id", type=int, required=True); listing.add_argument("--page", type=int, default=0); listing.add_argument("--order", choices=("ASC", "DESC"), default="DESC")
    product = sub.add_parser("product"); product.add_argument("--item-id", type=int, required=True)
    cart = sub.add_parser("cart"); cart.add_argument("--platform-id", type=int, required=True)
    delivery = sub.add_parser("delivery"); delivery.add_argument("--merchant-id", type=int, required=True)
    quantity = sub.add_parser("set-quantity"); quantity.add_argument("--item-id", type=int, required=True); quantity.add_argument("--quantity", type=int, required=True)
    remove = sub.add_parser("remove"); remove.add_argument("--item-id", type=int, required=True)
    args = parser.parse_args(argv)
    client = MagnumAPI()
    try:
        cmd = args.command
        if cmd == "status": result = auth_status()
        elif cmd == "profile-status":
            profile = client.read_profile(); result = {"authenticated_api_read": True, "customer_id": profile.get("id") if isinstance(profile, dict) else None}
        elif cmd == "context": result = client.delivery_context()
        elif cmd == "addresses": result = client.delivery_addresses()
        elif cmd == "refresh": result = client.refresh_session()
        elif cmd == "categories": result = client.categories(args.parent_id, args.platform_id)
        elif cmd == "search": result = client.search_products(args.query, args.platform_id, args.page)
        elif cmd == "suggest": result = client.suggest_products(args.query)
        elif cmd == "products": result = client.list_products(args.category_id, args.platform_id, args.page, sort_order=args.order)
        elif cmd == "product": result = client.product_detail(args.item_id)
        elif cmd == "cart": result = client.read_cart(args.platform_id)
        elif cmd == "delivery": result = client.merchant_delivery(args.merchant_id)
        elif cmd == "set-quantity": result = client.set_item_quantity(args.item_id, args.quantity)
        else: result = client.remove_item(args.item_id)
        print(json.dumps(safe_result(result), ensure_ascii=False, indent=2))
        return 0
    except (AuthError, wire.MagnumAPIError, RequestDeferred, RequestPolicyUnavailable, VaultError, CartOperationRejected, ValueError) as error:
        details = {"error": type(error).__name__, "message": str(error)}
        if hasattr(error, "safe_metadata"):
            details.update(error.safe_metadata())
        if hasattr(error, "retry_after_seconds") and error.retry_after_seconds is not None:
            details["retry_after_seconds"] = error.retry_after_seconds
        print(json.dumps(details), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
