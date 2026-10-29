"""Cart methods confirmed in MagnumGO 4.3.15, with no direct transport.

The host client supplies ``_call`` and owns authorization, rate limiting, caching
and the no-retry policy. Importing this module never accesses a session or API.
Evidence: cart-protocol-evidence.json (addresses refer to the analyzed APK).
"""


_MAX_ID = (1 << 63) - 1
# A client guard against accidental huge numbers, not a server/unit limit.
MAX_CART_QUANTITY = 100_000


CART_CONTRACTS = {
    "cart": {
        "method": "GET",
        "path": "/cart/v2/bymerchant",
        "query_keys": ("promoCode", "platformId"),
        "body_keys": (),
        "path_keys": (),
        "mutates": False,
        "evidence": "APK4.3.15:0x8a6aec; query0x8a6b18..0x8a6b6c; GET/path0x8a6be0..0x8a6c1c",
    },
    "merchant_delivery": {
        "method": "GET",
        "path": "/cart/merchant",
        "query_keys": ("merchantId",),
        "body_keys": (),
        "path_keys": (),
        "mutates": False,
        "evidence": "APK4.3.15:0x8a65a4; query0x8a65d0..0x8a6610; GET/path0x8a6684..0x8a66c0",
    },
    "cart_set_item": {
        "method": "PUT",
        "path": "/cart/v2/item",
        "query_keys": (),
        "body_keys": ("itemId", "quantity"),
        "path_keys": (),
        "mutates": True,
        "evidence": "APK4.3.15:0x8b2840; JSON map0x8b2870..0x8b28d8; PUT/path/data0x8b294c..0x8b2984",
    },
    "cart_remove_item": {
        "method": "DELETE",
        "path": "/cart/item",
        "query_keys": (),
        "body_keys": ("itemId",),
        "path_keys": (),
        "mutates": True,
        "evidence": "APK4.3.15:0x8a6d94; JSON map0x8a6df0..0x8a6e30; DELETE/path/data0x8a6e70..0x8a6ea8",
    },
}


class CartOperationRejected(RuntimeError):
    """Fixed diagnostics for a parsed negative/malformed operation response.

    A remote message is untrusted and can reflect credentials. Do not retain it
    in the exception, its arguments or metadata.
    """

    def __init__(self, *, invalid_response=False):
        self.reason = "cart_response_invalid" if invalid_response else "cart_rejected"
        super().__init__(
            "Magnum returned an invalid cart operation response."
            if invalid_response else "Magnum rejected the cart operation."
        )

    def safe_metadata(self):
        return {"reason": self.reason}


def _integer(value, name, *, minimum=1, maximum=_MAX_ID):
    # bool subclasses int in Python but is not an app request integer.
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError("{} must be an integer between {} and {}.".format(name, minimum, maximum))
    return value


class CartMethods:
    """Mixin; the host enforces its own explicit cart-write authorization."""

    def read_cart(self, platform_id, promo_code=""):
        """Read cart including server fees, limits and unavailable items."""
        _integer(platform_id, "platform_id")
        # Only the app's empty value has been verified for this API method.
        if type(promo_code) is not str or promo_code != "":
            raise ValueError("Only the app's verified empty promo_code is supported.")
        return self._call("cart", query={"promoCode": "", "platformId": platform_id})

    def merchant_delivery(self, merchant_id):
        """Read ShopDeliverySum; this is distinct from the basket item list."""
        _integer(merchant_id, "merchant_id")
        return self._call("merchant_delivery", query={"merchantId": merchant_id})

    def set_item_quantity(self, item_id, quantity):
        """Add/update the explicit SKU with an absolute API-unit quantity.

        Use the product's measureUnit.step and unit data; this method does not
        infer pieces, kilograms or a conversion. A first add uses the same PUT.
        The app routes zero to DELETE rather than sending PUT quantity=0.
        """
        _integer(item_id, "item_id")
        _integer(quantity, "quantity", minimum=0, maximum=MAX_CART_QUANTITY)
        if quantity == 0:
            return self.remove_item(item_id)
        reply = self._call("cart_set_item", body={"itemId": item_id, "quantity": quantity})
        # PutCartResponse.fromJson is strict bool/String, and the app checks
        # status after HTTP success. Do not coerce strings/numbers to bool.
        if (not isinstance(reply, dict) or type(reply.get("status")) is not bool
                or type(reply.get("message")) is not str):
            raise CartOperationRejected(invalid_response=True)
        if reply["status"] is not True:
            raise CartOperationRejected()
        # Only the two verified fields; message is service text, never code.
        return {"status": True, "message": reply["message"]}

    def remove_item(self, item_id):
        """Delete the explicit SKU using the app's JSON DELETE body."""
        _integer(item_id, "item_id")
        self._call("cart_remove_item", body={"itemId": item_id})
        # Like the app repository0x8a6d24: successful HTTP completion is enough;
        # no response body is assumed, so HTTP204 can also be represented.
        return {"status": True}
