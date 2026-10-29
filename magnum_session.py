"""Session and delivery reads verified against MagnumGO Android 4.3.15.

The host supplies ``_call`` and ``_current_phone`` and owns credentials,
transport, request scheduling and refresh persistence. Importing this module
does not read a session or contact Magnum.

Static evidence: session-protocol-evidence.json; APK binaries are not bundled.
"""

import math
import re


SESSION_CONTRACTS = {
    "profile": {
        "method": "GET",
        "path": "/auth/server/api/v1/customers/customer/{phone}",
        "query_keys": (),
        "body_keys": (),
        "path_keys": ("phone",),
        "mutates": False,
        "auth_required": True,
        "evidence": "APK4.3.15:phone source0x8bb16c..0x8bb170; API0x8bb6d8; GET0x8bb784; URL0x5e6b3c",
    },
    "last_delivery_address": {
        "method": "GET",
        "path": "/auth/server/api/v1/customers/locations/last",
        "query_keys": (),
        "body_keys": (),
        "path_keys": (),
        "mutates": False,
        "auth_required": True,
        "evidence": "APK4.3.15:API0x873b0c; auth extra0x873b64..0x873b88; GET0x873b9c; path0x873bc0",
    },
    "delivery_addresses": {
        "method": "GET",
        "path": "/auth/server/api/v1/customers/locations",
        "query_keys": (),
        "body_keys": (),
        "path_keys": (),
        "mutates": False,
        "auth_required": True,
        "evidence": "APK4.3.15:API0x873d54; auth extra0x873dac..0x873dd4; GET0x873de4; path0x873e08",
    },
    "resolve_stores": {
        "method": "GET",
        "path": "/productstore/geo/api/v1/type/all/attributes",
        "query_keys": ("latitude", "longitude"),
        "body_keys": (),
        "path_keys": (),
        "mutates": False,
        "auth_required": False,
        "evidence": "APK4.3.15:API0x8736e4; query0x873720..0x8737ac; GET0x8737f4; path0x873808; no accessToken extra",
    },
    # Registry only. The host refresh provider performs one request and atomically
    # stores both rotated fields. The app sends raw strings including Bearer.
    "refresh_session": {
        "method": "POST",
        "path": "/auth/server/api/v1/security/tokens/refresh",
        "query_keys": (),
        "body_keys": ("refreshToken", "token"),
        "path_keys": (),
        "mutates": True,
        "auth_required": False,
        "evidence": "APK4.3.15:API0x5e4c14; body0x5e4c50..0x5e4c70; source0x8ba874..0x8ba89c; no accessToken extra",
    },
}


def _coordinate(value, name, minimum, maximum):
    # bool is an int subclass; neither bool nor string is an app coordinate.
    if (type(value) not in (int, float) or not minimum <= value <= maximum
            or not math.isfinite(value)):
        raise ValueError("{} must be a finite number between {} and {}.".format(name, minimum, maximum))
    return float(value)


class SessionMethods:
    """Own-account reads. Remote response objects are returned unmodified."""

    def read_profile(self):
        """Read the signed-in account using its login phone, never a supplied ID.

        The APK passes the successful SMS login's phone to this URL, then saves
        the returned Customer.id separately. JWT userId is not this argument.
        The host resolves the phone in memory from its own authenticated session.
        """
        phone = self._current_phone()
        if type(phone) is not str or re.fullmatch(r"7[0-9]{10}", phone) is None:
            # Do not reflect an invalid claim, account identifier or phone.
            raise ValueError("The current session has no valid login phone.")
        return self._call("profile", path_params={"phone": phone})

    def last_delivery_address(self):
        """Read the last saved delivery address without changing it."""
        return self._call("last_delivery_address")

    def delivery_addresses(self):
        """Read the signed-in account's saved delivery addresses."""
        return self._call("delivery_addresses")

    def resolve_stores(self, latitude, longitude):
        """Resolve store attributes for an explicit geographic point."""
        latitude = _coordinate(latitude, "latitude", -90, 90)
        longitude = _coordinate(longitude, "longitude", -180, 180)
        return self._call("resolve_stores", query={"latitude": latitude, "longitude": longitude})
