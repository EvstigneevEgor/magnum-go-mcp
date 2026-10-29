"""Local, non-secret configuration for MagnumGO request scheduling.

Importing this module does not read configuration or environment variables.
The environment interval overrides the file without reading it. Otherwise,
MAGNUM_CONFIG selects a required file, or magnum.config.json next to this
module is optional. Configuration is loaded when the caller requests it.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import json
import math
import os
from pathlib import Path


DEFAULT_REQUEST_INTERVAL_SECONDS = 0.5
MAX_CONFIG_BYTES = 16 * 1024
_INTERVAL_KEY = "request_interval_seconds"
_ENV_INTERVAL = "MAGNUM_REQUEST_INTERVAL_SECONDS"
_ENV_PATH = "MAGNUM_CONFIG"


class ConfigurationError(ValueError):
    """Fixed diagnostic; never reflects file paths or configuration contents."""

    def __init__(self):
        super().__init__("Invalid MagnumGO configuration.")


def _interval(value):
    if type(value) not in (int, float):
        raise ConfigurationError()
    try:
        value = float(value)
    except (ValueError, OverflowError):
        raise ConfigurationError() from None
    if not math.isfinite(value) or value <= 0:
        raise ConfigurationError()
    return value


@dataclass(frozen=True, slots=True)
class Settings:
    request_interval_seconds: float = DEFAULT_REQUEST_INTERVAL_SECONDS

    def __post_init__(self):
        object.__setattr__(self, _INTERVAL_KEY, _interval(self.request_interval_seconds))


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ConfigurationError()
        result[key] = value
    return result


def _reject_constant(_value):
    raise ConfigurationError()


def load_settings(*, environ=None, default_path=None):
    """Return immutable settings, in order: environment, JSON file, defaults.

    A valid MAGNUM_REQUEST_INTERVAL_SECONDS skips file access entirely. JSON
    accepts only request_interval_seconds as a finite positive number. An
    explicit MAGNUM_CONFIG path must exist; the default file may be absent.
    Environment values and errors are never included in the diagnostic.
    """
    environ = os.environ if environ is None else environ
    if not isinstance(environ, Mapping):
        raise ConfigurationError()
    if _ENV_INTERVAL in environ:
        raw = environ[_ENV_INTERVAL]
        if not isinstance(raw, str) or not raw.strip():
            raise ConfigurationError()
        try:
            interval = float(raw)
        except (ValueError, OverflowError):
            raise ConfigurationError() from None
        return Settings(_interval(interval))

    explicit = _ENV_PATH in environ
    selected = environ[_ENV_PATH] if explicit else default_path
    if explicit and (not isinstance(selected, str) or not selected.strip()):
        raise ConfigurationError()
    try:
        path = Path(selected) if selected is not None else Path(__file__).with_name("magnum.config.json")
        with path.open("rb") as source:
            raw = source.read(MAX_CONFIG_BYTES + 1)
    except FileNotFoundError:
        if not explicit:
            return Settings()
        raise ConfigurationError() from None
    except (OSError, ValueError, TypeError):
        raise ConfigurationError() from None
    if len(raw) > MAX_CONFIG_BYTES:
        raise ConfigurationError()
    try:
        data = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=_object,
                          parse_constant=_reject_constant)
    except (ValueError, UnicodeError, RecursionError):
        raise ConfigurationError() from None
    if not isinstance(data, dict) or set(data) - {_INTERVAL_KEY}:
        raise ConfigurationError()
    return Settings(data.get(_INTERVAL_KEY, DEFAULT_REQUEST_INTERVAL_SECONDS))
