"""Configuration regression tests; no vault, network or real deployment config."""

from dataclasses import FrozenInstanceError
import importlib.util
import io
import pathlib
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import magnum_config as config


class ConfigTests(unittest.TestCase):
    def read(self, raw, *, environ=None):
        with patch.object(config.Path, "open", return_value=io.BytesIO(raw)):
            return config.load_settings(environ={} if environ is None else environ,
                                        default_path="synthetic-config.json")

    def assert_invalid(self, operation):
        with self.assertRaises(config.ConfigurationError) as caught:
            operation()
        self.assertEqual(str(caught.exception), "Invalid MagnumGO configuration.")
        self.assertNotIn("synthetic-private", repr(caught.exception))

    def test_missing_optional_file_uses_default(self):
        with patch.object(config.Path, "open", side_effect=FileNotFoundError()):
            settings = config.load_settings(environ={}, default_path="absent.json")
        self.assertEqual(settings.request_interval_seconds, 0.5)

    def test_default_path_is_next_to_module_not_working_directory(self):
        with patch.object(config.Path, "open", autospec=True, side_effect=FileNotFoundError()) as opened:
            config.load_settings(environ={})
        self.assertEqual(opened.call_args.args[0], pathlib.Path(config.__file__).with_name("magnum.config.json"))

    def test_explicit_file_is_required_and_diagnostics_hide_path(self):
        with patch.object(config.Path, "open", side_effect=FileNotFoundError("synthetic-private-error")):
            self.assert_invalid(lambda: config.load_settings(environ={"MAGNUM_CONFIG": "synthetic-private-path"}))

    def test_explicit_path_is_used(self):
        with patch.object(config.Path, "open", autospec=True, return_value=io.BytesIO(b'{"request_interval_seconds":1.25}')) as opened:
            settings = config.load_settings(environ={"MAGNUM_CONFIG": "custom.json"})
        self.assertEqual(opened.call_args.args[0], pathlib.Path("custom.json"))
        self.assertEqual(settings.request_interval_seconds, 1.25)

    def test_valid_json_numeric_intervals_include_values_below_old_floor(self):
        for value in (b"0.125", b"0.5", b"2", b"1e-2"):
            with self.subTest(value=value):
                result = self.read(b'{"request_interval_seconds":' + value + b'}')
                self.assertEqual(result.request_interval_seconds, float(value))
                self.assertIs(type(result.request_interval_seconds), float)

    def test_empty_object_and_utf8_bom_are_accepted(self):
        self.assertEqual(self.read(b'{}'), config.Settings())
        self.assertEqual(self.read(b'\xef\xbb\xbf{"request_interval_seconds":0.75}').request_interval_seconds, 0.75)

    def test_environment_interval_has_priority_and_skips_all_file_access(self):
        with patch.object(config.Path, "open", side_effect=AssertionError("File must not be read")):
            result = config.load_settings(environ={"MAGNUM_REQUEST_INTERVAL_SECONDS": "0.25",
                                                   "MAGNUM_CONFIG": "missing-private.json"})
        self.assertEqual(result.request_interval_seconds, 0.25)

    def test_environment_rejects_invalid_values_without_file_fallback(self):
        for value in ("", " ", "NaN", "Infinity", "-inf", "0", "-0.5", "synthetic-private", "1e999", None, True, 0.5):
            with self.subTest(value=value), patch.object(config.Path, "open", side_effect=AssertionError("No fallback")):
                self.assert_invalid(lambda: config.load_settings(environ={"MAGNUM_REQUEST_INTERVAL_SECONDS": value}))

    def test_environment_accepts_surrounding_whitespace(self):
        self.assertEqual(config.load_settings(environ={"MAGNUM_REQUEST_INTERVAL_SECONDS": " 0.75 "}).request_interval_seconds, 0.75)

    def test_bad_json_types_keys_duplicates_and_nonfinite_values_fail_closed(self):
        cases = (
            b"not-json-synthetic-private", b"null", b"[]", b"true", b"1", b'"synthetic-private"',
            b'{"unknown":"synthetic-private"}', b'{"request_interval_seconds":true}',
            b'{"request_interval_seconds":null}', b'{"request_interval_seconds":"0.5"}',
            b'{"request_interval_seconds":0}', b'{"request_interval_seconds":-1}',
            b'{"request_interval_seconds":NaN}', b'{"request_interval_seconds":Infinity}',
            b'{"request_interval_seconds":1e999}',
            b'{"request_interval_seconds":0.5,"request_interval_seconds":1}',
            b'{"request_interval_seconds":{}}', b'\xff',
        )
        for raw in cases:
            with self.subTest(raw=raw):
                self.assert_invalid(lambda: self.read(raw))

    def test_file_read_is_bounded_and_oversized_file_rejected(self):
        stream = io.BytesIO(b" " * (config.MAX_CONFIG_BYTES * 2))
        with patch.object(config.Path, "open", return_value=stream), patch.object(stream, "read", wraps=stream.read) as read:
            self.assert_invalid(lambda: config.load_settings(environ={}))
        read.assert_called_once_with(config.MAX_CONFIG_BYTES + 1)

    def test_import_reads_neither_config_file_nor_environment(self):
        class ForbiddenEnvironment(dict):
            def __contains__(self, _key):
                raise AssertionError("Import must not inspect environment")

            def get(self, *_args):
                raise AssertionError("Import must not inspect environment")

        name = "_magnum_config_import_probe"
        spec = importlib.util.spec_from_file_location(name, config.__file__)
        module = importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules, {name: module}), patch.object(config.os, "environ", ForbiddenEnvironment()), patch.object(config.Path, "open", side_effect=AssertionError("Import must not read config")):
            spec.loader.exec_module(module)
        self.assertEqual(module.Settings().request_interval_seconds, 0.5)

    def test_unreadable_files_fail_without_backend_details(self):
        for error in (PermissionError("synthetic-private"), IsADirectoryError("synthetic-private")):
            with self.subTest(error=type(error).__name__), patch.object(config.Path, "open", side_effect=error):
                self.assert_invalid(lambda: config.load_settings(environ={}))

    def test_empty_or_nontext_explicit_path_does_not_use_default(self):
        for value in ("", " ", None, True, 123):
            with self.subTest(value=value):
                self.assert_invalid(lambda: config.load_settings(environ={"MAGNUM_CONFIG": value}))

    def test_settings_are_immutable_and_validate_direct_construction(self):
        settings = config.Settings(2)
        with self.assertRaises(FrozenInstanceError):
            settings.request_interval_seconds = 1
        for value in (True, 0, -1, float("inf"), float("nan"), "0.5", None, 10 ** 10000):
            self.assert_invalid(lambda: config.Settings(value))


if __name__ == "__main__":
    unittest.main()
