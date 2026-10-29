"""Offline vault tests. No real credential APIs or user records are accessed."""
import importlib.util
import json
from pathlib import Path
import sys
import os
import stat
import tempfile
import subprocess
import unittest
from unittest.mock import Mock, patch

MODULE = Path(__file__).resolve().parents[1] / "magnum_vault.py"
spec = importlib.util.spec_from_file_location("vault_under_test", MODULE)
vault = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = vault
spec.loader.exec_module(vault)

TOKEN = "example-session-token-for-unit-tests"
REFRESH = "example-refresh-token-for-unit-tests"


class SchemaTests(unittest.TestCase):
    def record(self, **overrides):
        values = dict(token=TOKEN, refresh_token=REFRESH, stored_at=1700000000, expires_at=1700003600, kind="user")
        values.update(overrides)
        return vault.SessionRecord(**values)

    def assert_code(self, code, action):
        with self.assertRaises(vault.VaultError) as error:
            action()
        self.assertEqual(error.exception.code, code)
        self.assertNotIn(TOKEN, repr(error.exception))

    def test_schema_roundtrip_and_safe_repr(self):
        record = self.record()
        restored = vault._decode(vault._encode(record))
        self.assertEqual(restored.as_dict(), record.as_dict())
        self.assertNotIn(TOKEN, repr(record))
        self.assertNotIn(REFRESH, str(record))
        self.assertIn("redacted", repr(record))

    def test_guest_record_optional_refresh_and_expiry(self):
        record = vault.SessionRecord(token=TOKEN)
        self.assertEqual(record.kind, "guest")
        self.assertIsNone(vault._decode(vault._encode(record)).refresh_token)

    def test_phone_otp_unknown_fields_rejected(self):
        for field in ("phone", "otp", "sms_code", "arbitrary"):
            bad = self.record().as_dict()
            bad[field] = "123456"
            self.assert_code("vault_invalid_record", lambda: vault._encode(bad))

    def test_short_numeric_controls_and_oversized_secrets_rejected(self):
        for token in ("123456", "+77011234567", "+123456789012345", "+1(123)456-789012", "1" * 20, TOKEN + "\n", TOKEN + "\r", TOKEN + " ", "x" * 4097, "т" * 30):
            self.assert_code("vault_invalid_record", lambda: self.record(token=token))

    def test_timestamp_types_and_kind_rejected(self):
        for overrides in ({"stored_at": True}, {"stored_at": 0}, {"expires_at": "1700000000"}, {"kind": "admin"}):
            self.assert_code("vault_invalid_record", lambda: self.record(**overrides))

    def test_blob_size_checked_before_any_backend_call(self):
        store = vault.SecretStore()
        backend = Mock()
        store._backend = backend
        self.assert_code("vault_record_too_large", lambda: store.write(self.record(token="a" * 3000, refresh_token="b" * 3000)))
        backend.write.assert_not_called()

    def test_corrupt_saved_json_never_leaks_value(self):
        for blob in (b"not-json-" + TOKEN.encode(), json.dumps({"token": TOKEN, "kind": "user"}).encode(), b"[]", b"null", b"\xff"):
            self.assert_code("vault_invalid_record", lambda: vault._decode(blob))

    def test_unrelated_credential_target_rejected(self):
        for target in ("OtherApp/session", "MagnumGoMCP/", "MagnumGoMCP/v1/session\n"):
            self.assert_code("vault_invalid_target", lambda: vault.SecretStore(target))

    def test_unsupported_platform_is_fail_closed(self):
        with patch.object(vault.sys, "platform", "unsupported-os"):
            store = vault.SecretStore()
            self.assertFalse(store.check().available)
            self.assertEqual(store.check().reason, "vault_unsupported")
            self.assert_code("vault_unsupported", store.read)
            self.assert_code("vault_unsupported", lambda: store.write(self.record()))
            self.assert_code("vault_unsupported", store.delete)


class BackendTests(unittest.TestCase):
    def test_check_does_not_read_write_delete_or_encrypt(self):
        backend = Mock(name="secure-backend")
        backend.name = "linux_systemd_credentials"
        with patch.object(vault.sys, "platform", "linux"), patch.object(vault, "_check_program"), patch.object(vault, "_SystemdCredentialsBackend", return_value=backend):
            store = vault.SecretStore()
            self.assertTrue(store.check().available)
            self.assertTrue(store.check().available)
            backend.read.assert_not_called()
            backend.write.assert_not_called()
            backend.delete.assert_not_called()

    def test_windows_is_unsupported(self):
        with patch.object(vault.sys, "platform", "win32"):
            self.assertEqual(vault.SecretStore().check().reason, "vault_unsupported")

    def test_systemd_command_uses_user_host_key_and_pipes(self):
        plaintext = vault._encode(vault.SessionRecord(token=TOKEN))
        with patch.object(vault.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, b"ciphertext")) as run:
            self.assertEqual(vault._SystemdCredentialsBackend._run("encrypt", plaintext), b"ciphertext")
            args, kwargs = run.call_args
            self.assertEqual(args[0], ["/usr/bin/systemd-creds", "--user", "--with-key=host", "--name=magnum-go-session", "encrypt", "-", "-"])
            self.assertNotIn(TOKEN, " ".join(args[0]))
            self.assertEqual(kwargs["input"], plaintext)
            self.assertEqual(kwargs["stderr"], subprocess.DEVNULL)
            self.assertEqual(kwargs["stdout"], subprocess.PIPE)
            self.assertNotIn("--allow-null", args[0])
        with patch.object(vault.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, plaintext)) as run:
            self.assertEqual(vault._SystemdCredentialsBackend._run("decrypt", b"ciphertext"), plaintext)
            self.assertEqual(run.call_args.args[0], ["/usr/bin/systemd-creds", "--user", "--name=magnum-go-session", "decrypt", "-", "-"])

    def test_subprocess_failures_and_sizes_are_fail_closed(self):
        failures = [
            subprocess.CompletedProcess([], 1, b"backend said " + TOKEN.encode()),
            subprocess.CompletedProcess([], 0, b""),
            subprocess.CompletedProcess([], 0, b"x" * (vault.MAX_CIPHERTEXT_BYTES + 1)),
        ]
        for result in failures:
            with patch.object(vault.subprocess, "run", return_value=result):
                with self.assertRaises(vault.VaultError) as error:
                    vault._SystemdCredentialsBackend._run("encrypt", b"test")
                self.assertEqual(error.exception.code, "vault_encrypt_failed")
                self.assertNotIn(TOKEN, repr(error.exception))
        with patch.object(vault.subprocess, "run", side_effect=RuntimeError(TOKEN)):
            with self.assertRaises(vault.VaultError) as error:
                vault._SystemdCredentialsBackend._run("decrypt", b"ciphertext")
            self.assertEqual(error.exception.code, "vault_decrypt_failed")
            self.assertNotIn(TOKEN, repr(error.exception))
        with patch.object(vault.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, b"x" * (vault.MAX_BLOB_BYTES + 1))):
            with self.assertRaises(vault.VaultError):
                vault._SystemdCredentialsBackend._run("decrypt", b"ciphertext")

    def test_target_override_hashes_without_path_traversal(self):
        default = vault._SystemdCredentialsBackend(vault.DEFAULT_TARGET)
        probe = vault._SystemdCredentialsBackend("MagnumGoMCP/v1/preflight/../test")
        self.assertEqual(default.filename, "session.cred")
        self.assertRegex(probe.filename, r"^target-[0-9a-f]{64}\.cred$")
        self.assertNotEqual(default.filename, probe.filename)

    def test_xdg_state_home_requires_absolute_path(self):
        with patch.dict(os.environ, {"XDG_STATE_HOME": "relative-state"}):
            self.assertEqual(vault._default_directory(), Path.home() / ".local" / "state" / "magnum-go")


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux no-follow/dir_fd filesystem checks")
class LinuxFilesystemTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name) / "state" / "magnum-go"
        self.directory_patch = patch.object(vault, "_default_directory", return_value=self.directory)
        self.directory_patch.start()
        self.program_patch = patch.object(vault, "_check_program")
        self.program_patch.start()
        self.blobs = {}
        def fake_run(argv, *, input, **kwargs):
            if "encrypt" in argv:
                result = b"opaque-ciphertext-" + str(len(self.blobs)).encode()
                self.blobs[result] = input
                return subprocess.CompletedProcess(argv, 0, result)
            return subprocess.CompletedProcess(argv, 0, self.blobs.get(input, b""))
        self.run_patch = patch.object(vault.subprocess, "run", side_effect=fake_run)
        self.run_patch.start()

    def tearDown(self):
        self.run_patch.stop()
        self.program_patch.stop()
        self.directory_patch.stop()
        self.temp.cleanup()

    def test_ciphertext_only_atomic_roundtrip_and_modes(self):
        store = vault.SecretStore()
        self.assertIsNone(store.read())
        self.assertFalse(self.directory.exists())
        record = vault.SessionRecord(token=TOKEN, kind="user")
        store.write(record)
        path = self.directory / "session.cred"
        self.assertNotIn(TOKEN.encode(), path.read_bytes())
        self.assertEqual(stat.S_IMODE(self.directory.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(store.read().as_dict(), record.as_dict())
        store.write(vault.SessionRecord(token=REFRESH))
        self.assertEqual(store.read().token, REFRESH)
        self.assertEqual(list(self.directory.iterdir()), [path])
        self.assertTrue(store.delete())
        self.assertFalse(store.delete())

    def test_preflight_never_overwrites_main_session(self):
        main = vault.SecretStore()
        probe = vault.SecretStore(target="MagnumGoMCP/v1/preflight/test-1")
        main.write(vault.SessionRecord(token=TOKEN))
        before = (self.directory / "session.cred").read_bytes()
        probe.write(vault.SessionRecord(token=REFRESH))
        self.assertEqual(probe.read().token, REFRESH)
        probe.delete()
        self.assertEqual((self.directory / "session.cred").read_bytes(), before)
        self.assertEqual(main.read().token, TOKEN)

    def test_symlink_record_and_directory_are_rejected(self):
        self.directory.mkdir(mode=0o700, parents=True)
        outside = Path(self.temp.name) / "outside"
        outside.write_bytes(b"must stay untouched")
        path = self.directory / "session.cred"
        path.symlink_to(outside)
        store = vault.SecretStore()
        for operation in (store.read, store.delete, lambda: store.write(vault.SessionRecord(token=TOKEN))):
            with self.assertRaises(vault.VaultError) as error:
                operation()
            self.assertEqual(error.exception.code, "vault_insecure_path")
        self.assertEqual(outside.read_bytes(), b"must stay untouched")
        path.unlink()
        self.directory.rmdir()
        self.directory.symlink_to(outside.parent, target_is_directory=True)
        with self.assertRaises(vault.VaultError) as error:
            vault.SecretStore().read()
        self.assertEqual(error.exception.code, "vault_insecure_path")

    def test_insecure_permissions_and_hardlinks_are_rejected(self):
        store = vault.SecretStore()
        store.write(vault.SessionRecord(token=TOKEN))
        path = self.directory / "session.cred"
        path.chmod(0o644)
        with self.assertRaises(vault.VaultError):
            store.read()
        path.chmod(0o600)
        link = self.directory / "hardlink"
        os.link(path, link)
        with self.assertRaises(vault.VaultError):
            store.read()
        link.unlink()
        self.directory.chmod(0o755)
        with self.assertRaises(vault.VaultError):
            store.read()

    def test_failed_replace_preserves_previous_ciphertext_and_cleans_temp(self):
        store = vault.SecretStore()
        store.write(vault.SessionRecord(token=TOKEN))
        path = self.directory / "session.cred"
        before = path.read_bytes()
        with patch.object(vault.os, "replace", side_effect=OSError(TOKEN)):
            with self.assertRaises(vault.VaultError) as error:
                store.write(vault.SessionRecord(token=REFRESH))
        self.assertEqual(error.exception.code, "vault_write_failed")
        self.assertNotIn(TOKEN, repr(error.exception))
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(list(self.directory.iterdir()), [path])

    def test_oversized_ciphertext_never_reaches_decrypt(self):
        self.directory.mkdir(mode=0o700, parents=True)
        path = self.directory / "session.cred"
        path.write_bytes(b"x" * (vault.MAX_CIPHERTEXT_BYTES + 1))
        path.chmod(0o600)
        with patch.object(vault.subprocess, "run") as run:
            with self.assertRaises(vault.VaultError):
                vault.SecretStore().read()
            run.assert_not_called()


if __name__ == "__main__":
    unittest.main()


