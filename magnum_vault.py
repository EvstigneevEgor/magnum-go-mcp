"""Encrypted Linux storage for one MagnumGo MCP session.

Importing this module does not read or write credentials. ``check()`` verifies
the trusted systemd-creds program without encrypting or inspecting a session.
The Linux OS user's host key encrypts the record; only ciphertext is written
to disk. There is no Windows backend, plaintext fallback or graphical session
dependency. Host/user binding is enforced by systemd-creds --user.

``SessionRecord.as_dict()`` deliberately exports secrets: use it only when
needed for serialization/requests, never for logs or an MCP response.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import secrets
import stat
import subprocess
import sys
import time
import hashlib
from dataclasses import dataclass, field
from typing import Any, Mapping

DEFAULT_TARGET = "MagnumGoMCP/v1/session"
MAX_BLOB_BYTES = 5120
SYSTEMD_CREDS = "/usr/bin/systemd-creds"
MAX_CIPHERTEXT_BYTES = 64 * 1024
_CREDENTIAL_NAME = "magnum-go-session"
_FIELDS = frozenset({"token", "refresh_token", "stored_at", "expires_at", "kind"})
_MESSAGES = {
    "vault_unsupported": "Secure session storage is unsupported on this platform.",
    "vault_unavailable": "The OS credential store is unavailable.",
    "vault_locked": "The OS credential store is locked or has no active user session.",
    "vault_access_denied": "Access to the OS credential store was denied.",
    "vault_read_failed": "The saved session could not be read securely.",
    "vault_write_failed": "The session could not be saved securely.",
    "vault_delete_failed": "The saved session could not be removed securely.",
    "vault_invalid_record": "The session record has an invalid schema or value.",
    "vault_record_too_large": "The session exceeds the credential store size limit.",
    "vault_invalid_target": "The credential target must be in the MagnumGoMCP namespace.",
    "vault_insecure_path": "The session storage path has unsafe ownership, permissions or links.",
    "vault_encrypt_failed": "The Linux OS could not encrypt the session securely.",
    "vault_decrypt_failed": "The Linux OS could not decrypt the saved session.",
}


class VaultError(RuntimeError):
    """A stable, sanitized error containing no backend error text or secrets."""

    def __init__(self, code: str) -> None:
        if code not in _MESSAGES:
            code = "vault_unavailable"
        self.code = code
        super().__init__(_MESSAGES[code])


def _secret(value: Any, *, optional: bool = False) -> str | None:
    if optional and value is None:
        return None
    # Reject short numeric OTPs, phone numbers, controls, spaces and non-ASCII.
    if (
        not isinstance(value, str)
        or not 16 <= len(value) <= 4096
        or all(ch in "+-().0123456789" for ch in value)
        or any(not 0x21 <= ord(ch) <= 0x7E for ch in value)
    ):
        raise VaultError("vault_invalid_record")
    return value


def _timestamp(value: Any, *, optional: bool = False) -> int | None:
    if optional and value is None:
        return None
    if type(value) is not int or not 0 < value < 2**53:
        raise VaultError("vault_invalid_record")
    return value


@dataclass(frozen=True, slots=True, repr=False)
class SessionRecord:
    token: str
    refresh_token: str | None = None
    stored_at: int = field(default_factory=lambda: int(time.time()))
    expires_at: int | None = None
    kind: str = "guest"

    def __post_init__(self) -> None:
        _secret(self.token)
        _secret(self.refresh_token, optional=True)
        _timestamp(self.stored_at)
        _timestamp(self.expires_at, optional=True)
        if self.kind not in ("guest", "user"):
            raise VaultError("vault_invalid_record")

    def __repr__(self) -> str:
        return (
            f"SessionRecord(kind={self.kind!r}, stored_at={self.stored_at!r}, "
            f"expires_at={self.expires_at!r}, secrets=<redacted>)"
        )

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "SessionRecord":
        try:
            if not isinstance(value, Mapping) or set(value) - _FIELDS:
                raise VaultError("vault_invalid_record")
            if not {"token", "stored_at", "kind"}.issubset(value):
                raise VaultError("vault_invalid_record")
            return cls(**dict(value))
        except VaultError:
            raise
        except Exception:
            raise VaultError("vault_invalid_record") from None

    def as_dict(self) -> dict[str, Any]:
        """Explicit secret export. Do not log or return this through MCP."""
        return {
            "token": self.token,
            "refresh_token": self.refresh_token,
            "stored_at": self.stored_at,
            "expires_at": self.expires_at,
            "kind": self.kind,
        }


def _encode(record: SessionRecord | Mapping[str, Any]) -> bytes:
    if not isinstance(record, SessionRecord):
        record = SessionRecord.from_dict(record)
    try:
        blob = json.dumps(record.as_dict(), ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    except Exception:
        raise VaultError("vault_invalid_record") from None
    if len(blob) > MAX_BLOB_BYTES:
        raise VaultError("vault_record_too_large")
    return blob


def _decode(blob: bytes) -> SessionRecord:
    if not isinstance(blob, bytes) or len(blob) > MAX_BLOB_BYTES:
        raise VaultError("vault_invalid_record")
    try:
        value = json.loads(blob.decode("utf-8"))
        return SessionRecord.from_dict(value)
    except VaultError:
        raise
    except Exception:
        raise VaultError("vault_invalid_record") from None


def _target(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value.startswith("MagnumGoMCP/")
        or not 13 <= len(value) <= 256
        or any(not 0x21 <= ord(ch) <= 0x7E for ch in value)
    ):
        raise VaultError("vault_invalid_target")
    return value


@dataclass(frozen=True, slots=True)
class VaultAvailability:
    available: bool
    backend: str | None
    reason: str | None = None


def _default_directory() -> Path:
    state_home = os.environ.get("XDG_STATE_HOME", "")
    base = Path(state_home) if state_home and Path(state_home).is_absolute() else Path.home() / ".local" / "state"
    return base / "magnum-go"


def _check_program() -> None:
    try:
        info = os.lstat(SYSTEMD_CREDS)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or stat.S_IMODE(info.st_mode) & 0o022
            or not os.access(SYSTEMD_CREDS, os.X_OK)
        ):
            raise VaultError("vault_unavailable")
    except VaultError:
        raise
    except Exception:
        raise VaultError("vault_unavailable") from None


def _secure_file(info: os.stat_result) -> None:
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o600
        or info.st_nlink != 1
    ):
        raise VaultError("vault_insecure_path")


class _SystemdCredentialsBackend:
    name = "linux_systemd_credentials"

    def __init__(self, target: str) -> None:
        self.target = _target(target)
        self.directory = _default_directory()
        self.filename = "session.cred" if target == DEFAULT_TARGET else "target-" + hashlib.sha256(target.encode("ascii")).hexdigest() + ".cred"

    def _directory_fd(self, *, create: bool) -> int | None:
        """Walk each directory through no-follow descriptors; final mode is 0700.

        System-owned ancestors are allowed. A root-owned sticky temporary
        directory is also allowed, so isolated tests may use /tmp. The final
        directory is always owned by the current user and inaccessible to
        other users. All later record operations are relative to its open fd.
        """
        if not self.directory.is_absolute() or ".." in self.directory.parts:
            raise VaultError("vault_insecure_path")
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        fd = None
        try:
            fd = os.open("/", flags)
            parts = self.directory.parts[1:]
            for index, part in enumerate(parts):
                try:
                    child = os.open(part, flags, dir_fd=fd)
                except FileNotFoundError:
                    if not create:
                        os.close(fd)
                        fd = None
                        return None
                    try:
                        os.mkdir(part, mode=0o700, dir_fd=fd)
                    except FileExistsError:
                        pass
                    child = os.open(part, flags, dir_fd=fd)
                os.close(fd)
                fd = child
                info = os.fstat(fd)
                mode = stat.S_IMODE(info.st_mode)
                if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.getuid()):
                    raise VaultError("vault_insecure_path")
                sticky_system_temp = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
                if mode & 0o022 and not sticky_system_temp:
                    raise VaultError("vault_insecure_path")
                if index == len(parts) - 1 and (info.st_uid != os.getuid() or mode != 0o700):
                    raise VaultError("vault_insecure_path")
            result = fd
            fd = None
            return result
        except VaultError:
            raise
        except Exception:
            raise VaultError("vault_insecure_path") from None
        finally:
            if fd is not None:
                os.close(fd)

    def _inspect(self, directory_fd: int) -> bool:
        try:
            info = os.stat(self.filename, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            return False
        _secure_file(info)
        return True

    @staticmethod
    def _run(action: str, data: bytes) -> bytes:
        fallback = "vault_encrypt_failed" if action == "encrypt" else "vault_decrypt_failed"
        argv = [SYSTEMD_CREDS, "--user"]
        if action == "encrypt":
            argv.append("--with-key=host")
        argv.extend(["--name=" + _CREDENTIAL_NAME, action, "-", "-"])
        try:
            result = subprocess.run(
                argv,
                input=data,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=20,
                close_fds=True,
            )
            limit = MAX_CIPHERTEXT_BYTES if action == "encrypt" else MAX_BLOB_BYTES
            if result.returncode != 0 or not isinstance(result.stdout, bytes) or not 0 < len(result.stdout) <= limit:
                raise VaultError(fallback)
            return result.stdout
        except VaultError:
            raise
        except Exception:
            raise VaultError(fallback) from None

    def read(self) -> bytes | None:
        directory_fd = self._directory_fd(create=False)
        if directory_fd is None:
            return None
        record_fd = None
        try:
            if not self._inspect(directory_fd):
                return None
            record_fd = os.open(self.filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory_fd)
            info = os.fstat(record_fd)
            _secure_file(info)
            if not 0 < info.st_size <= MAX_CIPHERTEXT_BYTES:
                raise VaultError("vault_invalid_record")
            with os.fdopen(record_fd, "rb") as stream:
                record_fd = None
                ciphertext = stream.read(MAX_CIPHERTEXT_BYTES + 1)
            if not 0 < len(ciphertext) <= MAX_CIPHERTEXT_BYTES:
                raise VaultError("vault_invalid_record")
            return self._run("decrypt", ciphertext)
        except VaultError:
            raise
        except Exception:
            raise VaultError("vault_read_failed") from None
        finally:
            if record_fd is not None:
                os.close(record_fd)
            os.close(directory_fd)

    def write(self, blob: bytes) -> None:
        if not 0 < len(blob) <= MAX_BLOB_BYTES:
            raise VaultError("vault_record_too_large")
        ciphertext = self._run("encrypt", blob)
        directory_fd = self._directory_fd(create=True)
        tempname = "." + self.filename + "." + secrets.token_hex(16) + ".tmp"
        temp_fd = None
        created = False
        try:
            self._inspect(directory_fd)
            temp_fd = os.open(tempname, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory_fd)
            created = True
            _secure_file(os.fstat(temp_fd))
            with os.fdopen(temp_fd, "wb") as stream:
                temp_fd = None
                stream.write(ciphertext)
                stream.flush()
                os.fsync(stream.fileno())
            self._inspect(directory_fd)
            os.replace(tempname, self.filename, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
            created = False
            os.fsync(directory_fd)
        except VaultError:
            raise
        except Exception:
            raise VaultError("vault_write_failed") from None
        finally:
            if temp_fd is not None:
                os.close(temp_fd)
            if created:
                try:
                    os.unlink(tempname, dir_fd=directory_fd)
                except OSError:
                    pass
            os.close(directory_fd)

    def delete(self) -> bool:
        directory_fd = self._directory_fd(create=False)
        if directory_fd is None:
            return False
        try:
            if not self._inspect(directory_fd):
                return False
            os.unlink(self.filename, dir_fd=directory_fd)
            os.fsync(directory_fd)
            return True
        except VaultError:
            raise
        except Exception:
            raise VaultError("vault_delete_failed") from None
        finally:
            os.close(directory_fd)


class SecretStore:
    """One encrypted Linux session; initialization does not read or write it.

    Default: $XDG_STATE_HOME/magnum-go/session.cred, or
    ~/.local/state/magnum-go/session.cred when XDG_STATE_HOME is not absolute.
    Other MagnumGoMCP targets use a SHA-256 filename for isolated preflights.
    check() verifies program availability only; a synthetic preflight can test
    actual encryption/decryption without touching the default session.
    """

    def __init__(self, target: str = DEFAULT_TARGET) -> None:
        self.target = _target(target)
        self._backend: _SystemdCredentialsBackend | None = None

    def __repr__(self) -> str:
        return "SecretStore(secrets=<Linux encrypted credentials>)"

    def _get_backend(self) -> _SystemdCredentialsBackend:
        if not sys.platform.startswith("linux"):
            raise VaultError("vault_unsupported")
        if self._backend is None:
            _check_program()
            self._backend = _SystemdCredentialsBackend(self.target)
        return self._backend

    def check(self) -> VaultAvailability:
        try:
            backend = self._get_backend()
            return VaultAvailability(True, backend.name)
        except VaultError as error:
            return VaultAvailability(False, None, error.code)
        except Exception:
            return VaultAvailability(False, None, "vault_unavailable")

    def read(self) -> SessionRecord | None:
        blob = self._get_backend().read()
        return None if blob is None else _decode(blob)

    def write(self, record: SessionRecord | Mapping[str, Any]) -> None:
        blob = _encode(record)
        self._get_backend().write(blob)

    def delete(self) -> bool:
        return self._get_backend().delete()


__all__ = ["DEFAULT_TARGET", "MAX_BLOB_BYTES", "MAX_CIPHERTEXT_BYTES", "SecretStore", "SessionRecord", "VaultAvailability", "VaultError"]


