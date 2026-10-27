from __future__ import annotations

import platform
import subprocess
from typing import Protocol

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


class CredentialStore(Protocol):
    """Local secret-store seam; private keys never cross the Gateway interface."""

    def get(self, alias: str) -> bytes | None: ...

    def put(self, alias: str, value: bytes) -> None: ...


class InMemoryCredentialStore:
    """Test adapter. Production Workers must use an OS credential-store adapter."""

    def __init__(self) -> None:
        self._values: dict[str, bytes] = {}

    def get(self, alias: str) -> bytes | None:
        return self._values.get(alias)

    def put(self, alias: str, value: bytes) -> None:
        self._values[alias] = bytes(value)


class MacOSKeychainStore:
    """Store a PEM private key in the macOS login Keychain via `security`."""

    def __init__(self, service: str = "workbuddy-a2a-worker") -> None:
        if platform.system() != "Darwin":
            raise RuntimeError("MacOSKeychainStore is only available on macOS")
        self.service = service

    def get(self, alias: str) -> bytes | None:
        result = subprocess.run(
            ["security", "find-generic-password", "-a", alias, "-s", self.service, "-w"],
            check=False,
            capture_output=True,
        )
        if result.returncode != 0:
            return None
        return result.stdout

    def put(self, alias: str, value: bytes) -> None:
        subprocess.run(
            [
                "security",
                "add-generic-password",
                "-U",
                "-a",
                alias,
                "-s",
                self.service,
                "-w",
                value.decode("utf-8"),
            ],
            check=True,
            capture_output=True,
        )


def default_credential_store() -> CredentialStore:
    if platform.system() == "Darwin":
        return MacOSKeychainStore()
    raise RuntimeError("no OS credential-store adapter is configured for this platform")


def load_or_create_private_key(alias: str, store: CredentialStore) -> Ed25519PrivateKey:
    encoded = store.get(alias)
    if encoded is None:
        key = Ed25519PrivateKey.generate()
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        store.put(alias, pem)
        return key
    loaded = serialization.load_pem_private_key(encoded, password=None)
    if not isinstance(loaded, Ed25519PrivateKey):
        raise ValueError("credential store entry is not an Ed25519 private key")
    return loaded
