from __future__ import annotations

import platform
import subprocess
import ctypes
from ctypes import wintypes
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


class _WindowsFileTime(ctypes.Structure):
    _fields_ = [("dwLowDateTime", wintypes.DWORD), ("dwHighDateTime", wintypes.DWORD)]


class _WindowsCredential(ctypes.Structure):
    _fields_ = [
        ("Flags", wintypes.DWORD),
        ("Type", wintypes.DWORD),
        ("TargetName", wintypes.LPWSTR),
        ("Comment", wintypes.LPWSTR),
        ("LastWritten", _WindowsFileTime),
        ("CredentialBlobSize", wintypes.DWORD),
        ("CredentialBlob", wintypes.LPBYTE),
        ("Persist", wintypes.DWORD),
        ("AttributeCount", wintypes.DWORD),
        ("Attributes", ctypes.c_void_p),
        ("TargetAlias", wintypes.LPWSTR),
        ("UserName", wintypes.LPWSTR),
    ]


class WindowsCredentialStore:
    """Store a PEM private key in Windows Credential Manager."""

    _CRED_TYPE_GENERIC = 1
    _CRED_PERSIST_LOCAL_MACHINE = 2

    def __init__(self, service: str = "workbuddy-a2a-worker") -> None:
        if platform.system() != "Windows":
            raise RuntimeError("WindowsCredentialStore is only available on Windows")
        self.service = service
        self._advapi32 = ctypes.windll.advapi32
        self._advapi32.CredReadW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.POINTER(ctypes.POINTER(_WindowsCredential)),
        ]
        self._advapi32.CredReadW.restype = wintypes.BOOL
        self._advapi32.CredWriteW.argtypes = [ctypes.POINTER(_WindowsCredential), wintypes.DWORD]
        self._advapi32.CredWriteW.restype = wintypes.BOOL
        self._advapi32.CredFree.argtypes = [ctypes.c_void_p]
        self._advapi32.CredFree.restype = None

    def _target(self, alias: str) -> str:
        return f"{self.service}:{alias}"

    def get(self, alias: str) -> bytes | None:
        credential = ctypes.POINTER(_WindowsCredential)()
        if not self._advapi32.CredReadW(
            self._target(alias), self._CRED_TYPE_GENERIC, 0, ctypes.byref(credential)
        ):
            return None
        try:
            value = ctypes.string_at(credential.contents.CredentialBlob, credential.contents.CredentialBlobSize)
            return bytes(value)
        finally:
            self._advapi32.CredFree(credential)

    def put(self, alias: str, value: bytes) -> None:
        blob = ctypes.create_string_buffer(value)
        credential = _WindowsCredential()
        credential.Type = self._CRED_TYPE_GENERIC
        credential.TargetName = self._target(alias)
        credential.CredentialBlobSize = len(value)
        credential.CredentialBlob = ctypes.cast(blob, wintypes.LPBYTE)
        credential.Persist = self._CRED_PERSIST_LOCAL_MACHINE
        credential.UserName = alias
        if not self._advapi32.CredWriteW(ctypes.byref(credential), 0):
            raise OSError("Windows Credential Manager rejected the credential")


def default_credential_store() -> CredentialStore:
    if platform.system() == "Darwin":
        return MacOSKeychainStore()
    if platform.system() == "Windows":
        return WindowsCredentialStore()
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
