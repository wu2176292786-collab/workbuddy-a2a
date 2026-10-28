"""SQLite backup and restore verification used by the local PoC deployment."""

from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
import time
from pathlib import Path
from typing import Any, Mapping

from .admin import redact


class SQLiteBackupManager:
    def _integrity(self, path: Path) -> str:
        connection = sqlite3.connect(path)
        try:
            result = connection.execute("PRAGMA integrity_check").fetchone()[0]
            return str(result)
        finally:
            connection.close()

    def _sha256(self, path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def backup(self, source: str | Path, destination: str | Path, *, metadata: Mapping[str, Any] | None = None) -> dict[str, Any]:
        source_path, destination_path = Path(source), Path(destination)
        if not source_path.is_file():
            raise FileNotFoundError(source_path)
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        source_connection = sqlite3.connect(source_path)
        destination_connection = sqlite3.connect(destination_path)
        try:
            source_connection.backup(destination_connection)
        finally:
            destination_connection.close()
            source_connection.close()
        manifest = {"schema_version": 1, "created_at": time.time(), "size": destination_path.stat().st_size, "sha256": self._sha256(destination_path), "integrity_check": self._integrity(destination_path), "metadata": redact(metadata or {})}
        destination_path.with_suffix(destination_path.suffix + ".manifest.json").write_text(json.dumps(manifest, sort_keys=True) + "\n")
        return manifest

    def restore(self, backup: str | Path, destination: str | Path) -> dict[str, Any]:
        backup_path, destination_path = Path(backup), Path(destination)
        if not backup_path.is_file():
            raise FileNotFoundError(backup_path)
        manifest_path = backup_path.with_suffix(backup_path.suffix + ".manifest.json")
        if manifest_path.is_file():
            manifest = json.loads(manifest_path.read_text())
            if manifest.get("sha256") != self._sha256(backup_path):
                raise ValueError("backup checksum does not match manifest")
            if manifest.get("integrity_check") != "ok":
                raise ValueError("backup integrity manifest is not valid")
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(backup_path, destination_path)
        return {"schema_version": 1, "restored_at": time.time(), "size": destination_path.stat().st_size, "sha256": self._sha256(destination_path), "integrity_check": self._integrity(destination_path)}
