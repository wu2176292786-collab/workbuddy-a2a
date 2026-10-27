from __future__ import annotations

import hashlib
import secrets
import sqlite3
import time
import uuid
from contextlib import contextmanager
from typing import Iterator

from .errors import GatewayError, NoActiveWorker, PairingError, WorkerNotFound
from .models import Agent, BootstrapResult, PairingCode, TaskRecord, Team, User, WorkerRecord


class SQLiteStore:
    """Durable Gateway state for the PoC.

    The store intentionally has no private-key column. A Worker private key is
    created and retained by the Worker-side credential store; the Gateway only
    receives the corresponding public key during pairing.
    """

    def __init__(self, path: str = "gateway.db") -> None:
        self.connection = sqlite3.connect(path, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")
        self._initialize()

    def close(self) -> None:
        self.connection.close()

    def _initialize(self) -> None:
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS teams (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                created_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                team_id TEXT NOT NULL REFERENCES teams(id),
                name TEXT NOT NULL,
                created_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS agents (
                id TEXT PRIMARY KEY,
                team_id TEXT NOT NULL REFERENCES teams(id),
                user_id TEXT NOT NULL REFERENCES users(id),
                name TEXT NOT NULL,
                created_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS workers (
                id TEXT PRIMARY KEY,
                team_id TEXT NOT NULL REFERENCES teams(id),
                agent_id TEXT NOT NULL REFERENCES agents(id),
                public_key BLOB NOT NULL,
                worker_epoch INTEGER NOT NULL,
                status TEXT NOT NULL CHECK (status IN ('ACTIVE', 'REVOKED')),
                paired_at REAL NOT NULL,
                revoked_at REAL,
                last_seen_at REAL
            );
            CREATE INDEX IF NOT EXISTS workers_agent_status
                ON workers(agent_id, status);
            CREATE TABLE IF NOT EXISTS pairing_codes (
                code_hash TEXT PRIMARY KEY,
                team_id TEXT NOT NULL REFERENCES teams(id),
                agent_id TEXT NOT NULL REFERENCES agents(id),
                expires_at REAL NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                max_attempts INTEGER NOT NULL,
                created_at REAL NOT NULL,
                used_at REAL
            );
            CREATE TABLE IF NOT EXISTS tasks (
                id TEXT PRIMARY KEY,
                recipient_agent_id TEXT NOT NULL REFERENCES agents(id),
                payload TEXT NOT NULL,
                state TEXT NOT NULL,
                created_at REAL NOT NULL
            );
            """
        )
        self.connection.commit()

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        try:
            self.connection.execute("BEGIN IMMEDIATE")
            yield self.connection
        except Exception:
            self.connection.rollback()
            raise
        else:
            self.connection.commit()

    @staticmethod
    def _id() -> str:
        return str(uuid.uuid4())

    def bootstrap(self, team_name: str, user_name: str, agent_name: str) -> BootstrapResult:
        if not all(isinstance(value, str) and value.strip() for value in (team_name, user_name, agent_name)):
            raise GatewayError("team_name, user_name, and agent_name are required")
        now = time.time()
        team = Team(self._id(), team_name.strip(), now)
        user = User(self._id(), team.id, user_name.strip(), now)
        agent = Agent(self._id(), team.id, user.id, agent_name.strip(), now)
        with self._transaction() as connection:
            connection.execute("INSERT INTO teams VALUES (?, ?, ?)", (team.id, team.name, team.created_at))
            connection.execute("INSERT INTO users VALUES (?, ?, ?, ?)", (user.id, user.team_id, user.name, user.created_at))
            connection.execute(
                "INSERT INTO agents VALUES (?, ?, ?, ?, ?)",
                (agent.id, agent.team_id, agent.user_id, agent.name, agent.created_at),
            )
        return BootstrapResult(team=team, user=user, agent=agent)

    def get_agent(self, agent_id: str) -> Agent | None:
        row = self.connection.execute("SELECT * FROM agents WHERE id = ?", (agent_id,)).fetchone()
        if row is None:
            return None
        return Agent(row["id"], row["team_id"], row["user_id"], row["name"], row["created_at"])

    def agent_is_allowed(self, agent_id: str, team_id: str) -> bool:
        row = self.connection.execute(
            "SELECT 1 FROM agents WHERE id = ? AND team_id = ?", (agent_id, team_id)
        ).fetchone()
        return row is not None

    def create_pairing_code(
        self,
        team_id: str,
        agent_id: str,
        ttl_seconds: int = 600,
        max_attempts: int = 5,
    ) -> PairingCode:
        if not self.agent_is_allowed(agent_id, team_id):
            raise GatewayError("agent is not a member of the requested team")
        if not 60 <= ttl_seconds <= 3600:
            raise GatewayError("ttl_seconds must be between 60 and 3600")
        if not 1 <= max_attempts <= 10:
            raise GatewayError("max_attempts must be between 1 and 10")
        code = secrets.token_urlsafe(32)
        expires_at = time.time() + ttl_seconds
        with self._transaction() as connection:
            connection.execute(
                "INSERT INTO pairing_codes VALUES (?, ?, ?, ?, 0, ?, ?, NULL)",
                (self._hash_pairing_code(code), team_id, agent_id, expires_at, max_attempts, time.time()),
            )
        return PairingCode(code, team_id, agent_id, expires_at, max_attempts)

    @staticmethod
    def _hash_pairing_code(code: str) -> str:
        return hashlib.sha256(code.encode("utf-8")).hexdigest()

    def _record_pairing_failure(self, code: str) -> None:
        code_hash = self._hash_pairing_code(code)
        with self._transaction() as connection:
            connection.execute(
                "UPDATE pairing_codes SET attempts = attempts + 1 WHERE code_hash = ? AND used_at IS NULL",
                (code_hash,),
            )

    def record_pairing_failure(self, code: str) -> None:
        self._record_pairing_failure(code)

    def pair_worker(
        self,
        *,
        code: str,
        team_id: str,
        agent_id: str,
        worker_id: str,
        public_key: bytes,
    ) -> WorkerRecord:
        if not code or len(code) < 32:
            raise PairingError("pairing code is invalid")
        code_hash = self._hash_pairing_code(code)
        now = time.time()
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM pairing_codes WHERE code_hash = ?", (code_hash,)
            ).fetchone()
            if row is None:
                raise PairingError("pairing code is invalid")
            if row["used_at"] is not None:
                raise PairingError("pairing code has already been used")
            if row["attempts"] >= row["max_attempts"]:
                raise PairingError("pairing code has too many attempts")
            if row["expires_at"] <= now:
                raise PairingError("pairing code has expired")
            if row["team_id"] != team_id or row["agent_id"] != agent_id:
                connection.execute(
                    "UPDATE pairing_codes SET attempts = attempts + 1 WHERE code_hash = ?",
                    (code_hash,),
                )
                raise PairingError("pairing code is bound to a different Agent")

            existing = connection.execute(
                "SELECT MAX(worker_epoch) AS max_epoch FROM workers WHERE agent_id = ?", (agent_id,)
            ).fetchone()
            epoch = int(existing["max_epoch"] or 0) + 1
            connection.execute(
                "UPDATE workers SET status = 'REVOKED', revoked_at = ? WHERE agent_id = ? AND status = 'ACTIVE'",
                (now, agent_id),
            )
            connection.execute(
                "INSERT INTO workers VALUES (?, ?, ?, ?, ?, 'ACTIVE', ?, NULL, NULL)",
                (worker_id, team_id, agent_id, public_key, epoch, now),
            )
            connection.execute(
                "UPDATE pairing_codes SET used_at = ? WHERE code_hash = ?", (now, code_hash)
            )
        return WorkerRecord(worker_id, team_id, agent_id, public_key, epoch, "ACTIVE", now, None, None)

    def get_worker(self, worker_id: str) -> WorkerRecord | None:
        row = self.connection.execute("SELECT * FROM workers WHERE id = ?", (worker_id,)).fetchone()
        if row is None:
            return None
        return self._worker_from_row(row)

    def get_active_worker(self, agent_id: str) -> WorkerRecord | None:
        row = self.connection.execute(
            "SELECT * FROM workers WHERE agent_id = ? AND status = 'ACTIVE' ORDER BY worker_epoch DESC LIMIT 1",
            (agent_id,),
        ).fetchone()
        return None if row is None else self._worker_from_row(row)

    def _worker_from_row(self, row: sqlite3.Row) -> WorkerRecord:
        return WorkerRecord(
            id=row["id"],
            team_id=row["team_id"],
            agent_id=row["agent_id"],
            public_key=bytes(row["public_key"]),
            worker_epoch=int(row["worker_epoch"]),
            status=row["status"],
            paired_at=float(row["paired_at"]),
            revoked_at=None if row["revoked_at"] is None else float(row["revoked_at"]),
            last_seen_at=None if row["last_seen_at"] is None else float(row["last_seen_at"]),
        )

    def touch_worker(self, worker_id: str, worker_epoch: int, seen_at: float | None = None) -> WorkerRecord:
        seen_at = time.time() if seen_at is None else seen_at
        with self._transaction() as connection:
            result = connection.execute(
                "UPDATE workers SET last_seen_at = ? WHERE id = ? AND worker_epoch = ? AND status = 'ACTIVE'",
                (seen_at, worker_id, worker_epoch),
            )
            if result.rowcount != 1:
                worker = self.get_worker(worker_id)
                if worker is None:
                    raise WorkerNotFound(worker_id)
                raise PairingError("worker is not active for this epoch")
        worker = self.get_worker(worker_id)
        assert worker is not None
        return worker

    def revoke_worker(self, worker_id: str) -> WorkerRecord:
        with self._transaction() as connection:
            result = connection.execute(
                "UPDATE workers SET status = 'REVOKED', revoked_at = ? WHERE id = ? AND status = 'ACTIVE'",
                (time.time(), worker_id),
            )
            if result.rowcount != 1:
                worker = self.get_worker(worker_id)
                if worker is None:
                    raise WorkerNotFound(worker_id)
        worker = self.get_worker(worker_id)
        assert worker is not None
        return worker

    def create_task(self, recipient_agent_id: str, payload: str) -> TaskRecord:
        if self.get_agent(recipient_agent_id) is None:
            raise GatewayError("recipient Agent does not exist")
        now = time.time()
        task = TaskRecord(self._id(), recipient_agent_id, payload, "QUEUED", now)
        with self._transaction() as connection:
            worker = connection.execute(
                "SELECT 1 FROM workers WHERE agent_id = ? AND status = 'ACTIVE' LIMIT 1",
                (recipient_agent_id,),
            ).fetchone()
            if worker is None:
                raise NoActiveWorker(recipient_agent_id)
            connection.execute(
                "INSERT INTO tasks VALUES (?, ?, ?, ?, ?)",
                (task.id, task.recipient_agent_id, task.payload, task.state, task.created_at),
            )
        return task

    def get_task(self, task_id: str) -> TaskRecord | None:
        row = self.connection.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
        if row is None:
            return None
        return TaskRecord(row["id"], row["recipient_agent_id"], row["payload"], row["state"], row["created_at"])

    def workers_table_columns(self) -> list[str]:
        return [row["name"] for row in self.connection.execute("PRAGMA table_info(workers)").fetchall()]
