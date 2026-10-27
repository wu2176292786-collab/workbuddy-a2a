from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sqlite3
import time
import uuid
from contextlib import contextmanager
from typing import Iterator

from .canonical import compute_task_hash, hash_capability, normalize_expiry, normalize_json
from .errors import (
    ConfirmationError,
    FencingError,
    GatewayError,
    InvalidTransitionError,
    NoActiveWorker,
    PairingError,
    StateConflictError,
    TaskExpired,
    TerminalTaskError,
    WorkerNotFound,
)
from .models import Agent, BootstrapResult, PairingCode, TaskRecord, Team, User, WorkerRecord

_UNSET = object()
TERMINAL_STATES = {"REJECTED", "COMPLETED", "FAILED", "CANCELLED", "EXPIRED"}
TASK_TRANSITIONS = {
    "CREATED": {"WAITING_RECIPIENT_CONFIRM", "EXPIRED", "CANCELLED"},
    "WAITING_RECIPIENT_CONFIRM": {"ACCEPTED", "REJECTED", "EXPIRED", "CANCELLED"},
    "ACCEPTED": {"RUNNING", "CANCEL_REQUESTED", "CANCELLED"},
    "RUNNING": {"NEEDS_INPUT", "NEEDS_ATTENTION", "CANCEL_REQUESTED", "COMPLETED", "FAILED"},
    "NEEDS_INPUT": {"RUNNING", "NEEDS_ATTENTION", "CANCELLED"},
    "NEEDS_ATTENTION": {"RUNNING", "FAILED", "CANCELLED"},
    "CANCEL_REQUESTED": {"CANCELLED", "RUNNING"},
}


def decode_json_value(value: str | None) -> object:
    if value is None:
        return None
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return None


class SQLiteStore:
    """Durable Gateway state for the PoC.

    The store intentionally has no private-key column. A Worker private key is
    created and retained by the Worker-side credential store; the Gateway only
    receives the corresponding public key during pairing.
    """

    def __init__(self, path: str = "gateway.db") -> None:
        self.connection = sqlite3.connect(path, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self._task_secrets: dict[str, tuple[str, str]] = {}
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
                team_id TEXT,
                sender_agent_id TEXT,
                recipient_agent_id TEXT NOT NULL REFERENCES agents(id),
                payload TEXT NOT NULL,
                template_id TEXT,
                template_version TEXT,
                input_json TEXT,
                scope_json TEXT,
                permissions_json TEXT,
                expires_at REAL,
                task_hash TEXT,
                confirmation_nonce_hash TEXT,
                confirmation_consumed_at REAL,
                confirmed_by_agent_id TEXT,
                confirmed_at REAL,
                state TEXT NOT NULL,
                state_version INTEGER NOT NULL DEFAULT 0,
                worker_id TEXT,
                worker_epoch INTEGER,
                fencing_token_hash TEXT,
                lease_expires_at REAL,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS task_events (
                id TEXT PRIMARY KEY,
                task_id TEXT NOT NULL REFERENCES tasks(id),
                from_state TEXT,
                to_state TEXT NOT NULL,
                state_version INTEGER NOT NULL,
                worker_id TEXT,
                worker_epoch INTEGER,
                reason TEXT,
                created_at REAL NOT NULL
            );
            """
        )
        self._migrate_tasks_table()
        self.connection.commit()

    def _migrate_tasks_table(self) -> None:
        columns = {row["name"] for row in self.connection.execute("PRAGMA table_info(tasks)").fetchall()}
        additions = {
            "team_id": "TEXT",
            "sender_agent_id": "TEXT",
            "template_id": "TEXT",
            "template_version": "TEXT",
            "input_json": "TEXT",
            "scope_json": "TEXT",
            "permissions_json": "TEXT",
            "expires_at": "REAL",
            "task_hash": "TEXT",
            "confirmation_nonce_hash": "TEXT",
            "confirmation_consumed_at": "REAL",
            "confirmed_by_agent_id": "TEXT",
            "confirmed_at": "REAL",
            "state_version": "INTEGER NOT NULL DEFAULT 0",
            "worker_id": "TEXT",
            "worker_epoch": "INTEGER",
            "fencing_token_hash": "TEXT",
            "lease_expires_at": "REAL",
            "updated_at": "REAL NOT NULL DEFAULT 0",
        }
        for name, definition in additions.items():
            if name not in columns:
                self.connection.execute(f"ALTER TABLE tasks ADD COLUMN {name} {definition}")
        self.connection.execute("UPDATE tasks SET updated_at = created_at WHERE updated_at = 0")

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

    def create_user(self, team_id: str, name: str) -> User:
        if self.connection.execute("SELECT 1 FROM teams WHERE id = ?", (team_id,)).fetchone() is None:
            raise GatewayError("team does not exist")
        if not isinstance(name, str) or not name.strip():
            raise GatewayError("user name is required")
        user = User(self._id(), team_id, name.strip(), time.time())
        with self._transaction() as connection:
            connection.execute("INSERT INTO users VALUES (?, ?, ?, ?)", (user.id, user.team_id, user.name, user.created_at))
        return user

    def create_agent(self, team_id: str, user_id: str, name: str) -> Agent:
        user = self.connection.execute(
            "SELECT team_id FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        if user is None or user["team_id"] != team_id:
            raise GatewayError("user is not a member of the requested team")
        if not isinstance(name, str) or not name.strip():
            raise GatewayError("agent name is required")
        agent = Agent(self._id(), team_id, user_id, name.strip(), time.time())
        with self._transaction() as connection:
            connection.execute(
                "INSERT INTO agents VALUES (?, ?, ?, ?, ?)",
                (agent.id, agent.team_id, agent.user_id, agent.name, agent.created_at),
            )
        return agent

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

    def create_legacy_task(self, recipient_agent_id: str, payload: str) -> TaskRecord:
        recipient = self.get_agent(recipient_agent_id)
        if recipient is None:
            raise GatewayError("recipient Agent does not exist")
        return self.create_authorized_task(
            team_id=recipient.team_id,
            sender_agent_id=recipient_agent_id,
            recipient_agent_id=recipient_agent_id,
            template_id="legacy",
            template_version="1",
            input_data={"payload": payload},
            scope={},
            permissions=[],
            expires_at=time.time() + 24 * 60 * 60,
            initial_state="QUEUED",
        )

    def create_authorized_task(
        self,
        *,
        team_id: str,
        sender_agent_id: str,
        recipient_agent_id: str,
        template_id: str,
        template_version: str | int,
        input_data: object,
        scope: object,
        permissions: object,
        expires_at: object,
        lease_ttl_seconds: int = 60,
        initial_state: str = "WAITING_RECIPIENT_CONFIRM",
    ) -> TaskRecord:
        sender = self.get_agent(sender_agent_id)
        recipient = self.get_agent(recipient_agent_id)
        if sender is None or recipient is None:
            raise GatewayError("sender and recipient Agents must exist")
        if sender.team_id != team_id or recipient.team_id != team_id:
            raise GatewayError("sender and recipient must belong to the requested Team")
        if not isinstance(template_id, str) or not template_id.strip():
            raise GatewayError("template_id is required")
        if not isinstance(lease_ttl_seconds, int) or not 1 <= lease_ttl_seconds <= 24 * 60 * 60:
            raise GatewayError("lease_ttl_seconds must be between 1 and 86400")
        normalized_input = normalize_json(input_data)
        normalized_scope = normalize_json(scope)
        normalized_permissions = normalize_json(permissions)
        normalized_expiry = normalize_expiry(expires_at)
        task_hash = compute_task_hash(
            sender_agent_id=sender_agent_id,
            recipient_agent_id=recipient_agent_id,
            template_id=template_id.strip(),
            template_version=str(template_version),
            input_data=normalized_input,
            scope=normalized_scope,
            permissions=normalized_permissions,
            expires_at=normalized_expiry,
        )
        now = time.time()
        nonce = secrets.token_urlsafe(32)
        fencing_token = secrets.token_urlsafe(32)
        task_id = self._id()
        worker = self.get_active_worker(recipient_agent_id)
        if worker is None:
            raise NoActiveWorker(recipient_agent_id)
        lease_expires_at = min(normalized_expiry, now + lease_ttl_seconds)
        payload = json.dumps(normalized_input, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        with self._transaction() as connection:
            connection.execute(
                """
                INSERT INTO tasks (
                    id, team_id, sender_agent_id, recipient_agent_id, payload,
                    template_id, template_version, input_json, scope_json, permissions_json,
                    expires_at, task_hash, confirmation_nonce_hash, state, state_version,
                    worker_id, worker_epoch, fencing_token_hash, lease_expires_at,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?)
                """,
                (
                    task_id,
                    team_id,
                    sender_agent_id,
                    recipient_agent_id,
                    payload,
                    template_id.strip(),
                    str(template_version),
                    json.dumps(normalized_input, sort_keys=True, separators=(",", ":"), ensure_ascii=False),
                    json.dumps(normalized_scope, sort_keys=True, separators=(",", ":"), ensure_ascii=False),
                    json.dumps(normalized_permissions, sort_keys=True, separators=(",", ":"), ensure_ascii=False),
                    normalized_expiry,
                    task_hash,
                    hash_capability(nonce),
                    initial_state,
                    worker.id,
                    worker.worker_epoch,
                    hash_capability(fencing_token),
                    lease_expires_at,
                    now,
                    now,
                ),
            )
            self._insert_event(connection, task_id, None, initial_state, 1, worker.id, worker.worker_epoch, "created")
        self._task_secrets[task_id] = (nonce, fencing_token)
        row = self.connection.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
        assert row is not None
        return self._task_from_row(row, confirmation_nonce=nonce, fencing_token=fencing_token)

    def get_task(self, task_id: str, *, include_secrets: bool = False) -> TaskRecord | None:
        row = self.connection.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
        if row is None:
            return None
        secrets_for_task = self._task_secrets.get(task_id) if include_secrets else None
        return self._task_from_row(
            row,
            confirmation_nonce=None if secrets_for_task is None else secrets_for_task[0],
            fencing_token=None if secrets_for_task is None else secrets_for_task[1],
        )

    def _task_from_row(
        self,
        row: sqlite3.Row,
        *,
        confirmation_nonce: str | None = None,
        fencing_token: str | None = None,
    ) -> TaskRecord:
        def decode(name: str, fallback: object = None) -> object:
            value = row[name]
            if value is None:
                return fallback
            try:
                return json.loads(value)
            except (TypeError, json.JSONDecodeError):
                return fallback

        return TaskRecord(
            id=row["id"],
            recipient_agent_id=row["recipient_agent_id"],
            payload=row["payload"],
            state=row["state"],
            created_at=float(row["created_at"]),
            team_id=row["team_id"],
            sender_agent_id=row["sender_agent_id"],
            template_id=row["template_id"],
            template_version=row["template_version"],
            input_data=decode("input_json"),
            scope=decode("scope_json"),
            permissions=decode("permissions_json"),
            expires_at=None if row["expires_at"] is None else float(row["expires_at"]),
            task_hash=row["task_hash"],
            confirmation_nonce=confirmation_nonce,
            state_version=int(row["state_version"] or 0),
            worker_id=row["worker_id"],
            worker_epoch=None if row["worker_epoch"] is None else int(row["worker_epoch"]),
            fencing_token=fencing_token,
            lease_expires_at=None if row["lease_expires_at"] is None else float(row["lease_expires_at"]),
            updated_at=None if row["updated_at"] is None else float(row["updated_at"]),
        )

    def transition_task(
        self,
        task_id: str,
        *,
        expected_state_version: int,
        new_state: str,
        worker_id: str | None = None,
        worker_epoch: int | None = None,
        fencing_token: str | None = None,
        operator: bool = False,
        reason: str | None = None,
        require_fencing: bool = True,
    ) -> TaskRecord:
        terminal_error: TerminalTaskError | None = None
        with self._transaction() as connection:
            row = self._task_row(connection, task_id)
            if row is None:
                raise GatewayError("task does not exist")
            if row["state"] in TERMINAL_STATES:
                self._insert_event(
                    connection,
                    task_id,
                    row["state"],
                    row["state"],
                    int(row["state_version"] or 0),
                    worker_id,
                    worker_epoch,
                    "late_event_rejected",
                )
                terminal_error = TerminalTaskError("terminal Task cannot be reopened")
            else:
                self._assert_transition(row, new_state, operator=operator)
                if int(row["state_version"] or 0) != expected_state_version:
                    raise StateConflictError("task state_version does not match expected value")
                if require_fencing:
                    self._assert_fencing(row, worker_id, worker_epoch, fencing_token)
                now = time.time()
                result = connection.execute(
                    "UPDATE tasks SET state = ?, state_version = state_version + 1, updated_at = ? WHERE id = ? AND state_version = ?",
                    (new_state, now, task_id, expected_state_version),
                )
                if result.rowcount != 1:
                    raise StateConflictError("task state changed concurrently")
                self._insert_event(
                    connection,
                    task_id,
                    row["state"],
                    new_state,
                    expected_state_version + 1,
                    worker_id,
                    worker_epoch,
                    reason,
                )
        if terminal_error is not None:
            raise terminal_error
        return self.get_task(task_id)  # type: ignore[return-value]

    def confirm_task(
        self,
        task_id: str,
        *,
        decision: str,
        task_hash: str,
        confirmation_nonce: str,
        confirmation_expires_at: object,
        recipient_agent_id: str,
        expected_state_version: int,
        worker_id: str,
        worker_epoch: int,
        fencing_token: str,
    ) -> TaskRecord:
        expired = False
        with self._transaction() as connection:
            row = self._task_row(connection, task_id)
            if row is None:
                raise GatewayError("task does not exist")
            if row["state"] in TERMINAL_STATES:
                raise ConfirmationError("task is already terminal")
            if row["state"] != "WAITING_RECIPIENT_CONFIRM":
                raise ConfirmationError("task is not waiting for recipient confirmation")
            if int(row["state_version"] or 0) != expected_state_version:
                raise StateConflictError("task state_version does not match expected value")
            now = time.time()
            if row["expires_at"] is not None and float(row["expires_at"]) <= now:
                self._cas_transition_locked(connection, row, "EXPIRED", expected_state_version, "expired")
                expired = True
            else:
                try:
                    envelope_expiry = normalize_expiry(confirmation_expires_at)
                except ValueError as error:
                    raise ConfirmationError("confirmation expiry is invalid") from error
                if (
                    not hmac.compare_digest(str(row["task_hash"]), str(task_hash))
                    or not hmac.compare_digest(str(row["confirmation_nonce_hash"]), hash_capability(confirmation_nonce))
                    or row["recipient_agent_id"] != recipient_agent_id
                    or float(row["expires_at"]) != envelope_expiry
                ):
                    raise ConfirmationError("confirmation envelope does not match the immutable Task authorization")
                self._assert_fencing(row, worker_id, worker_epoch, fencing_token)
                normalized_decision = decision.lower()
                if normalized_decision == "accept":
                    new_state = "ACCEPTED"
                elif normalized_decision == "reject":
                    new_state = "REJECTED"
                else:
                    raise ConfirmationError("decision must be accept or reject")
                self._cas_transition_locked(
                    connection,
                    row,
                    new_state,
                    expected_state_version,
                    f"recipient_{normalized_decision}",
                    confirmation_nonce_consumed=True,
                    confirmed_by_agent_id=recipient_agent_id,
                )
        if expired:
            raise TaskExpired("task confirmation has expired")
        return self.get_task(task_id)  # type: ignore[return-value]

    def update_task_authorization(
        self,
        task_id: str,
        *,
        expected_state_version: int,
        sender_agent_id: str | None = None,
        recipient_agent_id: str | None = None,
        template_id: str | None = None,
        template_version: str | int | None = None,
        input_data: object = _UNSET,
        scope: object = _UNSET,
        permissions: object = _UNSET,
        expires_at: object = _UNSET,
    ) -> TaskRecord:
        with self._transaction() as connection:
            row = self._task_row(connection, task_id)
            if row is None:
                raise GatewayError("task does not exist")
            if row["state"] in TERMINAL_STATES:
                raise TerminalTaskError("terminal task authorization cannot be changed")
            if int(row["state_version"] or 0) != expected_state_version:
                raise StateConflictError("task state_version does not match expected value")
            sender_id = sender_agent_id or row["sender_agent_id"]
            recipient_id = recipient_agent_id or row["recipient_agent_id"]
            sender = self.get_agent(sender_id)
            recipient = self.get_agent(recipient_id)
            if sender is None or recipient is None or sender.team_id != row["team_id"] or recipient.team_id != row["team_id"]:
                raise GatewayError("updated sender and recipient must remain in the Task Team")
            new_template_id = template_id or row["template_id"]
            new_template_version = str(template_version if template_version is not None else row["template_version"])
            new_input = decode_json_value(row["input_json"]) if input_data is _UNSET else normalize_json(input_data)
            new_scope = decode_json_value(row["scope_json"]) if scope is _UNSET else normalize_json(scope)
            new_permissions = decode_json_value(row["permissions_json"]) if permissions is _UNSET else normalize_json(permissions)
            new_expiry = normalize_expiry(row["expires_at"] if expires_at is _UNSET else expires_at)
            new_hash = compute_task_hash(
                sender_agent_id=sender_id,
                recipient_agent_id=recipient_id,
                template_id=new_template_id,
                template_version=new_template_version,
                input_data=new_input,
                scope=new_scope,
                permissions=new_permissions,
                expires_at=new_expiry,
            )
            worker = self.get_active_worker(recipient_id)
            if worker is None:
                raise NoActiveWorker(recipient_id)
            nonce = secrets.token_urlsafe(32)
            fencing_token = secrets.token_urlsafe(32)
            now = time.time()
            lease_expires_at = min(new_expiry, now + 60)
            connection.execute(
                """
                UPDATE tasks SET sender_agent_id = ?, recipient_agent_id = ?, template_id = ?,
                    template_version = ?, input_json = ?, payload = ?, scope_json = ?,
                    permissions_json = ?, expires_at = ?, task_hash = ?,
                    confirmation_nonce_hash = ?, confirmation_consumed_at = NULL,
                    confirmed_by_agent_id = NULL, confirmed_at = NULL,
                    state = 'WAITING_RECIPIENT_CONFIRM', state_version = state_version + 1,
                    worker_id = ?, worker_epoch = ?, fencing_token_hash = ?,
                    lease_expires_at = ?, updated_at = ?
                WHERE id = ? AND state_version = ?
                """,
                (
                    sender_id,
                    recipient_id,
                    new_template_id,
                    new_template_version,
                    json.dumps(new_input, sort_keys=True, separators=(",", ":"), ensure_ascii=False),
                    json.dumps(new_input, sort_keys=True, separators=(",", ":"), ensure_ascii=False),
                    json.dumps(new_scope, sort_keys=True, separators=(",", ":"), ensure_ascii=False),
                    json.dumps(new_permissions, sort_keys=True, separators=(",", ":"), ensure_ascii=False),
                    new_expiry,
                    new_hash,
                    hash_capability(nonce),
                    worker.id,
                    worker.worker_epoch,
                    hash_capability(fencing_token),
                    lease_expires_at,
                    now,
                    task_id,
                    expected_state_version,
                ),
            )
            if connection.execute("SELECT changes()").fetchone()[0] != 1:
                raise StateConflictError("task state changed concurrently")
            self._insert_event(
                connection,
                task_id,
                row["state"],
                "WAITING_RECIPIENT_CONFIRM",
                expected_state_version + 1,
                worker.id,
                worker.worker_epoch,
                "authorization_changed",
            )
        updated = self.get_task(task_id)
        assert updated is not None
        self._task_secrets[task_id] = (nonce, fencing_token)
        return self._task_from_row(
            self._task_row(self.connection, task_id),
            confirmation_nonce=nonce,
            fencing_token=fencing_token,
        )

    def expire_task(self, task_id: str, *, expected_state_version: int) -> TaskRecord:
        with self._transaction() as connection:
            row = self._task_row(connection, task_id)
            if row is None:
                raise GatewayError("task does not exist")
            if row["state"] in TERMINAL_STATES:
                raise TerminalTaskError("task is already terminal")
            if row["expires_at"] is None or float(row["expires_at"]) > time.time():
                raise TaskExpired("task has not reached its expiry")
            if row["state"] not in {"CREATED", "WAITING_RECIPIENT_CONFIRM"}:
                raise InvalidTransitionError("only undelivered Tasks can expire")
            self._cas_transition_locked(connection, row, "EXPIRED", expected_state_version, "expired")
        return self.get_task(task_id)  # type: ignore[return-value]

    def _task_row(self, connection: sqlite3.Connection, task_id: str) -> sqlite3.Row | None:
        return connection.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()

    def get_task_events(self, task_id: str) -> list[dict[str, object]]:
        rows = self.connection.execute(
            "SELECT * FROM task_events WHERE task_id = ? ORDER BY state_version, created_at, id",
            (task_id,),
        ).fetchall()
        return [dict(row) for row in rows]

    def _assert_fencing(
        self,
        row: sqlite3.Row,
        worker_id: str | None,
        worker_epoch: int | None,
        fencing_token: str | None,
    ) -> None:
        if not worker_id or worker_epoch is None or not fencing_token:
            raise FencingError("worker_id, worker_epoch, and fencing_token are required")
        if row["worker_id"] != worker_id or int(row["worker_epoch"] or -1) != int(worker_epoch):
            raise FencingError("Worker identity or epoch does not match the Task lease")
        if not hmac.compare_digest(str(row["fencing_token_hash"]), hash_capability(fencing_token)):
            raise FencingError("fencing token does not match the Task lease")
        worker = self.get_worker(worker_id)
        if worker is None or worker.status != "ACTIVE" or worker.worker_epoch != int(worker_epoch):
            raise FencingError("Worker is revoked or superseded")
        if row["lease_expires_at"] is not None and float(row["lease_expires_at"]) <= time.time():
            raise FencingError("Task lease has expired")

    def _assert_transition(self, row: sqlite3.Row, new_state: str, *, operator: bool) -> None:
        current = row["state"]
        if current in TERMINAL_STATES:
            raise TerminalTaskError("terminal Task cannot be reopened")
        if current == "NEEDS_ATTENTION" and new_state == "RUNNING" and not operator:
            raise InvalidTransitionError("NEEDS_ATTENTION requires explicit operator action")
        allowed = TASK_TRANSITIONS.get(current, set())
        if new_state not in allowed:
            raise InvalidTransitionError(f"cannot transition {current} to {new_state}")

    def _cas_transition_locked(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
        new_state: str,
        expected_state_version: int,
        reason: str,
        *,
        confirmation_nonce_consumed: bool = False,
        confirmed_by_agent_id: str | None = None,
    ) -> None:
        self._assert_transition(row, new_state, operator=True)
        now = time.time()
        result = connection.execute(
            """
            UPDATE tasks SET state = ?, state_version = state_version + 1,
                confirmation_consumed_at = CASE WHEN ? THEN ? ELSE confirmation_consumed_at END,
                confirmed_by_agent_id = COALESCE(?, confirmed_by_agent_id),
                confirmed_at = CASE WHEN ? THEN ? ELSE confirmed_at END,
                updated_at = ?
            WHERE id = ? AND state_version = ?
            """,
            (
                new_state,
                1 if confirmation_nonce_consumed else 0,
                now,
                confirmed_by_agent_id,
                1 if confirmation_nonce_consumed else 0,
                now,
                now,
                row["id"],
                expected_state_version,
            ),
        )
        if result.rowcount != 1:
            raise StateConflictError("task state changed concurrently")
        self._insert_event(
            connection,
            row["id"],
            row["state"],
            new_state,
            expected_state_version + 1,
            row["worker_id"],
            row["worker_epoch"],
            reason,
        )

    @staticmethod
    def _insert_event(
        connection: sqlite3.Connection,
        task_id: str,
        from_state: str | None,
        to_state: str,
        state_version: int,
        worker_id: str | None,
        worker_epoch: int | None,
        reason: str | None,
    ) -> None:
        connection.execute(
            "INSERT INTO task_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (str(uuid.uuid4()), task_id, from_state, to_state, state_version, worker_id, worker_epoch, reason, time.time()),
        )

    def workers_table_columns(self) -> list[str]:
        return [row["name"] for row in self.connection.execute("PRAGMA table_info(workers)").fetchall()]
