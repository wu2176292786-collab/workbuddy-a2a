"""Minimal MFA/RBAC admin control plane, audit log, and data governance."""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Mapping

from .errors import AdminAuthorizationError, MFARequiredError, ResourceLimitError
from .isolation import TaskTemplate


SENSITIVE_KEYS = {
    "password", "secret", "token", "access_token", "api_key", "private_key",
    "fencing_token", "confirmation_nonce", "mfa_secret", "email", "phone",
}

ROLE_PERMISSIONS = {
    "viewer": {"audit:read", "task:read", "worker:read", "template:read"},
    "operator": {"audit:read", "task:read", "worker:read", "worker:manage", "member:manage", "template:read"},
    "security_admin": {"audit:read", "audit:export", "task:read", "worker:read", "worker:manage", "member:manage", "template:read", "template:manage", "data:export", "data:delete", "limits:manage"},
    "owner": {"*"},
}


def redact(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): ("[REDACTED]" if str(key).lower() in SENSITIVE_KEYS else redact(item)) for key, item in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, tuple):
        return [redact(item) for item in value]
    return value


@dataclass(frozen=True)
class AdminPrincipal:
    admin_id: str
    team_id: str
    role: str
    mfa_verified: bool


class AdminService:
    """Team-scoped admin service backed by the existing SQLite Gateway store."""

    def __init__(self, store: Any, *, audit_retention_days: int = 30, task_content_retention_days: int = 7, mfa_validator: Callable[[str, str], bool] | None = None) -> None:
        self.store = store
        self.audit_retention_days = audit_retention_days
        self.task_content_retention_days = task_content_retention_days
        self.mfa_validator = mfa_validator or (lambda _admin_id, code: code == "test-mfa")
        self._initialize()

    def _initialize(self) -> None:
        self.store.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS admin_subject_state (
                team_id TEXT NOT NULL,
                subject_type TEXT NOT NULL,
                subject_id TEXT NOT NULL,
                status TEXT NOT NULL,
                updated_at REAL NOT NULL,
                PRIMARY KEY (team_id, subject_type, subject_id)
            );
            CREATE TABLE IF NOT EXISTS admin_audit (
                id TEXT PRIMARY KEY,
                team_id TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                action TEXT NOT NULL,
                target_type TEXT,
                target_id TEXT,
                metadata_json TEXT NOT NULL,
                created_at REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS admin_audit_team_time ON admin_audit(team_id, created_at);
            CREATE TABLE IF NOT EXISTS admin_templates (
                team_id TEXT NOT NULL,
                template_id TEXT NOT NULL,
                version TEXT NOT NULL,
                status TEXT NOT NULL,
                definition_json TEXT NOT NULL,
                updated_at REAL NOT NULL,
                PRIMARY KEY (team_id, template_id, version)
            );
            CREATE TABLE IF NOT EXISTS admin_limits (
                team_id TEXT PRIMARY KEY,
                active_tasks INTEGER NOT NULL,
                max_rounds INTEGER NOT NULL,
                max_bytes INTEGER NOT NULL,
                event_frequency INTEGER NOT NULL,
                queue_depth INTEGER NOT NULL,
                updated_at REAL NOT NULL
            );
            """
        )
        self.store.connection.commit()

    def authenticate(self, admin_id: str, team_id: str, *, role: str = "viewer", mfa_code: str) -> AdminPrincipal:
        if role not in ROLE_PERMISSIONS:
            raise AdminAuthorizationError("unknown admin role")
        if not self.mfa_validator(admin_id, mfa_code):
            raise MFARequiredError("valid MFA verification is required")
        return AdminPrincipal(admin_id, team_id, role, True)

    def _authorize(self, principal: AdminPrincipal, permission: str) -> None:
        if not principal.mfa_verified:
            raise MFARequiredError("admin action requires MFA")
        permissions = ROLE_PERMISSIONS.get(principal.role, set())
        if "*" not in permissions and permission not in permissions:
            raise AdminAuthorizationError(f"role {principal.role!r} cannot perform {permission}")
        team = self.store.connection.execute("SELECT 1 FROM teams WHERE id = ?", (principal.team_id,)).fetchone()
        if team is None:
            raise AdminAuthorizationError("admin principal is not bound to an existing Team")

    def _audit(self, principal: AdminPrincipal, action: str, *, target_type: str | None = None, target_id: str | None = None, metadata: Mapping[str, Any] | None = None) -> None:
        self.store.connection.execute(
            "INSERT INTO admin_audit VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (str(uuid.uuid4()), principal.team_id, principal.admin_id, action, target_type, target_id, json.dumps(redact(metadata or {}), sort_keys=True, ensure_ascii=False), time.time()),
        )
        self.store.connection.commit()

    def _subject_status(self, team_id: str, subject_type: str, subject_id: str) -> str:
        row = self.store.connection.execute("SELECT status FROM admin_subject_state WHERE team_id = ? AND subject_type = ? AND subject_id = ?", (team_id, subject_type, subject_id)).fetchone()
        return "ACTIVE" if row is None else str(row["status"])

    def _set_subject_status(self, principal: AdminPrincipal, subject_type: str, subject_id: str, status: str) -> None:
        self.store.connection.execute(
            "INSERT INTO admin_subject_state(team_id, subject_type, subject_id, status, updated_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT(team_id, subject_type, subject_id) DO UPDATE SET status = excluded.status, updated_at = excluded.updated_at",
            (principal.team_id, subject_type, subject_id, status, time.time()),
        )
        self.store.connection.commit()

    def create_member(self, principal: AdminPrincipal, name: str) -> Any:
        self._authorize(principal, "member:manage")
        member = self.store.create_user(principal.team_id, name)
        self._audit(principal, "member_created", target_type="user", target_id=member.id, metadata={"name": member.name})
        return member

    def suspend_member(self, principal: AdminPrincipal, user_id: str) -> None:
        self._authorize(principal, "member:manage")
        self._set_subject_status(principal, "user", user_id, "SUSPENDED")
        self._audit(principal, "member_suspended", target_type="user", target_id=user_id)

    def remove_member(self, principal: AdminPrincipal, user_id: str) -> None:
        self._authorize(principal, "member:manage")
        self._set_subject_status(principal, "user", user_id, "REMOVED")
        self._audit(principal, "member_removed", target_type="user", target_id=user_id)

    def create_agent(self, principal: AdminPrincipal, user_id: str, name: str) -> Any:
        self._authorize(principal, "member:manage")
        if self._subject_status(principal.team_id, "user", user_id) != "ACTIVE":
            raise AdminAuthorizationError("suspended or removed member cannot receive an Agent")
        agent = self.store.create_agent(principal.team_id, user_id, name)
        self._audit(principal, "agent_created", target_type="agent", target_id=agent.id, metadata={"name": agent.name, "user_id": user_id})
        return agent

    def suspend_agent(self, principal: AdminPrincipal, agent_id: str) -> None:
        self._authorize(principal, "member:manage")
        self._set_subject_status(principal, "agent", agent_id, "SUSPENDED")
        self._audit(principal, "agent_suspended", target_type="agent", target_id=agent_id)

    def remove_agent(self, principal: AdminPrincipal, agent_id: str) -> None:
        self._authorize(principal, "member:manage")
        self._set_subject_status(principal, "agent", agent_id, "REMOVED")
        self._audit(principal, "agent_removed", target_type="agent", target_id=agent_id)

    def create_pairing_code(self, principal: AdminPrincipal, agent_id: str, *, ttl_seconds: int = 600, max_attempts: int = 5) -> Any:
        self._authorize(principal, "worker:manage")
        code = self.store.create_pairing_code(principal.team_id, agent_id, ttl_seconds, max_attempts)
        self._audit(principal, "pairing_approved", target_type="agent", target_id=agent_id, metadata={"expires_at": code.expires_at})
        return code

    def revoke_worker(self, principal: AdminPrincipal, worker_id: str) -> Any:
        self._authorize(principal, "worker:manage")
        worker = self.store.get_worker(worker_id)
        if worker is None or worker.team_id != principal.team_id:
            raise AdminAuthorizationError("Worker is outside the admin Team")
        record = self.store.revoke_worker(worker_id)
        self._audit(principal, "worker_revoked", target_type="worker", target_id=worker_id)
        return record

    def publish_template(self, principal: AdminPrincipal, template: TaskTemplate) -> TaskTemplate:
        self._authorize(principal, "template:manage")
        self.store.connection.execute(
            "INSERT INTO admin_templates VALUES (?, ?, ?, 'ACTIVE', ?, ?) ON CONFLICT(team_id, template_id, version) DO UPDATE SET status = 'ACTIVE', definition_json = excluded.definition_json, updated_at = excluded.updated_at",
            (principal.team_id, template.template_id, str(template.version), json.dumps(template.as_dict(), sort_keys=True, ensure_ascii=False), time.time()),
        )
        self.store.connection.commit()
        self._audit(principal, "template_published", target_type="template", target_id=f"{template.template_id}:{template.version}", metadata={"definition": template.as_dict()})
        return template

    def suspend_template(self, principal: AdminPrincipal, template_id: str, version: str | int) -> None:
        self._authorize(principal, "template:manage")
        result = self.store.connection.execute("UPDATE admin_templates SET status = 'SUSPENDED', updated_at = ? WHERE team_id = ? AND template_id = ? AND version = ?", (time.time(), principal.team_id, template_id, str(version)))
        if result.rowcount != 1:
            raise AdminAuthorizationError("template does not exist in the admin Team")
        self.store.connection.commit()
        self._audit(principal, "template_suspended", target_type="template", target_id=f"{template_id}:{version}")

    def list_templates(self, principal: AdminPrincipal) -> list[dict[str, Any]]:
        self._authorize(principal, "template:read")
        rows = self.store.connection.execute("SELECT * FROM admin_templates WHERE team_id = ? ORDER BY template_id, version", (principal.team_id,)).fetchall()
        return [{"template_id": row["template_id"], "version": row["version"], "status": row["status"], "definition": redact(json.loads(row["definition_json"]))} for row in rows]

    def audit_events(self, principal: AdminPrincipal, *, limit: int = 100, action: str | None = None) -> list[dict[str, Any]]:
        self._authorize(principal, "audit:read")
        query = "SELECT * FROM admin_audit WHERE team_id = ?"
        args: list[Any] = [principal.team_id]
        if action is not None:
            query += " AND action = ?"
            args.append(action)
        query += " ORDER BY created_at DESC LIMIT ?"
        args.append(max(1, min(limit, 1000)))
        rows = self.store.connection.execute(query, tuple(args)).fetchall()
        return [{"id": row["id"], "team_id": row["team_id"], "actor_id": row["actor_id"], "action": row["action"], "target_type": row["target_type"], "target_id": row["target_id"], "metadata": redact(json.loads(row["metadata_json"])), "created_at": row["created_at"]} for row in rows]

    def export_task(self, principal: AdminPrincipal, task_id: str) -> dict[str, Any]:
        self._authorize(principal, "data:export")
        task = self.store.get_task(task_id)
        if task is None or task.team_id != principal.team_id:
            raise AdminAuthorizationError("Task is outside the admin Team")
        exported = {"task": redact({"id": task.id, "team_id": task.team_id, "sender_agent_id": task.sender_agent_id, "recipient_agent_id": task.recipient_agent_id, "template_id": task.template_id, "template_version": task.template_version, "input_data": task.input_data, "scope": task.scope, "permissions": task.permissions, "task_hash": task.task_hash, "state": task.state, "state_version": task.state_version}), "events": redact(self.store.get_task_events(task_id))}
        self._audit(principal, "task_exported", target_type="task", target_id=task_id, metadata={"fields": list(exported["task"].keys())})
        return exported

    def delete_task_content(self, principal: AdminPrincipal, task_id: str) -> None:
        self._authorize(principal, "data:delete")
        task = self.store.get_task(task_id)
        if task is None or task.team_id != principal.team_id:
            raise AdminAuthorizationError("Task is outside the admin Team")
        self.store.connection.execute("UPDATE tasks SET payload = ?, input_json = ?, updated_at = ? WHERE id = ?", ("[REDACTED]", json.dumps({"redacted": True}), time.time(), task_id))
        self.store.connection.commit()
        self._audit(principal, "task_content_deleted", target_type="task", target_id=task_id)

    def purge_audit(self, principal: AdminPrincipal, *, now: float | None = None) -> int:
        self._authorize(principal, "data:delete")
        cutoff = (time.time() if now is None else now) - self.audit_retention_days * 86400
        result = self.store.connection.execute("DELETE FROM admin_audit WHERE team_id = ? AND created_at < ?", (principal.team_id, cutoff))
        self.store.connection.commit()
        self._audit(principal, "audit_purged", metadata={"deleted_count": result.rowcount, "cutoff": cutoff})
        return result.rowcount

    def configure_limits(self, principal: AdminPrincipal, *, active_tasks: int, max_rounds: int, max_bytes: int, event_frequency: int, queue_depth: int) -> None:
        self._authorize(principal, "limits:manage")
        values = (active_tasks, max_rounds, max_bytes, event_frequency, queue_depth)
        if any(not isinstance(value, int) or value < 1 for value in values):
            raise ResourceLimitError("resource limits must be positive integers")
        self.store.connection.execute("INSERT INTO admin_limits VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(team_id) DO UPDATE SET active_tasks = excluded.active_tasks, max_rounds = excluded.max_rounds, max_bytes = excluded.max_bytes, event_frequency = excluded.event_frequency, queue_depth = excluded.queue_depth, updated_at = excluded.updated_at", (principal.team_id, *values, time.time()))
        self.store.connection.commit()
        self._audit(principal, "limits_configured", metadata={"active_tasks": active_tasks, "max_rounds": max_rounds, "max_bytes": max_bytes, "event_frequency": event_frequency, "queue_depth": queue_depth})

    def check_limits(self, team_id: str, *, active_tasks: int = 0, rounds: int = 0, bytes_used: int = 0, events: int = 0, queue_depth: int = 0) -> None:
        row = self.store.connection.execute("SELECT * FROM admin_limits WHERE team_id = ?", (team_id,)).fetchone()
        if row is None:
            return
        checks = (("active_tasks", active_tasks, row["active_tasks"]), ("rounds", rounds, row["max_rounds"]), ("bytes", bytes_used, row["max_bytes"]), ("events", events, row["event_frequency"]), ("queue_depth", queue_depth, row["queue_depth"]))
        for name, actual, maximum in checks:
            if actual > maximum:
                raise ResourceLimitError(f"{name} limit exceeded: {actual} > {maximum}")
