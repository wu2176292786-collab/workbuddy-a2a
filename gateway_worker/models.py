from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Team:
    id: str
    name: str
    created_at: float


@dataclass(frozen=True)
class User:
    id: str
    team_id: str
    name: str
    created_at: float


@dataclass(frozen=True)
class Agent:
    id: str
    team_id: str
    user_id: str
    name: str
    created_at: float


@dataclass(frozen=True)
class BootstrapResult:
    team: Team
    user: User
    agent: Agent


@dataclass(frozen=True)
class PairingCode:
    code: str
    team_id: str
    agent_id: str
    expires_at: float
    max_attempts: int


@dataclass(frozen=True)
class WorkerRecord:
    id: str
    team_id: str
    agent_id: str
    public_key: bytes
    worker_epoch: int
    status: str
    paired_at: float
    revoked_at: float | None
    last_seen_at: float | None


@dataclass(frozen=True)
class TaskRecord:
    id: str
    recipient_agent_id: str
    payload: str
    state: str
    created_at: float
