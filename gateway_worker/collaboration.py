"""Deterministic Gateway/Worker collaboration contract.

The classes in this module are deliberately small, synchronous fakes.  They
model the seams a real Desktop adapter must implement without opening a real
WorkBuddy session: a command journal before UI injection, reconciliation after
an uncertain UI operation, template-defined execution evidence, at-least-once
Task events, and stable monitoring events.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Mapping

from .errors import (
    DesktopAdapterError,
    EgressError,
    GatewayError,
    InvalidTransitionError,
    IsolationError,
    ReplayError,
    ScopeViolationError,
    TaskError,
)
from .isolation import (
    EgressDecision,
    EgressStatus,
    RestrictedWorkspace,
    TaskTemplate,
    TemplateRegistry,
)


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Command:
    """Normalized instruction that is safe to hand to a Desktop adapter."""

    command_id: str
    task_id: str
    target_conversation: str
    intent: Mapping[str, Any]
    worker_epoch: int

    def __post_init__(self) -> None:
        if not self.command_id or not self.task_id or not self.target_conversation:
            raise ValueError("command_id, task_id, and target_conversation are required")
        if self.worker_epoch < 1:
            raise ValueError("worker_epoch must be positive")

    @property
    def fingerprint(self) -> str:
        return _digest(
            {
                "command_id": self.command_id,
                "task_id": self.task_id,
                "target_conversation": self.target_conversation,
                "intent": dict(self.intent),
                "worker_epoch": self.worker_epoch,
            }
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "command_id": self.command_id,
            "task_id": self.task_id,
            "target_conversation": self.target_conversation,
            "intent": dict(self.intent),
            "worker_epoch": self.worker_epoch,
        }

    to_dict = as_dict


@dataclass(frozen=True)
class ExecutionEvidence:
    """Machine-checkable evidence for a command's template-defined output."""

    task_id: str
    command_id: str
    template_id: str
    template_version: str
    result_hash: str
    output_schema: Mapping[str, Any]
    summary: str
    round_number: int
    status: str = "verified"

    @property
    def evidence_hash(self) -> str:
        return self.result_hash

    @property
    def round(self) -> int:
        return self.round_number

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "task_id": self.task_id,
            "command_id": self.command_id,
            "template_id": self.template_id,
            "template_version": self.template_version,
            "result_hash": self.result_hash,
            "output_schema": dict(self.output_schema),
            "summary": self.summary,
            "round": self.round_number,
            "status": self.status,
        }

    to_dict = as_dict


@dataclass(frozen=True)
class ResultSummary:
    task_id: str
    summary: str
    evidence: ExecutionEvidence
    recipients: tuple[str, ...]

    @property
    def text(self) -> str:
        return self.summary

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "task_id": self.task_id,
            "summary": self.summary,
            "evidence": self.evidence.as_dict(),
            "recipients": list(self.recipients),
        }

    to_dict = as_dict


@dataclass(frozen=True)
class UIReconciliation:
    command_id: str
    task_id: str
    target_conversation: str
    status: str
    reason: str
    worker_epoch: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "command_id": self.command_id,
            "task_id": self.task_id,
            "target_conversation": self.target_conversation,
            "status": self.status,
            "reason": self.reason,
            "worker_epoch": self.worker_epoch,
        }

    to_dict = as_dict


@dataclass(frozen=True)
class TaskEvent:
    """At-least-once Task event.  ``event_id`` is the replay key."""

    event_id: str
    task_id: str
    event_type: str
    round_number: int = 0
    from_agent_id: str | None = None
    to_agent_id: str | None = None
    command_id: str | None = None
    payload: Mapping[str, Any] = field(default_factory=dict)

    @property
    def message_id(self) -> str:
        return self.event_id

    @property
    def round(self) -> int:
        return self.round_number

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "event_id": self.event_id,
            "task_id": self.task_id,
            "event_type": self.event_type,
            "round": self.round_number,
            "from_agent_id": self.from_agent_id,
            "to_agent_id": self.to_agent_id,
            "command_id": self.command_id,
            "payload": dict(self.payload),
        }

    to_dict = as_dict


@dataclass(frozen=True)
class MonitoringEvent:
    """Stable monitoring envelope shared by fake and real adapters."""

    event_type: str
    task_id: str | None
    severity: str = "info"
    worker_id: str | None = None
    round_number: int | None = None
    details: Mapping[str, Any] = field(default_factory=dict)

    @property
    def round(self) -> int | None:
        return self.round_number

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "event_type": self.event_type,
            "task_id": self.task_id,
            "severity": self.severity,
            "worker_id": self.worker_id,
            "round": self.round_number,
            "details": dict(self.details),
        }

    to_dict = as_dict


@dataclass(frozen=True)
class CollaborationOutcome:
    task: Any
    rounds: tuple[int, ...]
    evidence: ExecutionEvidence
    result: ResultSummary
    events: tuple[TaskEvent, ...]


class ProtocolJournal:
    """Idempotency journal for protocol events and UI commands.

    A replay with the same key and payload returns the original result.  A
    reused key carrying different content is rejected instead of being
    silently treated as a retry.
    """

    def __init__(self) -> None:
        self._records: dict[tuple[str, str, str], tuple[str, Any]] = {}

    def record(
        self,
        *,
        namespace: str,
        task_id: str,
        key: str,
        payload: Any,
        create: Callable[[], Any],
    ) -> tuple[Any, bool]:
        if not key:
            raise ValueError("journal key is required")
        identity = (namespace, task_id, key)
        fingerprint = _digest(payload)
        existing = self._records.get(identity)
        if existing is not None:
            old_fingerprint, result = existing
            if not hmac.compare_digest(old_fingerprint, fingerprint):
                raise ReplayError("journal key was reused with different content")
            return result, True
        result = create()
        self._records[identity] = (fingerprint, result)
        return result, False

    def lookup(self, namespace: str, task_id: str, key: str) -> Any | None:
        entry = self._records.get((namespace, task_id, key))
        return None if entry is None else entry[1]

    def contains(self, namespace: str, task_id: str, key: str) -> bool:
        return (namespace, task_id, key) in self._records


class FakeDesktopAdapter:
    """Deterministic Desktop adapter with a command journal."""

    def __init__(
        self,
        *,
        worker_id: str,
        worker_epoch: int,
        conversation_id: str | None = None,
        journal: ProtocolJournal | None = None,
        workspace: RestrictedWorkspace | None = None,
        template_registry: TemplateRegistry | None = None,
    ) -> None:
        self.worker_id = worker_id
        self.worker_epoch = worker_epoch
        self.conversation_id = conversation_id or f"collaboration:{worker_id}"
        self.journal = journal or ProtocolJournal()
        self.workspace = workspace
        self.template_registry = template_registry
        self.execution_count = 0
        self._status: dict[str, str] = {}
        self._commands: dict[str, Command] = {}
        self._evidence: dict[str, ExecutionEvidence] = {}
        self.ui_errors: list[dict[str, Any]] = []

    def prepare(self, command: Command) -> Command:
        if command.worker_epoch != self.worker_epoch:
            raise ReplayError("command belongs to an old Worker epoch")
        existing = self._commands.get(command.command_id)
        if existing is not None:
            if not hmac.compare_digest(existing.fingerprint, command.fingerprint):
                raise ReplayError("command_id was reused with different content")
            return existing
        self._commands[command.command_id] = command
        self._status[command.command_id] = "prepared"
        return command

    def inject(self, command: Command) -> None:
        self.prepare(command)
        self._status[command.command_id] = "injected"

    def execute(self, command: Command, *, summary: str | None = None) -> ExecutionEvidence:
        self._authorize_command(command)
        command = self.prepare(command)
        previous = self._evidence.get(command.command_id)
        if previous is not None:
            return previous
        if self._status.get(command.command_id) == "injected":
            reconciliation = self.reconcile(command.command_id)
            if reconciliation.status != "matched":
                raise TaskError("UI command was injected but completion cannot be proven")
        self._status[command.command_id] = "injected"
        intent = dict(command.intent)
        template_id = str(intent.get("template_id", "unknown"))
        template_version = str(intent.get("template_version", "1"))
        round_number = int(intent.get("round", 1))
        input_value = intent.get("input")
        topic = input_value.get("topic") if isinstance(input_value, Mapping) else None
        default_summary = f"completed {template_id} round {round_number}"
        if topic:
            default_summary += f" for {topic}"
        result_summary = summary or str(intent.get("summary") or default_summary)
        result = {"summary": result_summary, "command_id": command.command_id, "round": round_number}
        evidence = ExecutionEvidence(
            task_id=command.task_id,
            command_id=command.command_id,
            template_id=template_id,
            template_version=template_version,
            result_hash=_digest(result),
            output_schema={"type": "object", "required": ["summary", "command_id", "round"]},
            summary=result_summary,
            round_number=round_number,
        )
        self._evidence[command.command_id] = evidence
        self._status[command.command_id] = "completed"
        self.execution_count += 1
        return evidence

    def _authorize_command(self, command: Command) -> None:
        if self.workspace is None:
            return
        intent = dict(command.intent)
        template = None
        if self.template_registry is not None:
            template = self.template_registry.resolve(intent.get("template_id", ""), intent.get("template_version", "1"))
        self.workspace.authorize_request(
            template=template,
            target_conversation=command.target_conversation,
            tools=intent.get("tools", ()),
            resources=intent.get("resources", ()),
            output_fields=intent.get("output_fields", ()),
            prompt=intent.get("prompt"),
        )

    def reconcile(self, command_id: str) -> UIReconciliation:
        command = self._commands.get(command_id)
        if command is None:
            return UIReconciliation(command_id, "", self.conversation_id, "not_found", "command_not_journaled", self.worker_epoch)
        if command_id in self._evidence:
            return UIReconciliation(command_id, command.task_id, command.target_conversation, "matched", "evidence_found", command.worker_epoch)
        if self._status.get(command_id) == "injected":
            return UIReconciliation(command_id, command.task_id, command.target_conversation, "uncertain", "injection_without_evidence", command.worker_epoch)
        return UIReconciliation(command_id, command.task_id, command.target_conversation, "not_found", "not_injected", command.worker_epoch)

    reconcile_ui = reconcile

    def command_status(self, command_id: str) -> str | None:
        return self._status.get(command_id)

    def report_ui_error(self, *, task_id: str | None, code: str, message: str) -> MonitoringEvent:
        detail = {"code": str(code), "message": str(message)}
        self.ui_errors.append(detail)
        return MonitoringEvent("ui_error", task_id, "error", self.worker_id, None, detail)

    def evidence_for(self, command_id: str) -> ExecutionEvidence | None:
        return self._evidence.get(command_id)

    def use_fallback_capability(self, capability: str) -> dict[str, Any]:
        if self.workspace is None:
            raise IsolationError("Desktop fallback capabilities require a RestrictedWorkspace")
        return self.workspace.use_capability(capability)

    use_capability = use_fallback_capability


class FakeWorker:
    """Small Worker facade used by adapter contract tests.

    It obtains its current epoch from the Gateway's active Worker record and
    accepts the per-Task fencing capabilities from the delivered Task.  The
    real Worker has the same separation between device identity and Task
    authorization, while this fake keeps the interaction deterministic.
    """

    def __init__(
        self,
        gateway: Any,
        agent_id: str,
        *,
        worker_id: str | None = None,
        adapter: FakeDesktopAdapter | None = None,
    ) -> None:
        self.gateway = gateway
        self.agent_id = agent_id
        record = gateway.store.get_worker(worker_id) if worker_id else gateway.store.get_active_worker(agent_id)
        if record is None or record.agent_id != agent_id:
            raise GatewayError("Fake Worker is not paired to this Agent")
        self.worker_id = record.id
        self.worker_epoch = record.worker_epoch
        self.adapter = adapter or FakeDesktopAdapter(worker_id=self.worker_id, worker_epoch=self.worker_epoch)

    def receive(self, task: Any) -> dict[str, Any]:
        if task.recipient_agent_id != self.agent_id:
            raise GatewayError("Task is addressed to a different Agent")
        return {
            "schema_version": 1,
            "task_id": task.id,
            "task_hash": task.task_hash,
            "recipient_agent_id": self.agent_id,
            "worker_id": self.worker_id,
            "worker_epoch": self.worker_epoch,
        }

    receive_task = receive

    def submit_task(self, *, recipient_agent_id: str, **kwargs: Any) -> Any:
        kwargs.setdefault("sender_agent_id", self.agent_id)
        kwargs["recipient_agent_id"] = recipient_agent_id
        return self.gateway.create_task(**kwargs)

    def confirm(self, task: Any, *, decision: str = "accept") -> Any:
        if not task.confirmation_nonce or not task.fencing_token:
            raise GatewayError("Task does not carry confirmation capabilities")
        return self.gateway.confirm_task(
            task.id,
            decision=decision,
            task_hash=task.task_hash,
            confirmation_nonce=task.confirmation_nonce,
            confirmation_expires_at=task.expires_at,
            recipient_agent_id=self.agent_id,
            expected_state_version=task.state_version,
            worker_id=self.worker_id,
            worker_epoch=self.worker_epoch,
            fencing_token=task.fencing_token,
        )

    send_confirmation = confirm

    def execute(self, command: Command, *, summary: str | None = None) -> ExecutionEvidence:
        return self.adapter.execute(command, summary=summary)


class FakeCollaboration:
    """End-to-end fake Worker pair built on the authoritative Gateway API."""

    CONTRACT_VERSION = 1

    def __init__(
        self,
        gateway: Any,
        *,
        journal: ProtocolJournal | None = None,
        adapters: Mapping[str, FakeDesktopAdapter] | None = None,
        template_registry: TemplateRegistry | None = None,
        workspaces: Mapping[str, RestrictedWorkspace] | None = None,
    ) -> None:
        self.gateway = gateway
        self.journal = journal or ProtocolJournal()
        self.adapters: dict[str, FakeDesktopAdapter] = dict(adapters or {})
        self.template_registry = template_registry
        self.workspaces: dict[str, RestrictedWorkspace] = dict(workspaces or {})
        self.events: list[TaskEvent] = []
        self.monitoring_events: list[MonitoringEvent] = []
        self._credentials: dict[str, tuple[str, int, str, str]] = {}
        self._tasks: dict[str, Any] = {}
        self._rounds: dict[str, int] = {}
        self._inputs: dict[str, dict[str, Any]] = {}
        self._evidence: dict[str, list[ExecutionEvidence]] = {}
        self._results: dict[str, ResultSummary] = {}

    def _adapter(self, agent_id: str, worker_id: str, worker_epoch: int) -> FakeDesktopAdapter:
        adapter = self.adapters.get(agent_id)
        if adapter is None:
            adapter = FakeDesktopAdapter(
                worker_id=worker_id,
                worker_epoch=worker_epoch,
                journal=self.journal,
                workspace=self.workspaces.get(agent_id),
                template_registry=self.template_registry,
            )
            self.adapters[agent_id] = adapter
        elif adapter.workspace is None and agent_id in self.workspaces:
            adapter.workspace = self.workspaces[agent_id]
            adapter.template_registry = self.template_registry
        return adapter

    @staticmethod
    def _scope_values(scope: Any, *names: str) -> list[str]:
        if not isinstance(scope, Mapping):
            return []
        for name in names:
            value = scope.get(name)
            if isinstance(value, str):
                return [value]
            if isinstance(value, (list, tuple, set, frozenset)):
                return [str(item) for item in value]
        return []

    def _template_for_task(self, task: Any) -> TaskTemplate | None:
        if self.template_registry is None:
            return None
        return self.template_registry.resolve(task.template_id, task.template_version)

    def _workspace_for_task(self, task: Any, *, worker_id: str, worker_epoch: int) -> RestrictedWorkspace:
        existing = self.workspaces.get(task.recipient_agent_id)
        if existing is not None:
            return existing
        template = self._template_for_task(task)
        scope = self._scope(task)
        workspace = RestrictedWorkspace(
            workspace_id=f"workspace:{task.recipient_agent_id}",
            collaboration_conversation=f"collaboration:{worker_id}",
            allowed_tools=(template.allowed_tools if template is not None else self._scope_values(scope, "tools", "allowed_tools")),
            allowed_resources=(template.allowed_resources if template is not None else self._scope_values(scope, "resources", "allowed_resources")),
        )
        self.workspaces[task.recipient_agent_id] = workspace
        return workspace

    def submit_task(self, **kwargs: Any) -> Any:
        raw_template = kwargs.get("template")
        if isinstance(raw_template, TaskTemplate):
            if self.template_registry is None:
                self.template_registry = TemplateRegistry([raw_template])
            kwargs.setdefault("template_id", raw_template.template_id)
            kwargs.setdefault("template_version", raw_template.version)
            kwargs["template"] = {"id": raw_template.template_id, "version": raw_template.version}
        if self.template_registry is not None:
            template_id = kwargs.get("template_id")
            template_version = kwargs.get("template_version")
            if isinstance(raw_template, Mapping):
                template_id = raw_template.get("id", template_id)
                template_version = raw_template.get("version", template_version)
            template = self.template_registry.resolve(str(template_id), str(template_version))
            scope = kwargs.get("scope") or {}
            requested_tools = set(self._scope_values(scope, "tools", "allowed_tools"))
            requested_resources = set(self._scope_values(scope, "resources", "allowed_resources"))
            if requested_tools - template.allowed_tools or requested_resources - template.allowed_resources:
                raise IsolationError("Task scope requests tools or resources outside the approved template")
            requested_outputs = set(self._scope_values(scope, "output_fields"))
            if requested_outputs - template.output_fields:
                raise IsolationError("Task scope requests output fields outside the approved template")
            requested_rounds = (kwargs.get("scope") or {}).get("max_rounds") if isinstance(kwargs.get("scope") or {}, Mapping) else None
            if requested_rounds is not None and int(requested_rounds) > template.max_rounds:
                raise IsolationError("Task scope requests more rounds than the approved template")
        task = self.gateway.create_task(**kwargs)
        if not task.confirmation_nonce or not task.fencing_token or task.worker_id is None or task.worker_epoch is None:
            raise GatewayError("Gateway did not return the recipient lease capabilities")
        self._tasks[task.id] = task
        self._credentials[task.id] = (task.worker_id, task.worker_epoch, task.fencing_token, task.confirmation_nonce)
        self._rounds[task.id] = 0
        if self.template_registry is not None:
            self._workspace_for_task(task, worker_id=task.worker_id, worker_epoch=task.worker_epoch)
        self._adapter(task.recipient_agent_id, task.worker_id, task.worker_epoch)
        self._emit(task.id, "task.submitted", from_agent_id=task.sender_agent_id, to_agent_id=task.recipient_agent_id)
        return task

    create_task = submit_task
    submit = submit_task

    def current_task(self, task_id: str) -> Any:
        task = self.gateway.get_task(task_id)
        if task is None:
            raise GatewayError("task does not exist")
        return task

    def task_capabilities(self, task_id: str) -> dict[str, Any]:
        """Return Worker-bound capabilities for an authenticated adapter.

        ClawBot never receives these values; the adapter uses them only when it
        has already authenticated the recipient channel and is calling the
        Gateway on behalf of that recipient.
        """
        worker_id, worker_epoch, fencing_token, confirmation_nonce = self._credential(task_id)
        return {
            "worker_id": worker_id,
            "worker_epoch": worker_epoch,
            "fencing_token": fencing_token,
            "confirmation_nonce": confirmation_nonce,
        }

    def _credential(self, task_id: str) -> tuple[str, int, str, str]:
        try:
            return self._credentials[task_id]
        except KeyError as error:
            raise GatewayError("task was not submitted through this collaboration harness") from error

    def _emit(
        self,
        task_id: str,
        event_type: str,
        *,
        event_id: str | None = None,
        round_number: int = 0,
        from_agent_id: str | None = None,
        to_agent_id: str | None = None,
        command_id: str | None = None,
        payload: Mapping[str, Any] | None = None,
    ) -> TaskEvent:
        event_id = event_id or str(uuid.uuid4())
        event = TaskEvent(
            event_id=event_id,
            task_id=task_id,
            event_type=event_type,
            round_number=round_number,
            from_agent_id=from_agent_id,
            to_agent_id=to_agent_id,
            command_id=command_id,
            payload=dict(payload or {}),
        )
        stored, duplicate = self.journal.record(
            namespace="task-event",
            task_id=task_id,
            key=event_id,
            payload=event.as_dict(),
            create=lambda: event,
        )
        if not duplicate:
            self.events.append(stored)
        return stored

    def _monitor(
        self,
        event_type: str,
        task_id: str | None,
        *,
        severity: str = "info",
        worker_id: str | None = None,
        round_number: int | None = None,
        details: Mapping[str, Any] | None = None,
    ) -> MonitoringEvent:
        event = MonitoringEvent(event_type, task_id, severity, worker_id, round_number, dict(details or {}))
        self.monitoring_events.append(event)
        return event

    def deliver_task(self, task_id: str, *, event_id: str | None = None) -> TaskEvent:
        task = self.current_task(task_id)
        event = self._emit(
            task_id,
            "task.delivered",
            event_id=event_id,
            from_agent_id=task.sender_agent_id,
            to_agent_id=task.recipient_agent_id,
            payload={"task_hash": task.task_hash},
        )
        if not self.journal.contains("monitor", task_id, event.event_id):
            self.journal.record(
                namespace="monitor",
                task_id=task_id,
                key=event.event_id,
                payload={"queue_depth": 1},
                create=lambda: self._monitor("task_backlog", task_id, worker_id=task.worker_id, details={"queue_depth": 1}),
            )
        return event

    deliver = deliver_task

    def confirm_task(self, task_id: str, *, decision: str = "accept", event_id: str | None = None) -> Any:
        task = self.current_task(task_id)
        worker_id, epoch, fencing, nonce = self._credential(task_id)
        event_key = event_id or f"confirmation:{decision.lower()}"
        payload = {"decision": decision.lower(), "task_hash": task.task_hash, "nonce": nonce}
        existing = self.journal.lookup("confirmation", task_id, event_key)
        if existing is not None:
            return existing

        def perform() -> Any:
            return self.gateway.confirm_task(
                task_id,
                decision=decision,
                task_hash=task.task_hash,
                confirmation_nonce=nonce,
                confirmation_expires_at=task.expires_at,
                recipient_agent_id=task.recipient_agent_id,
                expected_state_version=task.state_version,
                worker_id=worker_id,
                worker_epoch=epoch,
                fencing_token=fencing,
            )

        result, _ = self.journal.record(namespace="confirmation", task_id=task_id, key=event_key, payload=payload, create=perform)
        self._emit(task_id, "confirmation.accepted" if result.state == "ACCEPTED" else "confirmation.rejected", event_id=event_key, from_agent_id=task.recipient_agent_id, to_agent_id=task.sender_agent_id, payload={"state": result.state})
        return result

    confirm = confirm_task

    def start_task(self, task_id: str, *, event_id: str | None = None) -> Any:
        task = self.current_task(task_id)
        worker_id, epoch, fencing, _ = self._credential(task_id)
        key = event_id or "start"
        result, duplicate = self.journal.record(
            namespace="start",
            task_id=task_id,
            key=key,
            payload={"operation": "start"},
            create=lambda: self.gateway.start_task(task_id, expected_state_version=task.state_version, worker_id=worker_id, worker_epoch=epoch, fencing_token=fencing),
        )
        if not duplicate:
            self._emit(task_id, "task.started", event_id=key, from_agent_id=task.recipient_agent_id, to_agent_id=task.sender_agent_id)
        return result

    def _scope(self, task: Any) -> Mapping[str, Any]:
        return task.scope if isinstance(task.scope, Mapping) else {}

    def _allowed_input_keys(self, task: Any) -> set[str]:
        scope = self._scope(task)
        for name in ("allowed_input_keys", "input_fields", "needs_input_fields"):
            value = scope.get(name)
            if isinstance(value, Mapping):
                return {str(key) for key in value}
            if isinstance(value, (list, tuple, set, frozenset)):
                return {str(key) for key in value}
        return set()

    def _validate_input(self, task: Any, values: Mapping[str, Any]) -> None:
        if not isinstance(values, Mapping):
            raise ScopeViolationError("additional input must be an object")
        allowed = self._allowed_input_keys(task)
        unexpected = set(map(str, values)) - allowed
        if unexpected:
            raise ScopeViolationError(f"input fields are outside the immutable Task scope: {sorted(unexpected)}")
        max_bytes = self._scope(task).get("max_input_bytes")
        if max_bytes is not None and len(_canonical(values).encode("utf-8")) > int(max_bytes):
            raise ScopeViolationError("additional input exceeds the immutable byte budget")

    def request_input(self, task_id: str, *, fields: list[str] | tuple[str, ...], event_id: str | None = None) -> Any:
        task = self.current_task(task_id)
        requested = {str(field) for field in fields}
        self._validate_input(task, {field: None for field in requested})
        key = event_id or f"needs-input:{','.join(sorted(requested))}"
        worker_id, epoch, fencing, _ = self._credential(task_id)
        result, duplicate = self.journal.record(
            namespace="needs-input",
            task_id=task_id,
            key=key,
            payload={"fields": sorted(requested)},
            create=lambda: self.gateway.transition_task(task_id, expected_state_version=task.state_version, new_state="NEEDS_INPUT", worker_id=worker_id, worker_epoch=epoch, fencing_token=fencing, reason="recipient_needs_input"),
        )
        if not duplicate:
            self._emit(task_id, "coordination.needs_input", event_id=key, round_number=self._rounds.get(task_id, 0) + 1, from_agent_id=task.recipient_agent_id, to_agent_id=task.sender_agent_id, payload={"fields": sorted(requested)})
            self._monitor("task_needs_input", task_id, worker_id=worker_id, details={"fields": sorted(requested)})
        return result

    request_missing_input = request_input

    def provide_input(self, task_id: str, values: Mapping[str, Any], *, event_id: str | None = None) -> Any:
        task = self.current_task(task_id)
        self._validate_input(task, values)
        key = event_id or f"input:{_digest(values)}"
        worker_id, epoch, fencing, _ = self._credential(task_id)
        payload = {"values": dict(values), "state_version": task.state_version}
        result, duplicate = self.journal.record(
            namespace="input",
            task_id=task_id,
            key=key,
            payload={"values": dict(values)},
            create=lambda: self.gateway.transition_task(task_id, expected_state_version=task.state_version, new_state="RUNNING", worker_id=worker_id, worker_epoch=epoch, fencing_token=fencing, reason="sender_provided_input"),
        )
        if not duplicate:
            self._inputs[task_id] = dict(values)
            self._rounds[task_id] = self._rounds.get(task_id, 0) + 1
            self._emit(task_id, "coordination.input_provided", event_id=key, round_number=self._rounds[task_id], from_agent_id=task.sender_agent_id, to_agent_id=task.recipient_agent_id, payload={"fields": sorted(map(str, values))})
        return result

    send_input = provide_input

    def execute_round(
        self,
        task_id: str,
        *,
        round_number: int | None = None,
        event_id: str | None = None,
        requested_tools: Iterable[str] | None = None,
        requested_resources: Iterable[str] | None = None,
        output_fields: Iterable[str] | None = None,
        prompt: str | None = None,
    ) -> ExecutionEvidence:
        task = self.current_task(task_id)
        round_number = round_number or max(1, self._rounds.get(task_id, 0) + 1)
        template = self._template_for_task(task)
        max_rounds = int(self._scope(task).get("max_rounds", template.max_rounds if template is not None else 2))
        if template is not None:
            max_rounds = min(max_rounds, template.max_rounds)
        if round_number > max_rounds:
            raise ScopeViolationError("round exceeds the immutable Task scope")
        worker_id, epoch, _, _ = self._credential(task_id)
        adapter = self._adapter(task.recipient_agent_id, worker_id, epoch)
        command_input: Any = task.input_data
        if isinstance(task.input_data, Mapping) and isinstance(self._inputs.get(task_id), Mapping):
            command_input = {**task.input_data, **self._inputs[task_id]}
        elif task_id in self._inputs:
            command_input = self._inputs[task_id]
        scope_tools = list(requested_tools) if requested_tools is not None else self._scope_values(self._scope(task), "tools", "allowed_tools")
        scope_resources = list(requested_resources) if requested_resources is not None else self._scope_values(self._scope(task), "resources", "allowed_resources")
        scope_outputs = list(output_fields) if output_fields is not None else self._scope_values(self._scope(task), "output_fields")
        command = Command(
            command_id=f"{task_id}:round:{round_number}",
            task_id=task_id,
            target_conversation=adapter.conversation_id,
            intent={
                "template_id": task.template_id,
                "template_version": task.template_version,
                "round": round_number,
                "input": command_input,
                "tools": scope_tools,
                "resources": scope_resources,
                "output_fields": scope_outputs,
                "prompt": prompt,
            },
            worker_epoch=epoch,
        )
        event_key = event_id or command.command_id
        try:
            self._authorize_command(task, command, adapter)
        except IsolationError as error:
            self._record_isolation_failure(task, command, error, worker_id=worker_id, worker_epoch=epoch)
            raise
        try:
            evidence, duplicate = self.journal.record(
                namespace="execution",
                task_id=task_id,
                key=event_key,
                payload=command.as_dict(),
                create=lambda: self._execute_if_running(task_id, adapter, command),
            )
        except DesktopAdapterError as error:
            self._record_isolation_failure(task, command, error, worker_id=worker_id, worker_epoch=epoch)
            raise
        if not duplicate:
            self._evidence.setdefault(task_id, []).append(evidence)
            self._rounds[task_id] = max(self._rounds.get(task_id, 0), round_number)
            self._emit(task_id, "execution.evidence", event_id=event_key, round_number=round_number, command_id=command.command_id, from_agent_id=task.recipient_agent_id, to_agent_id=task.sender_agent_id, payload=evidence.as_dict())
            self._monitor("execution_evidence", task_id, worker_id=worker_id, round_number=round_number, details={"command_id": command.command_id, "result_hash": evidence.result_hash})
        return evidence

    def _authorize_command(self, task: Any, command: Command, adapter: FakeDesktopAdapter) -> None:
        workspace = self._workspace_for_task(task, worker_id=adapter.worker_id, worker_epoch=adapter.worker_epoch)
        template = self._template_for_task(task)
        intent = dict(command.intent)
        workspace.authorize_request(
            template=template,
            target_conversation=command.target_conversation,
            tools=intent.get("tools", ()),
            resources=intent.get("resources", ()),
            output_fields=intent.get("output_fields", ()),
            prompt=intent.get("prompt"),
        )

    def _record_isolation_failure(
        self,
        task: Any,
        command: Command,
        error: IsolationError,
        *,
        worker_id: str,
        worker_epoch: int,
    ) -> None:
        current = self.current_task(task.id)
        if current.state == "RUNNING":
            _, _, fencing, _ = self._credential(task.id)
            self.gateway.transition_task(
                task.id,
                expected_state_version=current.state_version,
                new_state="NEEDS_ATTENTION",
                worker_id=worker_id,
                worker_epoch=worker_epoch,
                fencing_token=fencing,
                reason="isolation_failure",
            )
        key = f"isolation-failure:{command.command_id}"
        self._emit(
            task.id,
            "isolation.failure",
            event_id=key,
            from_agent_id=task.recipient_agent_id,
            to_agent_id=task.sender_agent_id,
            command_id=command.command_id,
            payload={"code": error.code, "reason": str(error)},
        )
        self._monitor(
            "isolation_failure",
            task.id,
            severity="error",
            worker_id=worker_id,
            round_number=int(command.intent.get("round", 0)),
            details={"code": error.code, "reason": str(error), "command_id": command.command_id},
        )

    def _execute_if_running(self, task_id: str, adapter: FakeDesktopAdapter, command: Command) -> ExecutionEvidence:
        if self.current_task(task_id).state != "RUNNING":
            raise InvalidTransitionError("execution requires a RUNNING Task")
        return adapter.execute(command)

    def _egress_policy(self, task: Any):
        template = self._template_for_task(task)
        return None if template is None else template.egress_policy

    def egress_result(
        self,
        task_id: str,
        result: Mapping[str, Any],
        *,
        recipient_role: str = "sender",
        recipient_approved: bool = False,
        approval_id: str | None = None,
        event_id: str | None = None,
    ) -> EgressDecision:
        task = self.current_task(task_id)
        policy = self._egress_policy(task)
        if policy is None:
            decision = EgressDecision(
                task_id=task_id,
                status=EgressStatus.DELIVERED,
                delivered=dict(result),
                withheld_fields=(),
                recipient_agent_id=task.sender_agent_id or "",
                recipient_role=recipient_role,
                reason="no_template_policy_configured",
                approval_id=approval_id,
            )
            return decision
        key = event_id or f"egress:{_digest({'result': dict(result), 'role': recipient_role, 'approved': recipient_approved, 'approval_id': approval_id})}"
        payload = {
            "result": dict(result),
            "recipient_role": recipient_role,
            "recipient_approved": recipient_approved,
            "approval_id": approval_id,
        }
        decision, duplicate = self.journal.record(
            namespace="egress",
            task_id=task_id,
            key=key,
            payload=payload,
            create=lambda: policy.evaluate(
                task_id=task_id,
                result=result,
                recipient_agent_id=task.sender_agent_id or "",
                recipient_role=recipient_role,
                recipient_approved=recipient_approved,
                approval_id=approval_id,
            ),
        )
        if not duplicate:
            event_type = "result.egress" if decision.status.value == "delivered" else "result.egress_approval_required"
            self._emit(task_id, event_type, event_id=key, from_agent_id=task.recipient_agent_id, to_agent_id=task.sender_agent_id, payload=decision.as_dict())
        return decision

    evaluate_result_egress = egress_result

    def complete_task(
        self,
        task_id: str,
        *,
        evidence: ExecutionEvidence,
        summary: str | None = None,
        result_fields: Mapping[str, Any] | None = None,
        recipient_approved: bool = False,
        approval_id: str | None = None,
        event_id: str | None = None,
    ) -> Any:
        task = self.current_task(task_id)
        known = self._evidence.get(task_id, [])
        if evidence not in known:
            raise TaskError("completion requires evidence recorded for this Task")
        if evidence != known[-1] or evidence.task_id != task_id or evidence.template_id != task.template_id or evidence.template_version != str(task.template_version) or evidence.status != "verified":
            raise TaskError("execution evidence does not match the current Task authorization")
        output = dict(result_fields) if result_fields is not None else {"summary": summary or evidence.summary}
        egress = self.egress_result(
            task_id,
            output,
            recipient_approved=recipient_approved,
            approval_id=approval_id,
            event_id=f"{event_id}:egress" if event_id else None,
        )
        if egress.status.value != "delivered":
            raise EgressError(egress.reason)
        key = event_id or f"result:{evidence.command_id}"
        payload = {"evidence": evidence.as_dict(), "summary": summary or evidence.summary, "egress": egress.as_dict()}
        worker_id, epoch, fencing, _ = self._credential(task_id)

        def perform() -> Any:
            current = self.current_task(task_id)
            if current.state != "RUNNING":
                raise InvalidTransitionError("completion requires a RUNNING Task")
            return self.gateway.complete_task(task_id, expected_state_version=current.state_version, worker_id=worker_id, worker_epoch=epoch, fencing_token=fencing, result=payload)

        result, duplicate = self.journal.record(namespace="result", task_id=task_id, key=key, payload=payload, create=perform)
        if not duplicate:
            result_summary = ResultSummary(task_id, str(egress.delivered.get("summary", summary or evidence.summary)), evidence, tuple(x for x in (task.sender_agent_id, task.recipient_agent_id) if x))
            self._results[task_id] = result_summary
            self._emit(task_id, "result.completed", event_id=key, round_number=evidence.round_number, command_id=evidence.command_id, from_agent_id=task.recipient_agent_id, to_agent_id=task.sender_agent_id, payload=result_summary.as_dict())
            self._emit(task_id, "result.surfaced", event_id=f"{key}:recipient", round_number=evidence.round_number, command_id=evidence.command_id, from_agent_id=task.recipient_agent_id, to_agent_id=task.recipient_agent_id, payload={"summary": result_summary.summary, "task_id": task_id})
            self._monitor("task_failure_rate", task_id, details={"failed": 0, "completed": 1, "failure_rate": 0.0})
        return result

    def report_ui_error(self, task_id: str, *, code: str, message: str) -> MonitoringEvent:
        task = self.current_task(task_id)
        adapter = self._adapter(task.recipient_agent_id, task.worker_id or "unknown", int(task.worker_epoch or 1))
        event = adapter.report_ui_error(task_id=task_id, code=code, message=message)
        self.monitoring_events.append(event)
        return event

    def fail_task(self, task_id: str, *, reason: str = "worker_failure", event_id: str | None = None) -> Any:
        task = self.current_task(task_id)
        worker_id, epoch, fencing, _ = self._credential(task_id)
        key = event_id or f"failure:{reason}"
        result, duplicate = self.journal.record(
            namespace="failure",
            task_id=task_id,
            key=key,
            payload={"reason": reason},
            create=lambda: self.gateway.fail_task(task_id, expected_state_version=task.state_version, worker_id=worker_id, worker_epoch=epoch, fencing_token=fencing, result={"reason": reason}),
        )
        if not duplicate:
            self._emit(task_id, "task.failed", event_id=key, from_agent_id=task.recipient_agent_id, to_agent_id=task.sender_agent_id, payload={"reason": reason})
            self._monitor("task_failure_rate", task_id, severity="error", details={"failed": 1, "completed": 0, "failure_rate": 1.0, "reason": reason})
        return result

    def cancel_task(self, task_id: str, *, event_id: str | None = None) -> Any:
        task = self.current_task(task_id)
        key = event_id or "cancel"
        worker_id, epoch, fencing, _ = self._credential(task_id)

        def perform() -> Any:
            current = self.current_task(task_id)
            if current.state == "RUNNING":
                current = self.gateway.request_cancellation(task_id, expected_state_version=current.state_version, worker_id=worker_id, worker_epoch=epoch, fencing_token=fencing)
            return self.gateway.cancel_task(task_id, expected_state_version=current.state_version, worker_id=worker_id, worker_epoch=epoch, fencing_token=fencing)

        result, duplicate = self.journal.record(namespace="cancellation", task_id=task_id, key=key, payload={"operation": "cancel"}, create=perform)
        if not duplicate:
            self._emit(task_id, "cancellation.completed", event_id=key, from_agent_id=task.sender_agent_id, to_agent_id=task.recipient_agent_id, payload={"state": result.state})
        return result

    def run_two_rounds(
        self,
        task_id: str,
        *,
        additional_input: Mapping[str, Any] | None = None,
        input_data: Mapping[str, Any] | None = None,
        requested_input: Mapping[str, Any] | None = None,
    ) -> CollaborationOutcome:
        additional_input = additional_input or input_data or requested_input
        if additional_input is None:
            raise ScopeViolationError("two-round flow requires additional input")
        task = self.current_task(task_id)
        self.deliver_task(task_id)
        self.confirm_task(task_id)
        self.start_task(task_id)
        self.execute_round(task_id, round_number=1)
        self.request_input(task_id, fields=list(additional_input))
        self.provide_input(task_id, additional_input)
        evidence = self.execute_round(task_id, round_number=2)
        self.complete_task(task_id, evidence=evidence)
        result = self._results[task_id]
        return CollaborationOutcome(self.current_task(task_id), (1, 2), evidence, result, tuple(self.events_for(task_id)))

    run = run_two_rounds

    def events_for(self, task_id: str) -> list[TaskEvent]:
        return [event for event in self.events if event.task_id == task_id]

    def result_for(self, task_id: str) -> ResultSummary | None:
        return self._results.get(task_id)

    def contract(self) -> dict[str, Any]:
        return {
            "version": self.CONTRACT_VERSION,
            "command": ["command_id", "task_id", "target_conversation", "intent", "worker_epoch"],
            "event": ["event_id", "task_id", "event_type", "round", "payload"],
            "evidence": ["task_id", "command_id", "template_id", "template_version", "result_hash", "output_schema", "summary", "round", "status"],
            "reconciliation": ["command_id", "task_id", "target_conversation", "status", "reason", "worker_epoch"],
            "monitoring": ["schema_version", "event_type", "task_id", "severity", "worker_id", "round", "details"],
        }


# Explicit aliases make the contract vocabulary easy to discover for platform
# adapter tests without coupling them to this module's internal naming.
FakeDesktop = FakeDesktopAdapter
CommandJournal = ProtocolJournal
TaskExecutionEvidence = ExecutionEvidence
Reconciliation = UIReconciliation
