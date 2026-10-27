"""Windows WorkBuddy Desktop adapter contract.

The adapter depends on a small UI Automation backend interface.  Production
code can supply a Windows UIA implementation; tests use
``FakeWindowsUIAutomationBackend``.  The safety checks, command journal, and
reconciliation logic are shared by both backends.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

from .collaboration import Command, ExecutionEvidence, FakeDesktopAdapter, ProtocolJournal, UIReconciliation
from .errors import (
    AutomationPermissionError,
    CapabilityError,
    ControlNotFoundError,
    DesktopAdapterError,
    HumanInterferenceError,
    NeedsAttentionError,
    ReplayError,
    UIStateError,
    UnsupportedAppVersionError,
)
from .isolation import RestrictedWorkspace, TaskTemplate, TemplateRegistry


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class WindowsCompatibilityProfile:
    app_id: str
    supported_versions: frozenset[str]
    collaboration_conversation: str
    input_control: str
    reply_control: str
    status_control: str

    def __post_init__(self) -> None:
        if not self.app_id or not self.collaboration_conversation:
            raise ValueError("app_id and collaboration_conversation are required")
        versions = [self.supported_versions] if isinstance(self.supported_versions, str) else self.supported_versions
        object.__setattr__(self, "supported_versions", frozenset(str(version) for version in versions))
        for name in ("input_control", "reply_control", "status_control"):
            if not getattr(self, name):
                raise ValueError(f"{name} is required")

    def supports(self, app_version: str) -> bool:
        return str(app_version) in self.supported_versions

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "platform": "windows",
            "app_id": self.app_id,
            "supported_versions": sorted(self.supported_versions),
            "collaboration_conversation": self.collaboration_conversation,
            "input_control": self.input_control,
            "reply_control": self.reply_control,
            "status_control": self.status_control,
        }


@dataclass(frozen=True)
class InstallationReport:
    status: str
    app_id: str
    app_version: str
    conversation_id: str
    automation_permission: bool
    controls: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "status": self.status,
            "app_id": self.app_id,
            "app_version": self.app_version,
            "conversation_id": self.conversation_id,
            "automation_permission": self.automation_permission,
            "controls": list(self.controls),
        }


@dataclass(frozen=True)
class AdapterErrorEvent:
    code: str
    message: str
    phase: str
    task_id: str | None = None
    command_id: str | None = None
    details: Mapping[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "code": self.code,
            "message": self.message,
            "phase": self.phase,
            "task_id": self.task_id,
            "command_id": self.command_id,
            "details": dict(self.details),
        }


@dataclass(frozen=True)
class WindowsCommandRecord:
    command_id: str
    task_id: str
    target_conversation: str
    worker_epoch: int
    fingerprint: str
    status: str
    evidence: Mapping[str, Any] | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "command_id": self.command_id,
            "task_id": self.task_id,
            "target_conversation": self.target_conversation,
            "worker_epoch": self.worker_epoch,
            "fingerprint": self.fingerprint,
            "status": self.status,
            "evidence": None if self.evidence is None else dict(self.evidence),
        }


class WindowsCommandJournal:
    """Small file-backed journal used before UI injection."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = None if path is None else Path(path)
        self._records: dict[str, WindowsCommandRecord] = {}
        self._load()

    def _load(self) -> None:
        if self.path is None or not self.path.exists():
            return
        try:
            values = json.loads(self.path.read_text(encoding="utf-8"))
            self._records = {key: WindowsCommandRecord(**value) for key, value in values.items()}
        except (OSError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise DesktopAdapterError(f"Windows command journal cannot be read: {error}") from error

    def _save(self) -> None:
        if self.path is None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps({key: value.as_dict() for key, value in self._records.items()}, sort_keys=True, ensure_ascii=False, indent=2)
        fd, temp_name = tempfile.mkstemp(prefix="commands.", suffix=".tmp", dir=self.path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp_name, self.path)
        finally:
            if os.path.exists(temp_name):
                os.unlink(temp_name)

    def get(self, command_id: str) -> WindowsCommandRecord | None:
        return self._records.get(command_id)

    def prepare(self, command: Command) -> WindowsCommandRecord:
        existing = self._records.get(command.command_id)
        if existing is not None:
            if existing.fingerprint != command.fingerprint or existing.task_id != command.task_id:
                raise ReplayError("command_id was reused with different Windows UI intent")
            return existing
        record = WindowsCommandRecord(
            command_id=command.command_id,
            task_id=command.task_id,
            target_conversation=command.target_conversation,
            worker_epoch=command.worker_epoch,
            fingerprint=command.fingerprint,
            status="prepared",
        )
        self._records[command.command_id] = record
        self._save()
        return record

    def mark_injected(self, command_id: str) -> WindowsCommandRecord:
        record = self._require(command_id)
        updated = WindowsCommandRecord(**{**record.as_dict(), "status": "injected"})
        self._records[command_id] = updated
        self._save()
        return updated

    def record_evidence(self, command_id: str, evidence: ExecutionEvidence) -> WindowsCommandRecord:
        record = self._require(command_id)
        updated = WindowsCommandRecord(**{**record.as_dict(), "status": "completed", "evidence": evidence.as_dict()})
        self._records[command_id] = updated
        self._save()
        return updated

    def _require(self, command_id: str) -> WindowsCommandRecord:
        record = self.get(command_id)
        if record is None:
            raise DesktopAdapterError(f"command {command_id} is not in the Windows journal")
        return record


def _evidence_from_dict(value: Mapping[str, Any]) -> ExecutionEvidence:
    return ExecutionEvidence(
        task_id=str(value["task_id"]),
        command_id=str(value["command_id"]),
        template_id=str(value["template_id"]),
        template_version=str(value["template_version"]),
        result_hash=str(value["result_hash"]),
        output_schema=dict(value["output_schema"]),
        summary=str(value["summary"]),
        round_number=int(value["round"]),
        status=str(value.get("status", "verified")),
    )


class WindowsDesktopAdapter(FakeDesktopAdapter):
    """Windows UIA adapter with a deterministic backend seam."""

    permission_error_type = AutomationPermissionError
    permission_name = "Windows UI Automation"

    def __init__(
        self,
        *,
        profile: WindowsCompatibilityProfile,
        backend: Any,
        worker_id: str,
        worker_epoch: int,
        journal_path: str | Path | None = None,
        workspace: RestrictedWorkspace | None = None,
        template_registry: TemplateRegistry | None = None,
    ) -> None:
        super().__init__(
            worker_id=worker_id,
            worker_epoch=worker_epoch,
            conversation_id=profile.collaboration_conversation,
            journal=ProtocolJournal(),
            workspace=workspace,
            template_registry=template_registry,
        )
        self.profile = profile
        self.backend = backend
        self.command_journal = WindowsCommandJournal(journal_path)
        self.error_events: list[AdapterErrorEvent] = []

    def _record_error(self, error: DesktopAdapterError, *, phase: str, command: Command | None = None, details: Mapping[str, Any] | None = None) -> None:
        self.error_events.append(
            AdapterErrorEvent(
                code=error.code,
                message=str(error),
                phase=phase,
                task_id=None if command is None else command.task_id,
                command_id=None if command is None else command.command_id,
                details=dict(details or {}),
            )
        )

    def _fail(self, error_type: type[DesktopAdapterError], message: str, *, phase: str, command: Command | None = None, details: Mapping[str, Any] | None = None) -> None:
        error = error_type(message)
        self._record_error(error, phase=phase, command=command, details=details)
        raise error

    def verify_installation(self) -> InstallationReport:
        permission_value = getattr(self.backend, "automation_permission_granted", None)
        if permission_value is None:
            permission_value = getattr(self.backend, "automation_permission", None)
        if permission_value is None:
            permission_value = getattr(self.backend, "accessibility_permission_granted", False)
        permission = bool(permission_value() if callable(permission_value) else permission_value)
        if not permission:
            self._fail(self.permission_error_type, f"{self.permission_name} permission is required", phase="permission")
        app_id = str(self._backend_value("app_id", ""))
        if app_id != self.profile.app_id:
            self._fail(UIStateError, "the running app is not the supported WorkBuddy App", phase="app_identity", details={"app_id": app_id})
        app_version = str(self._backend_value("app_version", ""))
        if not self.profile.supports(app_version):
            self._fail(UnsupportedAppVersionError, f"WorkBuddy App version {app_version!r} is not supported", phase="app_version", details={"app_version": app_version})
        state = str(self._backend_value("ui_state", "unknown"))
        if state in {"login", "logged_out"}:
            self._fail(NeedsAttentionError, "WorkBuddy is logged out; login remains a human action", phase="ui_state", details={"ui_state": state})
        if state in {"update_dialog", "updating"}:
            self._fail(NeedsAttentionError, "WorkBuddy update dialog requires human attention", phase="ui_state", details={"ui_state": state})
        if state != "ready":
            self._fail(UIStateError, f"unexpected WorkBuddy UI state: {state}", phase="ui_state", details={"ui_state": state})
        self.select_conversation(self.profile.collaboration_conversation)
        for control in (self.profile.input_control, self.profile.reply_control, self.profile.status_control):
            if not bool(self.backend.has_control(control)):
                self._fail(ControlNotFoundError, f"required UI control is missing: {control}", phase="controls", details={"control": control})
        return InstallationReport("ready", app_id, app_version, self.profile.collaboration_conversation, True, (self.profile.input_control, self.profile.reply_control, self.profile.status_control))

    def _backend_value(self, name: str, default: Any = None) -> Any:
        value = getattr(self.backend, name, default)
        return value() if callable(value) else value

    verify_runtime = verify_installation

    def select_conversation(self, conversation_id: str) -> str:
        if conversation_id != self.profile.collaboration_conversation:
            self._fail(UIStateError, "adapter may select only the dedicated collaboration conversation", phase="conversation", details={"conversation_id": conversation_id})
        try:
            self.backend.select_conversation(conversation_id)
            selected = str(self._backend_value("selected_conversation", ""))
            if not selected:
                selected = str(self._backend_value("current_conversation", ""))
        except DesktopAdapterError as error:
            self._record_error(error, phase="conversation")
            raise
        except Exception as error:
            self._fail(UIStateError, f"dedicated collaboration conversation cannot be selected: {error}", phase="conversation")
        if selected != conversation_id:
            self._fail(UIStateError, "selected conversation does not match the dedicated collaboration conversation", phase="conversation", details={"selected": selected})
        self.conversation_id = selected
        return selected

    select_collaboration_conversation = select_conversation

    def prepare_command(self, command: Command) -> WindowsCommandRecord:
        if command.worker_epoch != self.worker_epoch:
            self._fail(ReplayError, "command belongs to an old Worker epoch", phase="journal", command=command)
        return self.command_journal.prepare(command)

    def _read_evidence(self, command: Command) -> ExecutionEvidence:
        status = str(self.backend.read_status()).lower()
        if status in {"login", "logged_out", "update_dialog", "updating", "blocked", "human_interference"}:
            self._fail(NeedsAttentionError, f"WorkBuddy reported unsafe UI status: {status}", phase="completion", command=command, details={"ui_status": status})
        if status not in {"completed", "complete", "done", "success"}:
            self._fail(NeedsAttentionError, f"completion cannot be established from UI status: {status}", phase="completion", command=command, details={"ui_status": status})
        reply = str(self.backend.read_reply())
        if not reply.strip():
            self._fail(NeedsAttentionError, "completion reply is empty", phase="completion", command=command)
        marker = dict(command.intent).get("completion_marker")
        if marker is not None and str(marker) not in reply:
            self._fail(NeedsAttentionError, "template completion evidence is missing", phase="completion", command=command, details={"completion_marker": marker})
        intent = dict(command.intent)
        round_number = int(intent.get("round", 1))
        template_id = str(intent.get("template_id", "unknown"))
        template_version = str(intent.get("template_version", "1"))
        result = {"summary": reply, "command_id": command.command_id, "round": round_number}
        return ExecutionEvidence(
            task_id=command.task_id,
            command_id=command.command_id,
            template_id=template_id,
            template_version=template_version,
            result_hash=_digest(result),
            output_schema={"type": "object", "required": ["summary", "command_id", "round"]},
            summary=reply,
            round_number=round_number,
        )

    def execute(self, command: Command, *, summary: str | None = None) -> ExecutionEvidence:
        existing = self.command_journal.get(command.command_id)
        if existing is not None:
            self.prepare_command(command)
        if existing is not None and existing.status == "completed" and existing.evidence is not None:
            return _evidence_from_dict(existing.evidence)
        if existing is not None and existing.status == "injected":
            reconciliation = self.reconcile(command.command_id)
            if reconciliation.status == "matched":
                record = self.command_journal.get(command.command_id)
                assert record is not None and record.evidence is not None
                return _evidence_from_dict(record.evidence)
            error = NeedsAttentionError("a previously injected command has no provable completion")
            self._record_error(error, phase="reconciliation", command=command)
            raise error
        try:
            if command.target_conversation != self.profile.collaboration_conversation:
                self._fail(UIStateError, "command targets a non-collaboration conversation", phase="conversation", command=command)
            self._authorize_command(command)
            self.prepare_command(command)
            self.verify_installation()
            focused = str(self._backend_value("focused_control_id", ""))
            if not focused:
                focused = str(self._backend_value("focused_control", ""))
            if focused != self.profile.input_control:
                self._fail(HumanInterferenceError, "the WorkBuddy input control is not focused", phase="focus", command=command, details={"focused_control": focused})
            intent = dict(command.intent)
            normalized_intent = _canonical(intent)
            try:
                self.backend.inject_text(f"[command_id:{command.command_id}] {normalized_intent}")
            except DesktopAdapterError as error:
                self._fail(NeedsAttentionError, f"UI changed during input injection: {error}", phase="injection", command=command)
            self.command_journal.mark_injected(command.command_id)
            try:
                self.backend.submit()
            except DesktopAdapterError as error:
                self._fail(NeedsAttentionError, f"UI changed before command acknowledgement: {error}", phase="submit", command=command)
            evidence = self._read_evidence(command)
            self.command_journal.record_evidence(command.command_id, evidence)
            self.execution_count += 1
            return evidence
        except DesktopAdapterError as error:
            if not self.error_events or self.error_events[-1].message != str(error):
                self._record_error(error, phase="execute", command=command)
            raise
        except Exception as error:
            self._fail(NeedsAttentionError, f"Windows UI automation failed safely: {error}", phase="execute", command=command)
        raise AssertionError("unreachable")

    def reconcile(self, command_id: str) -> UIReconciliation:
        record = self.command_journal.get(command_id)
        if record is None:
            return UIReconciliation(command_id, "", self.conversation_id, "not_found", "command_not_journaled", self.worker_epoch)
        if record.worker_epoch != self.worker_epoch:
            return UIReconciliation(command_id, record.task_id, record.target_conversation, "uncertain", "old_worker_epoch", self.worker_epoch)
        if record.status == "completed" and record.evidence is not None:
            evidence = _evidence_from_dict(record.evidence)
            return UIReconciliation(command_id, evidence.task_id, record.target_conversation, "matched", "evidence_found", record.worker_epoch)
        if record.status == "injected":
            finder = getattr(self.backend, "find_command_evidence", None)
            found = None if finder is None else finder(command_id)
            if found is not None:
                evidence = found if isinstance(found, ExecutionEvidence) else _evidence_from_dict(found)
                self.command_journal.record_evidence(command_id, evidence)
                return UIReconciliation(command_id, record.task_id, record.target_conversation, "matched", "ui_evidence_found", record.worker_epoch)
            return UIReconciliation(command_id, record.task_id, record.target_conversation, "uncertain", "injection_without_evidence", record.worker_epoch)
        return UIReconciliation(command_id, record.task_id, record.target_conversation, "not_found", "not_injected", record.worker_epoch)

    reconcile_ui = reconcile

    def with_clipboard(self, value: str, action: Callable[[], Any]) -> Any:
        if self.workspace is None:
            raise CapabilityError("clipboard fallback requires a RestrictedWorkspace capability grant")
        self.workspace.use_capability("clipboard")
        original = self.backend.clipboard_get()
        self.backend.clipboard_set(value)
        try:
            return action()
        finally:
            self.backend.clipboard_set(original)

    clipboard_fallback = with_clipboard


class FakeWindowsUIAutomationBackend:
    """Deterministic seam for Windows UI Automation contract tests."""

    def __init__(
        self,
        *,
        app_id: str,
        app_version: str,
        collaboration_conversation: str,
        controls: Iterable[str],
        reply: str = "",
        status: str = "completed",
        automation_permission_granted: bool = True,
    ) -> None:
        self.app_id = app_id
        self.app_version = app_version
        self.automation_permission_granted = automation_permission_granted
        self.ui_state = "ready"
        self.selected_conversation = ""
        self.available_conversations = {collaboration_conversation}
        self.controls = set(controls)
        self.focused_control_id = "composer"
        self.reply = reply
        self.status = status
        self.injected_texts: list[str] = []
        self.submitted_count = 0
        self.after_injection_state: str | None = None
        self.command_evidence: dict[str, ExecutionEvidence | Mapping[str, Any]] = {}
        self.clipboard_text = ""

    def select_conversation(self, conversation_id: str) -> None:
        if self.ui_state != "ready":
            raise UIStateError(f"cannot select a conversation while UI state is {self.ui_state}")
        if conversation_id not in self.available_conversations:
            raise UIStateError("conversation is not available")
        self.selected_conversation = conversation_id

    def has_control(self, control: str) -> bool:
        return control in self.controls

    def inject_text(self, text: str) -> None:
        if self.ui_state != "ready":
            raise UIStateError(f"cannot inject text while UI state is {self.ui_state}")
        self.injected_texts.append(text)
        if self.after_injection_state is not None:
            self.ui_state = self.after_injection_state

    def submit(self) -> None:
        if self.ui_state != "ready":
            raise UIStateError(f"cannot submit while UI state is {self.ui_state}")
        self.submitted_count += 1

    def read_reply(self) -> str:
        return self.reply

    def read_status(self) -> str:
        return self.status

    def find_command_evidence(self, command_id: str) -> ExecutionEvidence | Mapping[str, Any] | None:
        return self.command_evidence.get(command_id)

    def set_command_evidence(self, command_id: str, evidence: ExecutionEvidence | Mapping[str, Any]) -> None:
        self.command_evidence[command_id] = evidence

    def clipboard_get(self) -> str:
        return self.clipboard_text

    def clipboard_set(self, value: str) -> None:
        self.clipboard_text = value


WindowsUIAutomationAdapter = WindowsDesktopAdapter
WindowsUIAAdapter = WindowsDesktopAdapter
UIAutomationBackend = FakeWindowsUIAutomationBackend
WindowsAdapterError = DesktopAdapterError
WindowsUIAutomationError = DesktopAdapterError
