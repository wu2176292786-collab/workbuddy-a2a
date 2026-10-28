"""ClawBot confirmation and notification adapter contract.

The adapter is transport-neutral: a real WeChat/ClawBot connector can supply
the same identity and send methods as ``FakeClawBotTransport``.  Free-form
messages never enter the Gateway confirmation path.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any, Mapping

from .collaboration import ExecutionEvidence, FakeCollaboration, ProtocolJournal
from .errors import (
    ApprovalError,
    ChannelAuthenticationError,
    ConfirmationEnvelopeError,
    ForwardedMessageError,
    PlainTextConfirmationError,
    ReplayError,
)


def _digest(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True)
class ClawBotIdentity:
    channel_user_id: str
    team_id: str
    agent_id: str
    authenticated: bool
    strong_authentication: bool


class FakeClawBotTransport:
    """Synthetic ClawBot/WeChat transport used by contract tests."""

    def __init__(self, identities: list[ClawBotIdentity] | None = None) -> None:
        self.identities = {identity.channel_user_id: identity for identity in identities or []}
        self.outbox: list[dict[str, Any]] = []

    def identity_for(self, channel_user_id: str) -> ClawBotIdentity | None:
        return self.identities.get(channel_user_id)

    def send_notification(self, channel_user_id: str, message: Mapping[str, Any]) -> dict[str, Any]:
        record = {"channel_user_id": channel_user_id, "message": dict(message)}
        self.outbox.append(record)
        return dict(message)

    def messages_for(self, channel_user_id: str) -> list[dict[str, Any]]:
        return [dict(record["message"]) for record in self.outbox if record["channel_user_id"] == channel_user_id]


class ClawBotAdapter:
    """Authenticated confirmation, approval, and notification boundary."""

    def __init__(
        self,
        *,
        gateway: Any,
        transport: FakeClawBotTransport,
        collaboration: FakeCollaboration,
        channel_by_agent: Mapping[str, str],
        journal: ProtocolJournal | None = None,
    ) -> None:
        self.gateway = gateway
        self.transport = transport
        self.collaboration = collaboration
        self.channel_by_agent = dict(channel_by_agent)
        self.journal = journal or ProtocolJournal()
        self.blocked_events: list[dict[str, Any]] = []
        self._pending_approvals: dict[str, dict[str, Any]] = {}

    def _block(self, code: str, reason: str, *, task_id: str | None = None, channel_user_id: str | None = None) -> None:
        self.blocked_events.append({"schema_version": 1, "code": code, "reason": reason, "task_id": task_id, "channel_user_id": channel_user_id})

    def _identity(self, channel_user_id: str, *, task_id: str, expected_agent_id: str) -> ClawBotIdentity:
        identity = self.transport.identity_for(channel_user_id)
        if identity is None or not identity.authenticated or not identity.strong_authentication:
            self._block("CHANNEL_AUTHENTICATION_REQUIRED", "ClawBot channel cannot provide strong recipient identity", task_id=task_id, channel_user_id=channel_user_id)
            raise ChannelAuthenticationError("ClawBot channel authentication is insufficient for Task authorization")
        task = self.gateway.get_task(task_id)
        if task is None or identity.team_id != task.team_id or identity.agent_id != expected_agent_id:
            self._block("CHANNEL_IDENTITY_MISMATCH", "ClawBot identity is not the authenticated Task recipient", task_id=task_id, channel_user_id=channel_user_id)
            raise ChannelAuthenticationError("ClawBot identity is not bound to the Task recipient")
        return identity

    def _send(self, agent_id: str, message: Mapping[str, Any]) -> dict[str, Any]:
        channel = self.channel_by_agent.get(agent_id)
        if channel is None:
            raise ChannelAuthenticationError(f"no ClawBot channel is bound to Agent {agent_id}")
        return self.transport.send_notification(channel, message)

    def notify_task_created(self, task: Any) -> None:
        recipient_message = {
            "schema_version": 1,
            "type": "task_confirmation_required",
            "format": "clawbot_task_v1",
            "task_id": task.id,
            "task_hash": task.task_hash,
            "sender_agent_id": task.sender_agent_id,
            "recipient_agent_id": task.recipient_agent_id,
            "template_id": task.template_id,
            "template_version": task.template_version,
            "input": task.input_data,
            "scope": task.scope,
            "permissions": task.permissions,
            "expires_at": task.expires_at,
            "confirmation_nonce": task.confirmation_nonce,
        }
        sender_message = {
            "schema_version": 1,
            "type": "task_created",
            "format": "clawbot_task_v1",
            "task_id": task.id,
            "task_hash": task.task_hash,
            "sender_agent_id": task.sender_agent_id,
            "recipient_agent_id": task.recipient_agent_id,
            "template_id": task.template_id,
            "template_version": task.template_version,
            "expires_at": task.expires_at,
        }
        self._send(task.recipient_agent_id, recipient_message)
        self._send(task.sender_agent_id, sender_message)

    def notify_state(self, task: Any, state: str, *, reason: str | None = None) -> None:
        message = {"schema_version": 1, "type": "task_state_changed", "task_id": task.id, "task_hash": task.task_hash, "state": state, "reason": reason}
        self._send(task.sender_agent_id, message)
        self._send(task.recipient_agent_id, message)

    def notify_failure(self, task: Any, reason: str) -> None:
        message = {"schema_version": 1, "type": "task_failed", "task_id": task.id, "task_hash": task.task_hash, "reason": str(reason)}
        self._send(task.sender_agent_id, message)
        self._send(task.recipient_agent_id, message)

    def notify_result(self, task: Any, *, summary: str, evidence: ExecutionEvidence) -> None:
        message = {
            "schema_version": 1,
            "type": "result_completed",
            "task_id": task.id,
            "task_hash": task.task_hash,
            "summary": summary,
            "evidence": evidence.as_dict(),
        }
        self._send(task.sender_agent_id, message)
        self._send(task.recipient_agent_id, message)

    def receive_confirmation(self, channel_user_id: str, message: Mapping[str, Any] | str) -> Any:
        if not isinstance(message, Mapping):
            self._block("PLAINTEXT_CONFIRMATION_REJECTED", "confirmation must be a machine-readable envelope", channel_user_id=channel_user_id)
            raise PlainTextConfirmationError("natural-language ClawBot text cannot confirm a Task")
        if message.get("forwarded_from") or message.get("forwarded"):
            self._block("FORWARDED_MESSAGE_REJECTED", "forwarded ClawBot messages cannot confirm a Task", task_id=message.get("task_id"), channel_user_id=channel_user_id)
            raise ForwardedMessageError("forwarded messages are not valid confirmation envelopes")
        if message.get("type") != "task_confirmation" or message.get("format") != "clawbot_confirmation_v1":
            raise ConfirmationEnvelopeError("unsupported ClawBot confirmation envelope")
        task_id = str(message.get("task_id", ""))
        task = self.gateway.get_task(task_id)
        if task is None:
            raise ConfirmationEnvelopeError("Task does not exist")
        self._identity(channel_user_id, task_id=task_id, expected_agent_id=task.recipient_agent_id)
        required = ("message_id", "task_hash", "confirmation_nonce", "expires_at", "decision")
        if any(field not in message for field in required):
            raise ConfirmationEnvelopeError("confirmation envelope is missing required fields")
        capabilities = self.collaboration.task_capabilities(task_id)
        if message["task_hash"] != task.task_hash or message["confirmation_nonce"] != capabilities["confirmation_nonce"]:
            self._block("CONFIRMATION_BINDING_MISMATCH", "task_hash or confirmation nonce does not match the immutable Task", task_id=task_id, channel_user_id=channel_user_id)
            raise ConfirmationEnvelopeError("confirmation is not bound to the immutable Task authorization")
        try:
            if float(message["expires_at"]) != float(task.expires_at) or float(message["expires_at"]) <= time.time():
                raise ConfirmationEnvelopeError("confirmation envelope is expired or has a mismatched expiry")
        except (TypeError, ValueError) as error:
            raise ConfirmationEnvelopeError("confirmation expiry is invalid") from error
        decision = str(message["decision"]).lower()
        if decision not in {"accept", "reject"}:
            raise ConfirmationEnvelopeError("decision must be accept or reject")
        message_id = str(message["message_id"])
        payload = dict(message)

        def perform() -> Any:
            return self.gateway.confirm_task(
                task_id,
                decision=decision,
                task_hash=task.task_hash,
                confirmation_nonce=capabilities["confirmation_nonce"],
                confirmation_expires_at=task.expires_at,
                recipient_agent_id=task.recipient_agent_id,
                expected_state_version=task.state_version,
                worker_id=capabilities["worker_id"],
                worker_epoch=capabilities["worker_epoch"],
                fencing_token=capabilities["fencing_token"],
            )

        result, duplicate = self.journal.record(namespace="clawbot-confirmation", task_id=task_id, key=message_id, payload=payload, create=perform)
        if not duplicate:
            self.notify_state(task, result.state, reason=f"clawbot_recipient_{decision}")
        return result

    def request_result_approval(self, task_id: str, *, evidence: ExecutionEvidence, result_fields: Mapping[str, Any]) -> dict[str, Any]:
        task = self.gateway.get_task(task_id)
        if task is None:
            raise ApprovalError("Task does not exist")
        decision = self.collaboration.egress_result(task_id, result_fields)
        if decision.status.value != "approval_required":
            raise ApprovalError("result does not require recipient approval")
        approval_id = f"approval:{task_id}:{_digest({'evidence': evidence.result_hash, 'fields': sorted(result_fields)})[:20]}"
        self._pending_approvals[approval_id] = {"task_id": task_id, "evidence": evidence, "result_fields": dict(result_fields)}
        message = {
            "schema_version": 1,
            "type": "result_approval_required",
            "format": "clawbot_result_approval_v1",
            "task_id": task_id,
            "task_hash": task.task_hash,
            "approval_id": approval_id,
            "fields": sorted(result_fields),
            "withheld_fields": list(decision.withheld_fields),
        }
        self._send(task.recipient_agent_id, message)
        return message

    def receive_result_approval(self, channel_user_id: str, message: Mapping[str, Any]) -> Any:
        if not isinstance(message, Mapping) or message.get("type") != "result_approval" or message.get("format") != "clawbot_result_approval_v1":
            raise ApprovalError("unsupported result approval envelope")
        task_id = str(message.get("task_id", ""))
        task = self.gateway.get_task(task_id)
        if task is None:
            raise ApprovalError("Task does not exist")
        self._identity(channel_user_id, task_id=task_id, expected_agent_id=task.recipient_agent_id)
        approval_id = str(message.get("approval_id", ""))
        pending = self._pending_approvals.get(approval_id)
        if pending is None or pending["task_id"] != task_id:
            raise ApprovalError("result approval is unknown or expired")
        decision = str(message.get("decision", "")).lower()
        if decision not in {"approve", "reject"}:
            raise ApprovalError("result approval decision must be approve or reject")
        message_id = str(message.get("message_id", ""))
        if not message_id:
            raise ApprovalError("result approval message_id is required")

        def perform() -> Any:
            if decision == "reject":
                return self.gateway.get_task(task_id)
            result = self.collaboration.complete_task(
                task_id,
                evidence=pending["evidence"],
                result_fields=pending["result_fields"],
                recipient_approved=True,
                approval_id=approval_id,
                event_id=message_id,
            )
            self.notify_result(task, summary=str(pending["result_fields"].get("summary", pending["evidence"].summary)), evidence=pending["evidence"])
            return result

        result, _ = self.journal.record(namespace="clawbot-result-approval", task_id=task_id, key=message_id, payload=dict(message), create=perform)
        return result
