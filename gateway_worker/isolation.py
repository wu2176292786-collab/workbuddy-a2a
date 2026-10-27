"""Machine-enforced execution boundaries and result egress policy.

This module contains the controlled-demo boundary used by the Fake Desktop
adapter.  It intentionally exposes policy decisions as structured values so a
platform adapter can reuse the same checks without relying on prompt wording
or a separate chat being a security boundary.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable, Mapping

from .errors import CapabilityError, EgressError, IsolationError


def _names(values: Iterable[str] | None) -> frozenset[str]:
    if values is None:
        return frozenset()
    if isinstance(values, str):
        values = [values]
    result = frozenset(str(value) for value in values)
    if any(not value or value in {"*", "**"} for value in result):
        raise ValueError("allowlist entries must be non-empty and cannot be wildcards")
    return result


class EgressStatus(str, Enum):
    DELIVERED = "delivered"
    APPROVAL_REQUIRED = "approval_required"
    BLOCKED = "blocked"


@dataclass(frozen=True)
class EgressDecision:
    task_id: str
    status: EgressStatus
    delivered: Mapping[str, Any]
    withheld_fields: tuple[str, ...]
    recipient_agent_id: str
    recipient_role: str
    reason: str
    approval_id: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "task_id": self.task_id,
            "status": self.status.value,
            "delivered": dict(self.delivered),
            "withheld_fields": list(self.withheld_fields),
            "recipient_agent_id": self.recipient_agent_id,
            "recipient_role": self.recipient_role,
            "reason": self.reason,
            "approval_id": self.approval_id,
        }

    to_dict = as_dict


@dataclass(frozen=True)
class ResultEgressPolicy:
    output_fields: frozenset[str]
    sensitive_fields: frozenset[str] = frozenset()
    blocked_fields: frozenset[str] = frozenset()
    sensitive_field_mode: str = "block"
    allowed_recipient_roles: frozenset[str] = frozenset({"sender"})
    allowed_recipient_agents: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        object.__setattr__(self, "output_fields", _names(self.output_fields))
        object.__setattr__(self, "sensitive_fields", _names(self.sensitive_fields))
        object.__setattr__(self, "blocked_fields", _names(self.blocked_fields))
        object.__setattr__(self, "allowed_recipient_roles", _names(self.allowed_recipient_roles))
        object.__setattr__(self, "allowed_recipient_agents", _names(self.allowed_recipient_agents))
        if self.sensitive_field_mode not in {"block", "approval"}:
            raise ValueError("sensitive_field_mode must be 'block' or 'approval'")

    def evaluate(
        self,
        *,
        task_id: str,
        result: Mapping[str, Any],
        recipient_agent_id: str,
        recipient_role: str = "sender",
        recipient_approved: bool = False,
        approval_id: str | None = None,
    ) -> EgressDecision:
        if not isinstance(result, Mapping):
            raise EgressError("result must be an object")
        if recipient_role not in self.allowed_recipient_roles:
            raise EgressError("result recipient role is outside the template policy")
        if self.allowed_recipient_agents and recipient_agent_id not in self.allowed_recipient_agents:
            raise EgressError("result recipient Agent is outside the template policy")
        fields = {str(field) for field in result}
        unknown = fields - self.output_fields
        if unknown:
            raise EgressError(f"result fields are outside the template output allowlist: {sorted(unknown)}")
        blocked = fields & self.blocked_fields
        if blocked:
            raise EgressError(f"result contains blocked fields: {sorted(blocked)}")
        sensitive = fields & self.sensitive_fields
        if sensitive and self.sensitive_field_mode == "block":
            raise EgressError(f"result contains sensitive fields blocked by policy: {sorted(sensitive)}")
        if sensitive and not recipient_approved:
            delivered = {field: result[field] for field in sorted(fields - sensitive)}
            return EgressDecision(
                task_id=task_id,
                status=EgressStatus.APPROVAL_REQUIRED,
                delivered=delivered,
                withheld_fields=tuple(sorted(sensitive)),
                recipient_agent_id=recipient_agent_id,
                recipient_role=recipient_role,
                reason="recipient_approval_required_for_sensitive_fields",
            )
        if sensitive and not approval_id:
            raise EgressError("recipient approval requires an approval_id")
        return EgressDecision(
            task_id=task_id,
            status=EgressStatus.DELIVERED,
            delivered={field: result[field] for field in sorted(fields)},
            withheld_fields=(),
            recipient_agent_id=recipient_agent_id,
            recipient_role=recipient_role,
            reason="egress_allowed",
            approval_id=approval_id,
        )

    check = evaluate
    filter = evaluate


@dataclass(frozen=True)
class TaskTemplate:
    template_id: str
    version: str | int
    allowed_tools: frozenset[str] = frozenset()
    allowed_resources: frozenset[str] = frozenset()
    output_fields: frozenset[str] = frozenset({"summary"})
    sensitive_fields: frozenset[str] = frozenset()
    blocked_fields: frozenset[str] = frozenset()
    sensitive_field_mode: str = "block"
    allowed_recipient_roles: frozenset[str] = frozenset({"sender"})
    max_rounds: int = 2
    allowed_recipient_agents: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if not isinstance(self.template_id, str) or not self.template_id.strip():
            raise ValueError("template_id is required")
        object.__setattr__(self, "template_id", self.template_id.strip())
        object.__setattr__(self, "version", str(self.version))
        object.__setattr__(self, "allowed_tools", _names(self.allowed_tools))
        object.__setattr__(self, "allowed_resources", _names(self.allowed_resources))
        object.__setattr__(self, "output_fields", _names(self.output_fields))
        object.__setattr__(self, "sensitive_fields", _names(self.sensitive_fields))
        object.__setattr__(self, "blocked_fields", _names(self.blocked_fields))
        object.__setattr__(self, "allowed_recipient_roles", _names(self.allowed_recipient_roles))
        object.__setattr__(self, "allowed_recipient_agents", _names(self.allowed_recipient_agents))
        if self.max_rounds < 1:
            raise ValueError("max_rounds must be positive")

    @property
    def egress_policy(self) -> ResultEgressPolicy:
        return ResultEgressPolicy(
            output_fields=self.output_fields,
            sensitive_fields=self.sensitive_fields,
            blocked_fields=self.blocked_fields,
            sensitive_field_mode=self.sensitive_field_mode,
            allowed_recipient_roles=self.allowed_recipient_roles,
            allowed_recipient_agents=self.allowed_recipient_agents,
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "template_id": self.template_id,
            "version": self.version,
            "allowed_tools": sorted(self.allowed_tools),
            "allowed_resources": sorted(self.allowed_resources),
            "output_fields": sorted(self.output_fields),
            "sensitive_fields": sorted(self.sensitive_fields),
            "blocked_fields": sorted(self.blocked_fields),
            "sensitive_field_mode": self.sensitive_field_mode,
            "allowed_recipient_roles": sorted(self.allowed_recipient_roles),
            "allowed_recipient_agents": sorted(self.allowed_recipient_agents),
            "max_rounds": self.max_rounds,
        }

    to_dict = as_dict

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "TaskTemplate":
        if not isinstance(value, Mapping):
            raise ValueError("Task template must be an object")
        return cls(
            template_id=value.get("template_id", value.get("id", "")),
            version=value.get("version", value.get("template_version", "1")),
            allowed_tools=value.get("allowed_tools", value.get("tools", ())),
            allowed_resources=value.get("allowed_resources", value.get("resources", ())),
            output_fields=value.get("output_fields", value.get("outputs", ("summary",))),
            sensitive_fields=value.get("sensitive_fields", ()),
            blocked_fields=value.get("blocked_fields", ()),
            sensitive_field_mode=value.get("sensitive_field_mode", "block"),
            allowed_recipient_roles=value.get("allowed_recipient_roles", ("sender",)),
            max_rounds=int(value.get("max_rounds", 2)),
            allowed_recipient_agents=value.get("allowed_recipient_agents", ()),
        )


class TemplateRegistry:
    def __init__(self, templates: Iterable[TaskTemplate] | None = None) -> None:
        self._templates: dict[tuple[str, str], TaskTemplate] = {}
        for template in templates or ():
            self.register(template)

    def register(self, template: TaskTemplate | Mapping[str, Any]) -> TaskTemplate:
        if isinstance(template, Mapping):
            template = TaskTemplate.from_dict(template)
        key = (template.template_id, str(template.version))
        existing = self._templates.get(key)
        if existing is not None and existing != template:
            raise ValueError("template version is already registered with different policy")
        self._templates[key] = template
        return template

    def resolve(self, template_id: str, version: str | int) -> TaskTemplate:
        try:
            return self._templates[(str(template_id), str(version))]
        except KeyError as error:
            raise IsolationError(f"Task template {template_id!r} version {version!r} is not approved") from error

    get = resolve

    def __contains__(self, key: object) -> bool:
        if isinstance(key, tuple) and len(key) == 2:
            return (str(key[0]), str(key[1])) in self._templates
        return False


@dataclass(frozen=True)
class CapabilityGrant:
    capability: str
    grant_id: str
    actor: str
    reason: str

    def as_dict(self) -> dict[str, str | int]:
        return {
            "schema_version": 1,
            "capability": self.capability,
            "grant_id": self.grant_id,
            "actor": self.actor,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class AuthorizationReceipt:
    status: str
    workspace_id: str
    conversation_id: str
    tools: tuple[str, ...]
    resources: tuple[str, ...]
    output_fields: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "status": self.status,
            "workspace_id": self.workspace_id,
            "conversation_id": self.conversation_id,
            "tools": list(self.tools),
            "resources": list(self.resources),
            "output_fields": list(self.output_fields),
        }


@dataclass
class RestrictedWorkspace:
    """A synthetic isolated workspace for one collaboration Worker.

    The workspace has one dedicated conversation and explicit allowlists.  It
    never interprets a prompt as an authorization signal; prompt text is
    carried for audit only while the machine policy checks every requested
    capability.
    """

    workspace_id: str
    collaboration_conversation: str
    allowed_tools: frozenset[str] = frozenset()
    allowed_resources: frozenset[str] = frozenset()
    _capabilities: dict[str, bool] = field(default_factory=lambda: {"screenshot_ocr": False, "clipboard": False})
    capability_records: list[CapabilityGrant] = field(default_factory=list)
    access_log: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.workspace_id or not self.collaboration_conversation:
            raise ValueError("workspace_id and collaboration_conversation are required")
        self.allowed_tools = _names(self.allowed_tools)
        self.allowed_resources = _names(self.allowed_resources)
        requested_capabilities = dict(self._capabilities)
        unknown = set(requested_capabilities) - {"screenshot_ocr", "clipboard"}
        if unknown:
            raise ValueError(f"unknown fallback capabilities: {sorted(unknown)}")
        if any(bool(value) for value in requested_capabilities.values()):
            raise CapabilityError("fallback capabilities require an explicit grant")
        self._capabilities = {"screenshot_ocr": False, "clipboard": False}

    def authorize(
        self,
        template: TaskTemplate,
        *,
        target_conversation: str,
        tools: Iterable[str] | None = None,
        resources: Iterable[str] | None = None,
        output_fields: Iterable[str] | None = None,
        prompt: str | None = None,
        tool_names: Iterable[str] | None = None,
        resource_names: Iterable[str] | None = None,
        output_field_names: Iterable[str] | None = None,
    ) -> AuthorizationReceipt:
        if tools is None:
            tools = tool_names
        if resources is None:
            resources = resource_names
        if output_fields is None:
            output_fields = output_field_names
        requested_tools = _names(tools)
        requested_resources = _names(resources)
        requested_outputs = _names(output_fields)
        self._check_conversation(target_conversation)
        self._check_allowlist("tool", requested_tools, self.allowed_tools & template.allowed_tools)
        self._check_allowlist("resource", requested_resources, self.allowed_resources & template.allowed_resources)
        self._check_allowlist("output field", requested_outputs, template.output_fields)
        # ``prompt`` is deliberately not inspected for permission.  This is a
        # machine-only policy boundary; natural language cannot expand it.
        self.access_log.append(
            {
                "operation": "authorize",
                "conversation": target_conversation,
                "tools": sorted(requested_tools),
                "resources": sorted(requested_resources),
                "output_fields": sorted(requested_outputs),
                "prompt_present": prompt is not None,
            }
        )
        return AuthorizationReceipt(
            status="authorized",
            workspace_id=self.workspace_id,
            conversation_id=target_conversation,
            tools=tuple(sorted(requested_tools)),
            resources=tuple(sorted(requested_resources)),
            output_fields=tuple(sorted(requested_outputs)),
        )

    def authorize_request(
        self,
        *,
        template: TaskTemplate | None,
        target_conversation: str,
        tools: Iterable[str] | None = None,
        resources: Iterable[str] | None = None,
        output_fields: Iterable[str] | None = None,
        prompt: str | None = None,
        tool_names: Iterable[str] | None = None,
        resource_names: Iterable[str] | None = None,
        output_field_names: Iterable[str] | None = None,
    ) -> AuthorizationReceipt:
        if template is None:
            # A template is required for real execution.  This path is only a
            # convenience for a pre-resolved request and still enforces the
            # workspace allowlists and dedicated conversation.
            template = TaskTemplate(
                template_id="unregistered",
                version="1",
                allowed_tools=self.allowed_tools,
                allowed_resources=self.allowed_resources,
                output_fields=_names(output_fields) or frozenset({"summary"}),
            )
        return self.authorize(
            template,
            target_conversation=target_conversation,
            tools=tools,
            resources=resources,
            output_fields=output_fields,
            prompt=prompt,
            tool_names=tool_names,
            resource_names=resource_names,
            output_field_names=output_field_names,
        )

    def _check_conversation(self, target_conversation: str) -> None:
        if target_conversation != self.collaboration_conversation:
            raise IsolationError("Desktop automation may access only the dedicated collaboration conversation")

    @staticmethod
    def _check_allowlist(kind: str, requested: frozenset[str], allowed: frozenset[str]) -> None:
        unauthorized = requested - allowed
        if unauthorized:
            raise IsolationError(f"{kind} request is outside the machine allowlist: {sorted(unauthorized)}")

    def access_conversation(self, conversation_id: str) -> str:
        self._check_conversation(conversation_id)
        self.access_log.append({"operation": "conversation", "conversation": conversation_id})
        return conversation_id

    def read_resource(self, resource: str) -> str:
        if resource not in self.allowed_resources or resource.startswith(("/", "~", "..")):
            raise IsolationError("resource is outside the restricted workspace")
        self.access_log.append({"operation": "resource", "resource": resource})
        return resource

    read_file = read_resource

    def invoke_tool(
        self,
        template: TaskTemplate,
        tool: str,
        *,
        target_conversation: str | None = None,
        resources: Iterable[str] | None = None,
        prompt: str | None = None,
    ) -> dict[str, Any]:
        self.authorize(
            template,
            target_conversation=target_conversation or self.collaboration_conversation,
            tools=[tool],
            resources=resources,
            prompt=prompt,
        )
        return {"schema_version": 1, "status": "executed", "workspace_id": self.workspace_id, "tool": tool}

    def capability_enabled(self, capability: str) -> bool:
        if capability not in self._capabilities:
            raise CapabilityError(f"unknown fallback capability: {capability}")
        return bool(self._capabilities[capability])

    is_capability_enabled = capability_enabled

    def grant_capability(self, capability: str, *, actor: str, grant_id: str, reason: str) -> CapabilityGrant:
        if capability not in self._capabilities:
            raise CapabilityError(f"unknown fallback capability: {capability}")
        if not actor or not grant_id or not reason:
            raise CapabilityError("capability grants require an actor, grant_id, and reason")
        grant = CapabilityGrant(capability, grant_id, actor, reason)
        self._capabilities[capability] = True
        self.capability_records.append(grant)
        self.access_log.append({"operation": "capability_grant", **grant.as_dict()})
        return grant

    enable_capability = grant_capability

    def use_capability(self, capability: str) -> dict[str, Any]:
        if not self.capability_enabled(capability):
            raise CapabilityError(f"{capability} is disabled; an explicit capability grant is required")
        grant = next((item for item in reversed(self.capability_records) if item.capability == capability), None)
        return {
            "schema_version": 1,
            "capability": capability,
            "status": "enabled",
            "grant_id": None if grant is None else grant.grant_id,
        }

    request_capability = use_capability

    def execute(self, template: TaskTemplate, **request: Any) -> AuthorizationReceipt:
        request.setdefault("target_conversation", self.collaboration_conversation)
        return self.authorize(template, **request)


# Names used by the architecture docs and platform adapter work items.
ExecutionIsolation = RestrictedWorkspace
IsolatedWorkspace = RestrictedWorkspace
ExecutionBoundary = RestrictedWorkspace
EgressPolicy = ResultEgressPolicy
