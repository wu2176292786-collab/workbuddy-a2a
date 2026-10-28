class GatewayError(Exception):
    """Base class for expected Gateway/Worker interface errors."""

    code = "GATEWAY_ERROR"


class ValidationError(GatewayError):
    code = "INVALID_REQUEST"


class PairingError(GatewayError):
    code = "PAIRING_REJECTED"


class WorkerNotFound(GatewayError):
    code = "WORKER_NOT_FOUND"


class WorkerRevoked(GatewayError):
    code = "WORKER_REVOKED"


class UnauthorizedWorker(GatewayError):
    code = "WORKER_UNAUTHORIZED"


class NoActiveWorker(GatewayError):
    code = "NO_ACTIVE_WORKER"


class WorkerError(GatewayError):
    code = "WORKER_CONNECTION_ERROR"


class TaskError(GatewayError):
    code = "TASK_ERROR"


class ConfirmationError(TaskError):
    code = "CONFIRMATION_REJECTED"


class StateConflictError(TaskError):
    code = "STATE_CONFLICT"


class InvalidTransitionError(TaskError):
    code = "INVALID_TRANSITION"


class TerminalTaskError(TaskError):
    code = "TASK_TERMINAL"


class FencingError(TaskError):
    code = "FENCING_REJECTED"


class TaskExpired(TaskError):
    code = "TASK_EXPIRED"


class ReplayError(TaskError):
    code = "REPLAY_REJECTED"


class ScopeViolationError(TaskError):
    code = "SCOPE_VIOLATION"


class IsolationError(TaskError):
    code = "ISOLATION_VIOLATION"


class CapabilityError(IsolationError):
    code = "CAPABILITY_REJECTED"


class EgressError(TaskError):
    code = "EGRESS_BLOCKED"


class ChannelAuthenticationError(TaskError):
    code = "CHANNEL_AUTHENTICATION_REQUIRED"


class ConfirmationEnvelopeError(TaskError):
    code = "CONFIRMATION_ENVELOPE_REJECTED"


class ForwardedMessageError(ConfirmationEnvelopeError):
    code = "FORWARDED_MESSAGE_REJECTED"


class PlainTextConfirmationError(ConfirmationEnvelopeError):
    code = "PLAINTEXT_CONFIRMATION_REJECTED"


class ApprovalError(TaskError):
    code = "RESULT_APPROVAL_REJECTED"


class AdminAuthorizationError(GatewayError):
    code = "ADMIN_UNAUTHORIZED"


class MFARequiredError(AdminAuthorizationError):
    code = "MFA_REQUIRED"


class ResourceLimitError(GatewayError):
    code = "RESOURCE_LIMIT_EXCEEDED"


class DesktopAdapterError(IsolationError):
    code = "DESKTOP_ADAPTER_ERROR"


class AutomationPermissionError(DesktopAdapterError):
    code = "AUTOMATION_PERMISSION_REQUIRED"


class AccessibilityPermissionError(DesktopAdapterError):
    code = "ACCESSIBILITY_PERMISSION_REQUIRED"


class UnsupportedAppVersionError(DesktopAdapterError):
    code = "UNSUPPORTED_APP_VERSION"


class UIStateError(DesktopAdapterError):
    code = "UNEXPECTED_UI_STATE"


class NeedsAttentionError(DesktopAdapterError):
    code = "NEEDS_ATTENTION"


class ControlNotFoundError(UIStateError):
    code = "UI_CONTROL_NOT_FOUND"


class HumanInterferenceError(NeedsAttentionError):
    code = "HUMAN_INTERFERENCE"
