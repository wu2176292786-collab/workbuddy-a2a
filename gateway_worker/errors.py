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
