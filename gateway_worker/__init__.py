"""Gateway and Worker pairing PoC."""

from .gateway import Gateway
from .canonical import canonical_task_fields, compute_task_hash
from .store import SQLiteStore
from .worker import Worker
from .collaboration import (
    Command,
    CommandJournal,
    CollaborationOutcome,
    ExecutionEvidence,
    FakeDesktop,
    FakeCollaboration,
    FakeWorker,
    FakeDesktopAdapter,
    MonitoringEvent,
    ProtocolJournal,
    Reconciliation,
    ResultSummary,
    TaskEvent,
    TaskExecutionEvidence,
    UIReconciliation,
)

__all__ = [
    "Gateway",
    "SQLiteStore",
    "Worker",
    "canonical_task_fields",
    "compute_task_hash",
    "Command",
    "CommandJournal",
    "CollaborationOutcome",
    "ExecutionEvidence",
    "FakeDesktop",
    "FakeCollaboration",
    "FakeWorker",
    "FakeDesktopAdapter",
    "MonitoringEvent",
    "ProtocolJournal",
    "Reconciliation",
    "ResultSummary",
    "TaskEvent",
    "TaskExecutionEvidence",
    "UIReconciliation",
]
