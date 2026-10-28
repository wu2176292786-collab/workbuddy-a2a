"""Low-dependency monitoring, metrics, and alert aggregation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .admin import redact
from .collaboration import MonitoringEvent


@dataclass(frozen=True)
class MonitoringSnapshot:
    workers_online: int
    queue_depth: int
    failure_rate: float
    confirmation_timeouts: int
    ui_errors: int
    tasks_failed: int
    tasks_completed: int


@dataclass(frozen=True)
class Alert:
    name: str
    severity: str
    value: float
    threshold: float
    message: str


class MonitoringCollector:
    def __init__(
        self,
        *,
        queue_depth_limit: int = 100,
        failure_rate_limit: float = 0.25,
        confirmation_timeout_limit: int = 10,
        ui_error_limit: int = 10,
        max_events: int = 1000,
    ) -> None:
        self.queue_depth_limit = queue_depth_limit
        self.failure_rate_limit = failure_rate_limit
        self.confirmation_timeout_limit = confirmation_timeout_limit
        self.ui_error_limit = ui_error_limit
        self.max_events = max(1, int(max_events))
        self._workers: dict[str, bool] = {}
        self._queue_depth = 0
        self._failed = 0
        self._completed = 0
        self._failure_rate_override: float | None = None
        self._confirmation_timeouts = 0
        self._ui_errors = 0
        self._events: list[dict[str, Any]] = []

    def worker_seen(self, worker_id: str, *, online: bool = True) -> None:
        self._workers[str(worker_id)] = bool(online)

    def ingest(self, event: MonitoringEvent | Mapping[str, Any]) -> None:
        if isinstance(event, MonitoringEvent):
            event_type = event.event_type
            task_id = event.task_id
            details = event.details
            severity = event.severity
            worker_id = event.worker_id
        else:
            event_type = str(event.get("event_type", "unknown"))
            task_id = event.get("task_id")
            details = event.get("details", {})
            severity = str(event.get("severity", "info"))
            worker_id = event.get("worker_id")
        details = details if isinstance(details, Mapping) else {}
        if worker_id is not None:
            self.worker_seen(str(worker_id), online=True)
        if event_type == "task_backlog":
            self._queue_depth = max(0, int(details.get("queue_depth", 0)))
        elif event_type in {"task_failure_rate", "task_failed"}:
            self._failed += int(details.get("failed", 1 if event_type == "task_failed" else 0))
            self._completed += int(details.get("completed", 0))
            if "failure_rate" in details:
                self._failure_rate_override = max(0.0, min(1.0, float(details["failure_rate"])))
            elif event_type == "task_failed":
                self._failure_rate_override = None
        elif event_type == "confirmation_timeout":
            self._confirmation_timeouts += 1
        elif event_type == "ui_error":
            self._ui_errors += 1
        self._events.append(redact({"event_type": event_type, "task_id": task_id, "severity": severity, "worker_id": worker_id, "details": details}))
        if len(self._events) > self.max_events:
            del self._events[:-self.max_events]

    def snapshot(self) -> MonitoringSnapshot:
        total = self._failed + self._completed
        return MonitoringSnapshot(
            workers_online=sum(1 for online in self._workers.values() if online),
            queue_depth=self._queue_depth,
            failure_rate=self._failure_rate_override if self._failure_rate_override is not None else ((self._failed / total) if total else 0.0),
            confirmation_timeouts=self._confirmation_timeouts,
            ui_errors=self._ui_errors,
            tasks_failed=self._failed,
            tasks_completed=self._completed,
        )

    def alerts(self) -> list[Alert]:
        current = self.snapshot()
        alerts: list[Alert] = []
        if current.queue_depth > self.queue_depth_limit:
            alerts.append(Alert("queue_depth_high", "warning", current.queue_depth, self.queue_depth_limit, "Task queue depth exceeds configured limit"))
        if current.failure_rate > self.failure_rate_limit:
            alerts.append(Alert("failure_rate_high", "critical", current.failure_rate, self.failure_rate_limit, "Task failure rate exceeds configured limit"))
        if current.confirmation_timeouts >= self.confirmation_timeout_limit:
            alerts.append(Alert("confirmation_timeouts_high", "warning", current.confirmation_timeouts, self.confirmation_timeout_limit, "Confirmation timeouts exceed configured limit"))
        if current.ui_errors >= self.ui_error_limit:
            alerts.append(Alert("ui_errors_high", "warning", current.ui_errors, self.ui_error_limit, "UI errors exceed configured limit"))
        return alerts

    def prometheus_text(self) -> str:
        current = self.snapshot()
        lines = [
            "# TYPE workbuddy_workers_online gauge",
            f"workbuddy_workers_online {current.workers_online}",
            "# TYPE workbuddy_task_queue_depth gauge",
            f"workbuddy_task_queue_depth {current.queue_depth}",
            "# TYPE workbuddy_task_failure_rate gauge",
            f"workbuddy_task_failure_rate {current.failure_rate}",
            "# TYPE workbuddy_confirmation_timeouts counter",
            f"workbuddy_confirmation_timeouts {current.confirmation_timeouts}",
            "# TYPE workbuddy_ui_errors counter",
            f"workbuddy_ui_errors {current.ui_errors}",
        ]
        return "\n".join(lines) + "\n"

    def health(self) -> dict[str, Any]:
        current = self.snapshot()
        alerts = self.alerts()
        return {"status": "ok" if not any(alert.severity == "critical" for alert in alerts) else "degraded", "workers_online": current.workers_online, "queue_depth": current.queue_depth, "alerts": [{"name": alert.name, "severity": alert.severity, "value": alert.value, "threshold": alert.threshold} for alert in alerts]}

    @property
    def events(self) -> tuple[dict[str, Any], ...]:
        """Return the bounded, already-redacted event history."""
        return tuple(self._events)
