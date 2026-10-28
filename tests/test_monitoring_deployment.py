from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from gateway_worker import SQLiteStore
from gateway_worker.backup import SQLiteBackupManager
from gateway_worker.collaboration import MonitoringEvent
from gateway_worker.monitoring import MonitoringCollector


class MonitoringDeploymentTests(unittest.TestCase):
    def test_monitoring_snapshot_metrics_alerts_and_redaction(self) -> None:
        collector = MonitoringCollector(
            queue_depth_limit=3,
            failure_rate_limit=0.25,
            confirmation_timeout_limit=1,
            ui_error_limit=1,
        )
        collector.worker_seen("worker-1", online=True)
        collector.ingest(MonitoringEvent("task_backlog", "task-1", details={"queue_depth": 4, "token": "secret"}))
        collector.ingest(MonitoringEvent("task_failure_rate", "task-1", severity="error", details={"failed": 2, "completed": 1}))
        collector.ingest(MonitoringEvent("confirmation_timeout", "task-2", severity="error", details={"user": "alice@example.test"}))
        collector.ingest(MonitoringEvent("ui_error", "task-3", severity="error", worker_id="worker-1", details={"message": "dialog", "password": "secret"}))
        snapshot = collector.snapshot()
        self.assertEqual(snapshot.workers_online, 1)
        self.assertEqual(snapshot.queue_depth, 4)
        self.assertAlmostEqual(snapshot.failure_rate, 2 / 3)
        self.assertEqual(snapshot.confirmation_timeouts, 1)
        self.assertEqual(snapshot.ui_errors, 1)
        alert_names = {alert.name for alert in collector.alerts()}
        self.assertEqual(alert_names, {"queue_depth_high", "failure_rate_high", "confirmation_timeouts_high", "ui_errors_high"})
        prometheus = collector.prometheus_text()
        self.assertIn("workbuddy_workers_online 1", prometheus)
        self.assertIn("workbuddy_task_failure_rate", prometheus)
        self.assertNotIn("secret", prometheus)
        self.assertNotIn("alice@example.test", prometheus)

        bounded = MonitoringCollector(max_events=2)
        bounded.ingest(MonitoringEvent("task_failure_rate", "task-4", details={"failure_rate": 0.5}))
        bounded.ingest(MonitoringEvent("task_backlog", "task-5", details={"queue_depth": 8}))
        bounded.ingest(MonitoringEvent("ui_error", "task-6"))
        self.assertEqual(bounded.snapshot().failure_rate, 0.5)
        self.assertEqual(len(bounded.events), 2)

    def test_sqlite_backup_restore_and_integrity_manifest(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        source = Path(tmp.name) / "source.db"
        backup = Path(tmp.name) / "backup.db"
        restored = Path(tmp.name) / "restored.db"
        store = SQLiteStore(str(source))
        team = store.bootstrap("Team", "Alice", "Alice Agent")
        manager = SQLiteBackupManager()
        manifest = manager.backup(source, backup, metadata={"team_id": team.team.id, "token": "redacted"})
        self.assertEqual(manifest["integrity_check"], "ok")
        self.assertNotIn("token", manifest)
        self.assertTrue(backup.with_suffix(".db.manifest.json").is_file())
        restored_manifest = manager.restore(backup, restored)
        self.assertEqual(restored_manifest["integrity_check"], "ok")
        restored_store = SQLiteStore(str(restored))
        self.assertIsNotNone(restored_store.get_agent(team.agent.id))
        restored_store.close()
        store.close()
        tmp.cleanup()

    def test_deployment_contract_files_define_services_tls_health_and_backup(self) -> None:
        root = Path(__file__).resolve().parents[1]
        compose = (root / "deploy" / "docker-compose.yml").read_text()
        nginx = (root / "deploy" / "nginx.conf").read_text()
        backup = (root / "deploy" / "backup.sh").read_text()
        self.assertIn("gateway:", compose)
        self.assertIn("postgres:", compose)
        self.assertIn("redis:", compose)
        self.assertIn("reverse-proxy:", compose)
        self.assertIn("healthcheck:", compose)
        self.assertIn("wss://", nginx)
        self.assertIn("proxy_set_header Upgrade", nginx)
        self.assertIn("pg_dump", backup)
        self.assertIn("redis-cli", backup)


if __name__ == "__main__":
    unittest.main()
