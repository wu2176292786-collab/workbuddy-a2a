from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from gateway_worker.collaboration import Command
from gateway_worker.errors import (
    AutomationPermissionError,
    CapabilityError,
    ControlNotFoundError,
    NeedsAttentionError,
    ReplayError,
    UnsupportedAppVersionError,
)
from gateway_worker.isolation import RestrictedWorkspace, TaskTemplate, TemplateRegistry
from gateway_worker.windows_adapter import (
    FakeWindowsUIAutomationBackend,
    WindowsCommandJournal,
    WindowsCompatibilityProfile,
    WindowsDesktopAdapter,
)


class WindowsDesktopAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.journal_path = Path(self.tmp.name) / "commands.json"
        self.profile = WindowsCompatibilityProfile(
            app_id="workbuddy",
            supported_versions={"1.2.3"},
            collaboration_conversation="collaboration:worker-b",
            input_control="composer",
            reply_control="reply",
            status_control="status",
        )
        self.backend = FakeWindowsUIAutomationBackend(
            app_id="workbuddy",
            app_version="1.2.3",
            collaboration_conversation=self.profile.collaboration_conversation,
            controls={"composer", "reply", "status"},
            reply="A verified summary",
            status="completed",
        )
        self.template = TaskTemplate(
            template_id="research_summary",
            version="1",
            output_fields={"summary"},
        )
        self.registry = TemplateRegistry([self.template])
        self.workspace = RestrictedWorkspace(
            workspace_id="workspace:worker-b",
            collaboration_conversation=self.profile.collaboration_conversation,
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _adapter(self, **kwargs) -> WindowsDesktopAdapter:
        return WindowsDesktopAdapter(
            profile=self.profile,
            backend=self.backend,
            worker_id="worker-b",
            worker_epoch=1,
            journal_path=self.journal_path,
            workspace=self.workspace,
            template_registry=self.registry,
            **kwargs,
        )

    def _command(self, command_id: str = "cmd-1") -> Command:
        return Command(
            command_id=command_id,
            task_id="task-1",
            target_conversation=self.profile.collaboration_conversation,
            intent={"template_id": "research_summary", "template_version": "1", "round": 1, "input": {"topic": "x"}},
            worker_epoch=1,
        )

    def test_installation_checks_permission_version_session_and_controls(self) -> None:
        report = self._adapter().verify_installation()
        self.assertEqual(report.status, "ready")
        self.assertEqual(report.app_version, "1.2.3")
        self.assertEqual(self.backend.selected_conversation, self.profile.collaboration_conversation)

        self.backend.automation_permission_granted = False
        failed = self._adapter()
        with self.assertRaises(AutomationPermissionError):
            failed.verify_installation()
        self.assertEqual(failed.error_events[-1].code, "AUTOMATION_PERMISSION_REQUIRED")

        self.backend.automation_permission_granted = True
        self.backend.app_version = "9.9.9"
        with self.assertRaises(UnsupportedAppVersionError):
            self._adapter().verify_installation()

    def test_execute_injects_into_dedicated_conversation_and_returns_evidence(self) -> None:
        adapter = self._adapter()
        evidence = adapter.execute(self._command())
        self.assertEqual(evidence.task_id, "task-1")
        self.assertEqual(evidence.command_id, "cmd-1")
        self.assertEqual(evidence.summary, "A verified summary")
        self.assertEqual(self.backend.selected_conversation, self.profile.collaboration_conversation)
        self.assertEqual(len(self.backend.injected_texts), 1)
        self.assertIn("cmd-1", self.backend.injected_texts[0])
        self.assertEqual(adapter.reconcile("cmd-1").status, "matched")

    def test_command_is_persisted_before_injection_and_replay_does_not_execute_twice(self) -> None:
        adapter = self._adapter()
        adapter.execute(self._command())
        record = WindowsCommandJournal(self.journal_path).get("cmd-1")
        self.assertIsNotNone(record)
        self.assertEqual(record.status, "completed")
        self.assertEqual(len(self.backend.injected_texts), 1)
        adapter.execute(self._command())
        self.assertEqual(len(self.backend.injected_texts), 1)
        changed = Command(
            command_id="cmd-1",
            task_id="task-1",
            target_conversation=self.profile.collaboration_conversation,
            intent={"template_id": "research_summary", "template_version": "1", "round": 1, "input": {"topic": "tampered"}},
            worker_epoch=1,
        )
        with self.assertRaises(ReplayError):
            adapter.execute(changed)
        raw = json.loads(self.journal_path.read_text())
        self.assertEqual(raw["cmd-1"]["status"], "completed")

    def test_uncertain_reconnect_reconciliation_requires_attention(self) -> None:
        self.backend.after_injection_state = "update_dialog"
        adapter = self._adapter()
        with self.assertRaises(NeedsAttentionError):
            adapter.execute(self._command())
        record = WindowsCommandJournal(self.journal_path).get("cmd-1")
        self.assertEqual(record.status, "injected")

        self.backend.after_injection_state = None
        reconnected = self._adapter()
        reconciliation = reconnected.reconcile("cmd-1")
        self.assertEqual(reconciliation.status, "uncertain")
        with self.assertRaises(NeedsAttentionError):
            reconnected.execute(self._command())

    def test_login_update_focus_and_missing_controls_are_not_bypassed(self) -> None:
        self.backend.ui_state = "login"
        with self.assertRaises(NeedsAttentionError):
            self._adapter().verify_installation()
        self.backend.ui_state = "ready"
        self.backend.focused_control_id = "ordinary-window"
        with self.assertRaises(NeedsAttentionError):
            self._adapter().execute(self._command("cmd-focus"))
        self.backend.focused_control_id = "composer"
        self.backend.controls.remove("reply")
        with self.assertRaises(ControlNotFoundError):
            self._adapter().verify_installation()

    def test_clipboard_fallback_is_disabled_and_restores_original_value_when_granted(self) -> None:
        adapter = self._adapter()
        with self.assertRaises(CapabilityError):
            adapter.with_clipboard("temporary", lambda: self.backend.clipboard_text)
        self.workspace.grant_capability("clipboard", actor="operator-1", grant_id="grant-1", reason="test")
        self.backend.clipboard_text = "original"
        seen = adapter.with_clipboard("temporary", lambda: self.backend.clipboard_text)
        self.assertEqual(seen, "temporary")
        self.assertEqual(self.backend.clipboard_text, "original")


if __name__ == "__main__":
    unittest.main()
