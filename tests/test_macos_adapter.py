from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from gateway_worker.collaboration import Command
from gateway_worker.errors import AccessibilityPermissionError, NeedsAttentionError
from gateway_worker.isolation import RestrictedWorkspace, TaskTemplate, TemplateRegistry
from gateway_worker.macos_adapter import (
    FakeMacOSAccessibilityBackend,
    MacOSCompatibilityProfile,
    MacOSDesktopAdapter,
)


class MacOSDesktopAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.profile = MacOSCompatibilityProfile(
            app_id="workbuddy",
            supported_versions={"2.4.0"},
            collaboration_conversation="collaboration:worker-mac",
            input_control="composer",
            reply_control="reply",
            status_control="status",
        )
        self.backend = FakeMacOSAccessibilityBackend(
            app_id="workbuddy",
            app_version="2.4.0",
            collaboration_conversation=self.profile.collaboration_conversation,
            controls={"composer", "reply", "status"},
            reply="macOS verified summary",
            status="completed",
        )
        self.template = TaskTemplate(template_id="research_summary", version="1", output_fields={"summary"})
        self.workspace = RestrictedWorkspace(
            workspace_id="workspace:worker-mac",
            collaboration_conversation=self.profile.collaboration_conversation,
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _adapter(self) -> MacOSDesktopAdapter:
        return MacOSDesktopAdapter(
            profile=self.profile,
            backend=self.backend,
            worker_id="worker-mac",
            worker_epoch=1,
            journal_path=Path(self.tmp.name) / "commands.json",
            workspace=self.workspace,
            template_registry=TemplateRegistry([self.template]),
        )

    def _command(self, command_id: str = "mac-cmd-1") -> Command:
        return Command(
            command_id=command_id,
            task_id="mac-task-1",
            target_conversation=self.profile.collaboration_conversation,
            intent={"template_id": "research_summary", "template_version": "1", "round": 1, "input": {"topic": "x"}},
            worker_epoch=1,
        )

    def test_accessibility_permission_version_and_dedicated_session(self) -> None:
        report = self._adapter().verify_installation()
        self.assertEqual(report.status, "ready")
        self.assertEqual(report.app_version, "2.4.0")
        self.assertEqual(self.backend.selected_conversation, self.profile.collaboration_conversation)
        self.backend.accessibility_permission_granted = False
        adapter = self._adapter()
        with self.assertRaises(AccessibilityPermissionError):
            adapter.verify_installation()
        self.assertEqual(adapter.error_events[-1].code, "ACCESSIBILITY_PERMISSION_REQUIRED")

    def test_execute_replay_and_template_evidence(self) -> None:
        adapter = self._adapter()
        evidence = adapter.execute(self._command())
        self.assertEqual(evidence.summary, "macOS verified summary")
        self.assertEqual(adapter.reconcile("mac-cmd-1").status, "matched")
        adapter.execute(self._command())
        self.assertEqual(len(self.backend.injected_texts), 1)

    def test_uncertain_accessibility_reconnect_requires_attention(self) -> None:
        self.backend.after_injection_state = "update_dialog"
        adapter = self._adapter()
        with self.assertRaises(NeedsAttentionError):
            adapter.execute(self._command())
        reconnected = self._adapter()
        self.assertEqual(reconnected.reconcile("mac-cmd-1").status, "uncertain")

    def test_login_and_human_focus_are_safe_stops(self) -> None:
        self.backend.ui_state = "login"
        with self.assertRaises(NeedsAttentionError):
            self._adapter().verify_installation()
        self.backend.ui_state = "ready"
        self.backend.focused_control_id = "ordinary-window"
        with self.assertRaises(NeedsAttentionError):
            self._adapter().execute(self._command("mac-focus"))

    def test_clipboard_requires_grant_and_restores_original_value(self) -> None:
        adapter = self._adapter()
        self.workspace.grant_capability("clipboard", actor="operator-1", grant_id="mac-grant-1", reason="test")
        self.backend.clipboard_text = "original"
        self.assertEqual(adapter.with_clipboard("temporary", lambda: self.backend.clipboard_text), "temporary")
        self.assertEqual(self.backend.clipboard_text, "original")


if __name__ == "__main__":
    unittest.main()
