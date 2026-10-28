from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gateway_worker import Gateway, SQLiteStore
from gateway_worker.collaboration import Command, FakeCollaboration
from gateway_worker.errors import (
    ConfirmationError,
    FencingError,
    NeedsAttentionError,
    StateConflictError,
    TerminalTaskError,
)
from gateway_worker.macos_adapter import FakeMacOSAccessibilityBackend, MacOSCompatibilityProfile, MacOSDesktopAdapter
from gateway_worker.windows_adapter import FakeWindowsUIAutomationBackend, WindowsCompatibilityProfile, WindowsDesktopAdapter
from gateway_worker.isolation import RestrictedWorkspace, TaskTemplate, TemplateRegistry


class AdversarialRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = SQLiteStore(str(Path(self.tmp.name) / "gateway.db"))
        self.gateway = Gateway(self.store)
        first = self.gateway.bootstrap(team_name="Team", user_name="Alice", agent_name="Alice Agent")
        user = self.store.create_user(first.team.id, "Bob")
        recipient = self.store.create_agent(first.team.id, user.id, "Bob Agent")
        self.team_id = first.team.id
        self.sender = first.agent
        self.recipient = recipient
        self.worker_ids = {}
        for agent_id, worker_id in ((self.sender.id, "worker-a"), (self.recipient.id, "worker-b")):
            self._pair(agent_id, worker_id)
            self.worker_ids[agent_id] = worker_id
        self.harness = FakeCollaboration(self.gateway)

    def tearDown(self) -> None:
        self.store.close()
        self.tmp.cleanup()

    def _pair(self, agent_id: str, worker_id: str) -> None:
        code = self.store.create_pairing_code(self.team_id, agent_id)
        key = Ed25519PrivateKey.generate()
        self.store.pair_worker(code=code.code, team_id=self.team_id, agent_id=agent_id, worker_id=worker_id, public_key=key.public_key().public_bytes_raw())

    def _task(self, **kwargs):
        return self.harness.submit_task(
            sender_agent_id=self.sender.id,
            recipient_agent_id=self.recipient.id,
            template={"id": "research_summary", "version": "1"},
            input_data={"topic": "x"},
            scope={"allowed_input_keys": ["question"], "max_rounds": 2},
            permissions=["read"],
            **kwargs,
        )

    def _running(self):
        task = self._task()
        self.harness.deliver_task(task.id)
        self.harness.confirm_task(task.id)
        self.harness.start_task(task.id)
        return self.harness.current_task(task.id)

    def test_windows_crash_boundaries_never_blindly_repeat(self) -> None:
        profile = WindowsCompatibilityProfile("workbuddy", {"1"}, "collaboration:worker-b", "composer", "reply", "status")
        backend = FakeWindowsUIAutomationBackend(app_id="workbuddy", app_version="1", collaboration_conversation=profile.collaboration_conversation, controls={"composer", "reply", "status"}, reply="ok", status="completed")
        journal_path = Path(self.tmp.name) / "windows.json"
        adapter = WindowsDesktopAdapter(profile=profile, backend=backend, worker_id="worker-b", worker_epoch=1, journal_path=journal_path, workspace=RestrictedWorkspace("ws", profile.collaboration_conversation), template_registry=TemplateRegistry([TaskTemplate("research_summary", "1")]))
        command = Command("cmd-before", "task-1", profile.collaboration_conversation, {"template_id": "research_summary", "template_version": "1"}, 1)
        adapter.prepare_command(command)
        reconnected = WindowsDesktopAdapter(profile=profile, backend=backend, worker_id="worker-b", worker_epoch=1, journal_path=journal_path, workspace=RestrictedWorkspace("ws", profile.collaboration_conversation), template_registry=TemplateRegistry([TaskTemplate("research_summary", "1")]))
        self.assertEqual(reconnected.reconcile(command.command_id).status, "not_found")
        reconnected.execute(command)
        self.assertEqual(len(backend.injected_texts), 1)

        backend.after_injection_state = "update_dialog"
        command2 = Command("cmd-after", "task-2", profile.collaboration_conversation, {"template_id": "research_summary", "template_version": "1"}, 1)
        with self.assertRaises(NeedsAttentionError):
            reconnected.execute(command2)
        second_reconnect = WindowsDesktopAdapter(profile=profile, backend=backend, worker_id="worker-b", worker_epoch=1, journal_path=journal_path, workspace=RestrictedWorkspace("ws", profile.collaboration_conversation), template_registry=TemplateRegistry([TaskTemplate("research_summary", "1")]))
        self.assertEqual(second_reconnect.reconcile(command2.command_id).status, "uncertain")
        with self.assertRaises(NeedsAttentionError):
            second_reconnect.execute(command2)
        self.assertEqual(len(backend.injected_texts), 2)

    def test_macos_crash_after_injection_has_same_safe_stop(self) -> None:
        profile = MacOSCompatibilityProfile("workbuddy", {"2"}, "collaboration:worker-mac", "composer", "reply", "status")
        backend = FakeMacOSAccessibilityBackend(app_id="workbuddy", app_version="2", collaboration_conversation=profile.collaboration_conversation, controls={"composer", "reply", "status"}, reply="ok", status="completed")
        path = Path(self.tmp.name) / "mac.json"
        adapter = MacOSDesktopAdapter(profile=profile, backend=backend, worker_id="worker-mac", worker_epoch=1, journal_path=path, workspace=RestrictedWorkspace("ws", profile.collaboration_conversation), template_registry=TemplateRegistry([TaskTemplate("research_summary", "1")]))
        backend.after_injection_state = "update_dialog"
        command = Command("mac-crash", "task-mac", profile.collaboration_conversation, {"template_id": "research_summary", "template_version": "1"}, 1)
        with self.assertRaises(NeedsAttentionError):
            adapter.execute(command)
        reconnect = MacOSDesktopAdapter(profile=profile, backend=backend, worker_id="worker-mac", worker_epoch=1, journal_path=path, workspace=RestrictedWorkspace("ws", profile.collaboration_conversation), template_registry=TemplateRegistry([TaskTemplate("research_summary", "1")]))
        self.assertEqual(reconnect.reconcile(command.command_id).status, "uncertain")

    def test_old_epoch_revoked_worker_and_stale_fencing_cannot_mutate(self) -> None:
        task = self._running()
        caps = self.harness.task_capabilities(task.id)
        self._pair(self.recipient.id, "worker-b-new")
        with self.assertRaises(FencingError):
            self.gateway.transition_task(task.id, expected_state_version=self.harness.current_task(task.id).state_version, new_state="NEEDS_INPUT", worker_id=caps["worker_id"], worker_epoch=caps["worker_epoch"], fencing_token=caps["fencing_token"])
        task2 = self._running()
        caps2 = self.harness.task_capabilities(task2.id)
        time.sleep(1.1)
        # The lease is one minute by default; explicitly shorten it only for
        # this fault-injection test, preserving the public fencing check.
        self.store.connection.execute("UPDATE tasks SET lease_expires_at = ? WHERE id = ?", (time.time() - 1, task2.id))
        self.store.connection.commit()
        with self.assertRaises(FencingError):
            self.gateway.transition_task(task2.id, expected_state_version=task2.state_version, new_state="NEEDS_INPUT", worker_id=caps2["worker_id"], worker_epoch=caps2["worker_epoch"], fencing_token=caps2["fencing_token"])

    def test_terminal_late_events_and_replayed_operations_do_not_reopen(self) -> None:
        task = self._running()
        caps = self.harness.task_capabilities(task.id)
        completed = self.gateway.complete_task(task.id, expected_state_version=task.state_version, worker_id=caps["worker_id"], worker_epoch=caps["worker_epoch"], fencing_token=caps["fencing_token"])
        self.assertEqual(completed.state, "COMPLETED")
        with self.assertRaises(TerminalTaskError):
            self.gateway.fail_task(task.id, expected_state_version=completed.state_version, worker_id=caps["worker_id"], worker_epoch=caps["worker_epoch"], fencing_token=caps["fencing_token"])
        events = self.store.get_task_events(task.id)
        self.assertEqual(events[-1]["reason"], "late_event_rejected")

        task2 = self._task()
        first = self.harness.confirm_task(task2.id, event_id="confirm-replay")
        second = self.harness.confirm_task(task2.id, event_id="confirm-replay")
        self.assertEqual(first.state_version, second.state_version)
        with self.assertRaises(ConfirmationError):
            self.gateway.confirm_task(task2.id, decision="accept", task_hash=task2.task_hash, confirmation_nonce=task2.confirmation_nonce, confirmation_expires_at=task2.expires_at, recipient_agent_id=task2.recipient_agent_id, expected_state_version=task2.state_version, worker_id=task2.worker_id, worker_epoch=task2.worker_epoch, fencing_token=task2.fencing_token)

    def test_stale_cas_race_has_one_state_transition(self) -> None:
        task = self._running()
        caps = self.harness.task_capabilities(task.id)
        expected = task.state_version
        completed = self.gateway.complete_task(task.id, expected_state_version=expected, worker_id=caps["worker_id"], worker_epoch=caps["worker_epoch"], fencing_token=caps["fencing_token"])
        self.assertEqual(completed.state, "COMPLETED")
        with self.assertRaises((StateConflictError, TerminalTaskError)):
            self.gateway.fail_task(task.id, expected_state_version=expected, worker_id=caps["worker_id"], worker_epoch=caps["worker_epoch"], fencing_token=caps["fencing_token"])
        self.assertEqual(self.harness.current_task(task.id).state, "COMPLETED")


if __name__ == "__main__":
    unittest.main()
