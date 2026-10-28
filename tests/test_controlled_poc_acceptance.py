from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gateway_worker import Gateway, SQLiteStore
from gateway_worker.clawbot import ClawBotAdapter, ClawBotIdentity, FakeClawBotTransport
from gateway_worker.collaboration import FakeCollaboration
from gateway_worker.errors import NeedsAttentionError
from gateway_worker.isolation import RestrictedWorkspace, TaskTemplate, TemplateRegistry
from gateway_worker.macos_adapter import FakeMacOSAccessibilityBackend, MacOSCompatibilityProfile, MacOSDesktopAdapter
from gateway_worker.windows_adapter import FakeWindowsUIAutomationBackend, WindowsCompatibilityProfile, WindowsDesktopAdapter


class ControlledPocAcceptanceTests(unittest.TestCase):
    """Synthetic acceptance matrix; real ClawBot and physical desktop evidence is separate."""

    SAMPLE_SIZE_PER_PLATFORM = 10

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = SQLiteStore(str(Path(self.tmp.name) / "gateway.db"))
        self.gateway = Gateway(self.store)
        first = self.gateway.bootstrap(team_name="Synthetic Acceptance Team", user_name="Alice", agent_name="Alice Agent")
        windows_user = self.store.create_user(first.team.id, "Win User")
        windows_agent = self.store.create_agent(first.team.id, windows_user.id, "Windows Agent")
        mac_user = self.store.create_user(first.team.id, "Mac User")
        mac_agent = self.store.create_agent(first.team.id, mac_user.id, "macOS Agent")
        self.team_id = first.team.id
        self.sender = first.agent
        self.agents = {"windows": windows_agent, "macos": mac_agent}
        self.worker_ids = {"windows": "acceptance-worker-windows", "macos": "acceptance-worker-macos"}
        for platform, agent in self.agents.items():
            self._pair(agent.id, self.worker_ids[platform])

        self.template = TaskTemplate(
            template_id="research_summary",
            version="1",
            output_fields={"summary"},
            max_rounds=2,
        )
        registry = TemplateRegistry([self.template])
        self.adapters = {
            "windows": self._windows_adapter(registry),
            "macos": self._macos_adapter(registry),
        }
        self.harness = FakeCollaboration(
            self.gateway,
            adapters={agent.id: self.adapters[platform] for platform, agent in self.agents.items()},
            template_registry=registry,
            workspaces={
                agent.id: RestrictedWorkspace(
                    f"workspace:{platform}",
                    f"collaboration:{self.worker_ids[platform]}",
                )
                for platform, agent in self.agents.items()
            },
        )
        identities = [
            ClawBotIdentity("clawbot-alice", self.team_id, self.sender.id, authenticated=True, strong_authentication=True),
            ClawBotIdentity("clawbot-windows", self.team_id, self.agents["windows"].id, authenticated=True, strong_authentication=True),
            ClawBotIdentity("clawbot-macos", self.team_id, self.agents["macos"].id, authenticated=True, strong_authentication=True),
        ]
        self.transport = FakeClawBotTransport(identities)
        self.clawbot = ClawBotAdapter(
            gateway=self.gateway,
            transport=self.transport,
            collaboration=self.harness,
            channel_by_agent={
                self.sender.id: "clawbot-alice",
                self.agents["windows"].id: "clawbot-windows",
                self.agents["macos"].id: "clawbot-macos",
            },
        )

    def tearDown(self) -> None:
        self.store.close()
        self.tmp.cleanup()

    def _pair(self, agent_id: str, worker_id: str) -> None:
        code = self.store.create_pairing_code(self.team_id, agent_id)
        key = Ed25519PrivateKey.generate()
        self.store.pair_worker(
            code=code.code,
            team_id=self.team_id,
            agent_id=agent_id,
            worker_id=worker_id,
            public_key=key.public_key().public_bytes_raw(),
        )

    def _windows_adapter(self, registry: TemplateRegistry) -> WindowsDesktopAdapter:
        worker_id = self.worker_ids["windows"]
        profile = WindowsCompatibilityProfile(
            "workbuddy",
            {"acceptance-windows-1"},
            f"collaboration:{worker_id}",
            "composer",
            "reply",
            "status",
        )
        backend = FakeWindowsUIAutomationBackend(
            app_id="workbuddy",
            app_version="acceptance-windows-1",
            collaboration_conversation=profile.collaboration_conversation,
            controls={"composer", "reply", "status"},
            reply="synthetic Windows result",
            status="completed",
        )
        return WindowsDesktopAdapter(
            profile=profile,
            backend=backend,
            worker_id=worker_id,
            worker_epoch=1,
            journal_path=Path(self.tmp.name) / "windows-commands.json",
            workspace=RestrictedWorkspace("workspace:windows", profile.collaboration_conversation),
            template_registry=registry,
        )

    def _macos_adapter(self, registry: TemplateRegistry) -> MacOSDesktopAdapter:
        worker_id = self.worker_ids["macos"]
        profile = MacOSCompatibilityProfile(
            "workbuddy",
            {"acceptance-macos-1"},
            f"collaboration:{worker_id}",
            "composer",
            "reply",
            "status",
        )
        backend = FakeMacOSAccessibilityBackend(
            app_id="workbuddy",
            app_version="acceptance-macos-1",
            collaboration_conversation=profile.collaboration_conversation,
            controls={"composer", "reply", "status"},
            reply="synthetic macOS result",
            status="completed",
        )
        return MacOSDesktopAdapter(
            profile=profile,
            backend=backend,
            worker_id=worker_id,
            worker_epoch=1,
            journal_path=Path(self.tmp.name) / "macos-commands.json",
            workspace=RestrictedWorkspace("workspace:macos", profile.collaboration_conversation),
            template_registry=registry,
        )

    def _new_task(self, platform: str, sample: int):
        return self.harness.submit_task(
            sender_agent_id=self.sender.id,
            recipient_agent_id=self.agents[platform].id,
            template=self.template,
            input_data={"topic": f"synthetic-{platform}-{sample}"},
            scope={"allowed_input_keys": ["question"], "max_rounds": 2},
            permissions=["read"],
        )

    def _confirm_from_clawbot(self, task):
        channel = self.clawbot.channel_by_agent[task.recipient_agent_id]
        notice = self.transport.messages_for(channel)[-1]
        envelope = {
            "type": "task_confirmation",
            "format": "clawbot_confirmation_v1",
            "message_id": f"acceptance-confirm:{task.id}",
            "task_id": task.id,
            "task_hash": notice["task_hash"],
            "confirmation_nonce": notice["confirmation_nonce"],
            "expires_at": notice["expires_at"],
            "decision": "accept",
        }
        return self.clawbot.receive_confirmation(channel, envelope)

    def _run_two_round_flow(self, platform: str, sample: int):
        task = self._new_task(platform, sample)
        self.clawbot.notify_task_created(task)
        self.harness.deliver_task(task.id)
        accepted = self._confirm_from_clawbot(task)
        self.assertEqual(accepted.state, "ACCEPTED")
        started = self.harness.start_task(task.id)
        self.assertEqual(started.state, "RUNNING")
        self.clawbot.notify_state(task, "RUNNING", reason="accepted")
        first_evidence = self.harness.execute_round(task.id, round_number=1)
        self.harness.request_input(task.id, fields=["question"])
        self.harness.provide_input(task.id, {"question": "compare two options"})
        second_evidence = self.harness.execute_round(task.id, round_number=2)
        completed = self.harness.complete_task(task.id, evidence=second_evidence)
        self.assertEqual(completed.state, "COMPLETED")
        self.clawbot.notify_result(task, summary=second_evidence.summary, evidence=second_evidence)
        events = self.harness.events_for(task.id)
        self.assertEqual({event.task_id for event in events}, {task.id})
        self.assertEqual([e.round_number for e in events if e.event_type == "execution.evidence"], [1, 2])
        return task, first_evidence, second_evidence

    def test_twenty_synthetic_samples_cover_both_platforms_and_bilateral_notifications(self) -> None:
        results = []
        for platform in ("windows", "macos"):
            for sample in range(self.SAMPLE_SIZE_PER_PLATFORM):
                results.append((platform, *self._run_two_round_flow(platform, sample)))
        self.assertEqual(len(results), 20)
        self.assertGreaterEqual(len(results) / 20, 0.90)
        for platform, task, _first, second in results:
            self.assertEqual(self.adapters[platform].execution_count, self.SAMPLE_SIZE_PER_PLATFORM * 2)
            self.assertEqual(second.task_id, task.id)
            sender_messages = self.transport.messages_for("clawbot-alice")
            recipient_messages = self.transport.messages_for(self.clawbot.channel_by_agent[task.recipient_agent_id])
            sender_types = {message["type"] for message in sender_messages if message.get("task_id") == task.id}
            recipient_types = {message["type"] for message in recipient_messages if message.get("task_id") == task.id}
            self.assertTrue({"task_created", "task_state_changed", "result_completed"} <= sender_types)
            self.assertTrue({"task_confirmation_required", "task_state_changed", "result_completed"} <= recipient_types)
            self.assertTrue(any(message["type"] == "result_completed" and message["task_id"] == task.id for message in sender_messages))
            self.assertTrue(any(message["type"] == "result_completed" and message["task_id"] == task.id for message in recipient_messages))

    def test_injected_ui_failures_enter_needs_attention_without_duplicate_execution(self) -> None:
        windows_task = self._new_task("windows", 100)
        self.clawbot.notify_task_created(windows_task)
        self.harness.deliver_task(windows_task.id)
        self._confirm_from_clawbot(windows_task)
        self.harness.start_task(windows_task.id)
        windows_backend = self.adapters["windows"].backend
        windows_backend.after_injection_state = "update_dialog"
        with self.assertRaises(NeedsAttentionError):
            self.harness.execute_round(windows_task.id, round_number=1)
        self.assertEqual(self.harness.current_task(windows_task.id).state, "NEEDS_ATTENTION")
        self.assertEqual(self.adapters["windows"].execution_count, 0)
        self.assertEqual(len(windows_backend.injected_texts), 1)

        mac_task = self._new_task("macos", 101)
        self.clawbot.notify_task_created(mac_task)
        self.harness.deliver_task(mac_task.id)
        self._confirm_from_clawbot(mac_task)
        self.harness.start_task(mac_task.id)
        mac_backend = self.adapters["macos"].backend
        mac_backend.ui_state = "login"
        with self.assertRaises(NeedsAttentionError):
            self.harness.execute_round(mac_task.id, round_number=1)
        self.assertEqual(self.harness.current_task(mac_task.id).state, "NEEDS_ATTENTION")
        self.assertEqual(self.adapters["macos"].execution_count, 0)


if __name__ == "__main__":
    unittest.main()
