from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gateway_worker import Gateway, SQLiteStore
from gateway_worker.clawbot import (
    ClawBotAdapter,
    ClawBotIdentity,
    FakeClawBotTransport,
)
from gateway_worker.collaboration import FakeCollaboration
from gateway_worker.errors import (
    ChannelAuthenticationError,
    ConfirmationEnvelopeError,
    ForwardedMessageError,
    PlainTextConfirmationError,
    ReplayError,
)
from gateway_worker.isolation import TaskTemplate, TemplateRegistry, RestrictedWorkspace


class ClawBotAdapterTests(unittest.TestCase):
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
        for agent_id, worker_id in ((self.sender.id, "worker-a"), (self.recipient.id, "worker-b")):
            code = self.store.create_pairing_code(self.team_id, agent_id)
            key = Ed25519PrivateKey.generate()
            self.store.pair_worker(
                code=code.code,
                team_id=self.team_id,
                agent_id=agent_id,
                worker_id=worker_id,
                public_key=key.public_key().public_bytes_raw(),
            )
        self.transport = FakeClawBotTransport(
            [
                ClawBotIdentity("wechat-alice", self.team_id, self.sender.id, authenticated=True, strong_authentication=True),
                ClawBotIdentity("wechat-bob", self.team_id, self.recipient.id, authenticated=True, strong_authentication=True),
                ClawBotIdentity("wechat-weak", self.team_id, self.recipient.id, authenticated=True, strong_authentication=False),
            ]
        )
        self.harness = FakeCollaboration(self.gateway)
        self.adapter = ClawBotAdapter(
            gateway=self.gateway,
            transport=self.transport,
            collaboration=self.harness,
            channel_by_agent={self.sender.id: "wechat-alice", self.recipient.id: "wechat-bob"},
        )

    def tearDown(self) -> None:
        self.store.close()
        self.tmp.cleanup()

    def _create(self, **kwargs):
        return self.harness.submit_task(
            sender_agent_id=self.sender.id,
            recipient_agent_id=self.recipient.id,
            template={"id": "research_summary", "version": "1"},
            input_data={"topic": "renewable energy"},
            scope={"allowed_input_keys": ["question"], "max_rounds": 2},
            permissions=["read"],
            **kwargs,
        )

    def test_creation_notice_contains_immutable_summary_and_reaches_both_channels(self) -> None:
        task = self._create()
        self.adapter.notify_task_created(task)
        messages = self.transport.messages_for("wechat-bob")
        self.assertEqual(len(messages), 1)
        message = messages[0]
        self.assertEqual(message["type"], "task_confirmation_required")
        self.assertEqual(message["task_id"], task.id)
        self.assertEqual(message["task_hash"], task.task_hash)
        self.assertEqual(message["recipient_agent_id"], self.recipient.id)
        self.assertEqual(message["input"], task.input_data)
        self.assertEqual(message["scope"], task.scope)
        self.assertNotIn("fencing_token", message)
        self.assertEqual(len(self.transport.messages_for("wechat-alice")), 1)

    def test_only_authenticated_recipient_machine_envelope_can_confirm(self) -> None:
        task = self._create()
        self.adapter.notify_task_created(task)
        notice = self.transport.messages_for("wechat-bob")[0]
        envelope = {
            "type": "task_confirmation",
            "format": "clawbot_confirmation_v1",
            "message_id": "confirm-1",
            "task_id": task.id,
            "task_hash": notice["task_hash"],
            "confirmation_nonce": notice["confirmation_nonce"],
            "expires_at": notice["expires_at"],
            "decision": "accept",
        }
        accepted = self.adapter.receive_confirmation("wechat-bob", envelope)
        self.assertEqual(accepted.state, "ACCEPTED")

        with self.assertRaises(PlainTextConfirmationError):
            self.adapter.receive_confirmation("wechat-bob", "yes")
        with self.assertRaises(ChannelAuthenticationError):
            self.adapter.receive_confirmation("wechat-weak", {**envelope, "message_id": "weak"})
        with self.assertRaises(ForwardedMessageError):
            self.adapter.receive_confirmation("wechat-bob", {**envelope, "message_id": "forwarded", "forwarded_from": "wechat-alice"})

    def test_confirmation_hash_nonce_expiry_and_replay_are_rejected(self) -> None:
        task = self._create()
        self.adapter.notify_task_created(task)
        notice = self.transport.messages_for("wechat-bob")[0]
        envelope = {
            "type": "task_confirmation",
            "format": "clawbot_confirmation_v1",
            "message_id": "confirm-1",
            "task_id": task.id,
            "task_hash": notice["task_hash"],
            "confirmation_nonce": notice["confirmation_nonce"],
            "expires_at": notice["expires_at"],
            "decision": "accept",
        }
        self.adapter.receive_confirmation("wechat-bob", envelope)
        replay = self.adapter.receive_confirmation("wechat-bob", envelope)
        self.assertEqual(replay.state, "ACCEPTED")
        with self.assertRaises(ReplayError):
            self.adapter.receive_confirmation("wechat-bob", {**envelope, "decision": "reject"})

        task2 = self._create(expires_at=time.time() - 1)
        self.adapter.notify_task_created(task2)
        notice2 = self.transport.messages_for("wechat-bob")[-1]
        with self.assertRaises(ConfirmationEnvelopeError):
            self.adapter.receive_confirmation(
                "wechat-bob",
                {"type": "task_confirmation", "format": "clawbot_confirmation_v1", "message_id": "expired", "task_id": task2.id, "task_hash": notice2["task_hash"], "confirmation_nonce": notice2["confirmation_nonce"], "expires_at": notice2["expires_at"], "decision": "accept"},
            )

    def test_status_and_failure_notifications_reach_both_users(self) -> None:
        task = self._create()
        self.adapter.notify_task_created(task)
        self.adapter.notify_state(task, "RUNNING", reason="accepted")
        self.adapter.notify_failure(task, "UI state uncertain")
        for channel in ("wechat-alice", "wechat-bob"):
            types = [message["type"] for message in self.transport.messages_for(channel)]
            self.assertTrue("task_created" in types or "task_confirmation_required" in types)
            self.assertIn("task_state_changed", types)
            self.assertIn("task_failed", types)

    def test_sensitive_result_requires_recipient_approval_before_completion(self) -> None:
        template = TaskTemplate(
            template_id="research_summary",
            version="1",
            output_fields={"summary", "email"},
            sensitive_fields={"email"},
            sensitive_field_mode="approval",
        )
        workspace = RestrictedWorkspace("workspace:bob", "collaboration:worker-b")
        harness = FakeCollaboration(
            self.gateway,
            template_registry=TemplateRegistry([template]),
            workspaces={self.recipient.id: workspace},
        )
        adapter = ClawBotAdapter(
            gateway=self.gateway,
            transport=self.transport,
            collaboration=harness,
            channel_by_agent={self.sender.id: "wechat-alice", self.recipient.id: "wechat-bob"},
        )
        task = harness.submit_task(
            sender_agent_id=self.sender.id,
            recipient_agent_id=self.recipient.id,
            template=template,
            input_data={"topic": "x"},
            scope={},
            permissions=["read"],
        )
        harness.deliver_task(task.id)
        harness.confirm_task(task.id)
        harness.start_task(task.id)
        evidence = harness.execute_round(task.id, round_number=1)
        approval = adapter.request_result_approval(task.id, evidence=evidence, result_fields={"summary": "ok", "email": "bob@example.test"})
        self.assertEqual(approval["type"], "result_approval_required")
        approval_envelope = {"type": "result_approval", "format": "clawbot_result_approval_v1", "message_id": "approval-1", "task_id": task.id, "approval_id": approval["approval_id"], "decision": "approve"}
        completed = adapter.receive_result_approval("wechat-bob", approval_envelope)
        self.assertEqual(completed.state, "COMPLETED")
        self.assertTrue(any(message["type"] == "result_completed" for message in self.transport.messages_for("wechat-alice")))


if __name__ == "__main__":
    unittest.main()
