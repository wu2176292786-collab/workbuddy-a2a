from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gateway_worker import Gateway, SQLiteStore
from gateway_worker.collaboration import (
    Command,
    FakeCollaboration,
    FakeDesktopAdapter,
    FakeWorker,
    ProtocolJournal,
)
from gateway_worker.errors import ReplayError, ScopeViolationError, TaskError


class FakeCollaborationContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = SQLiteStore(str(Path(self.tmp.name) / "gateway.db"))
        self.gateway = Gateway(self.store)
        first = self.gateway.bootstrap(team_name="Team", user_name="Alice", agent_name="Alice Agent")
        second_user = self.store.create_user(first.team.id, "Bob")
        second_agent = self.store.create_agent(first.team.id, second_user.id, "Bob Agent")
        self.team_id = first.team.id
        self.sender = first.agent
        self.recipient = second_agent
        self._pair(self.sender.id, "worker-a")
        self._pair(self.recipient.id, "worker-b")

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

    def _new_harness(self) -> FakeCollaboration:
        return FakeCollaboration(self.gateway)

    def _create(self, harness: FakeCollaboration):
        return harness.submit_task(
            sender_agent_id=self.sender.id,
            recipient_agent_id=self.recipient.id,
            template={"id": "research_summary", "version": "1"},
            input_data={"topic": "renewable energy"},
            scope={"allowed_input_keys": ["question"], "max_rounds": 2},
            permissions=["read"],
        )

    def test_two_round_flow_preserves_task_id_and_returns_execution_evidence(self) -> None:
        harness = self._new_harness()
        task = self._create(harness)

        outcome = harness.run_two_rounds(task.id, additional_input={"question": "compare costs"})

        self.assertEqual(outcome.task.state, "COMPLETED")
        self.assertEqual(outcome.task.id, task.id)
        self.assertEqual(outcome.rounds, (1, 2))
        self.assertEqual(outcome.evidence.task_id, task.id)
        self.assertEqual(outcome.evidence.command_id, f"{task.id}:round:2")
        self.assertTrue(outcome.evidence.result_hash.startswith("sha256:"))
        self.assertEqual(outcome.result.task_id, task.id)
        self.assertIn("renewable energy", outcome.result.summary)
        self.assertEqual(harness.adapters[self.recipient.id].execution_count, 2)

        event_types = [event.event_type for event in harness.events_for(task.id)]
        self.assertIn("task.delivered", event_types)
        self.assertIn("confirmation.accepted", event_types)
        self.assertIn("coordination.needs_input", event_types)
        self.assertIn("coordination.input_provided", event_types)
        self.assertIn("execution.evidence", event_types)
        self.assertIn("result.completed", event_types)
        self.assertTrue(all(event.task_id == task.id for event in harness.events_for(task.id)))

    def test_needs_input_is_restricted_to_original_scope(self) -> None:
        harness = self._new_harness()
        task = self._create(harness)
        harness.deliver_task(task.id)
        harness.confirm_task(task.id)
        harness.start_task(task.id)

        with self.assertRaises(ScopeViolationError):
            harness.request_input(task.id, fields=["question", "unapproved"])
        self.assertEqual(harness.current_task(task.id).state, "RUNNING")

        harness.request_input(task.id, fields=["question"])
        with self.assertRaises(ScopeViolationError):
            harness.provide_input(task.id, {"unapproved": "secret"})
        self.assertEqual(harness.current_task(task.id).state, "NEEDS_INPUT")

    def test_protocol_events_and_results_are_idempotent_on_replay(self) -> None:
        harness = self._new_harness()
        task = self._create(harness)
        harness.deliver_task(task.id, event_id="delivery-1")
        accepted = harness.confirm_task(task.id, event_id="confirm-1")
        accepted_again = harness.confirm_task(task.id, event_id="confirm-1")
        self.assertEqual(accepted.state_version, accepted_again.state_version)
        harness.start_task(task.id)
        evidence = harness.execute_round(task.id, round_number=1)
        result = harness.complete_task(task.id, evidence=evidence, event_id="result-1")
        result_again = harness.complete_task(task.id, evidence=evidence, event_id="result-1")
        self.assertEqual(result.state_version, result_again.state_version)
        self.assertEqual(harness.adapters[self.recipient.id].execution_count, 1)
        self.assertEqual(len([e for e in harness.events_for(task.id) if e.event_type == "result.completed"]), 1)

        with self.assertRaises(ReplayError):
            harness.complete_task(task.id, evidence=evidence, event_id="result-1", summary="tampered")

    def test_command_journal_and_ui_reconciliation_prevent_duplicate_execution(self) -> None:
        journal = ProtocolJournal()
        adapter = FakeDesktopAdapter(worker_id="worker-b", worker_epoch=1, journal=journal)
        command = Command(
            command_id="cmd-1",
            task_id="task-1",
            target_conversation="collaboration:worker-b",
            intent={"template_id": "research_summary", "round": 1, "topic": "x"},
            worker_epoch=1,
        )
        first = adapter.execute(command)
        second = adapter.execute(command)
        self.assertEqual(first, second)
        self.assertEqual(adapter.execution_count, 1)
        reconciliation = adapter.reconcile("cmd-1")
        self.assertEqual(reconciliation.status, "matched")
        self.assertEqual(reconciliation.command_id, "cmd-1")

        changed = Command(
            command_id="cmd-1",
            task_id="task-1",
            target_conversation="collaboration:worker-b",
            intent={"template_id": "different", "round": 1},
            worker_epoch=1,
        )
        with self.assertRaises(ReplayError):
            adapter.execute(changed)

        uncertain = Command(
            command_id="cmd-uncertain",
            task_id="task-1",
            target_conversation="collaboration:worker-b",
            intent={"template_id": "research_summary", "round": 2},
            worker_epoch=1,
        )
        adapter.inject(uncertain)
        self.assertEqual(adapter.reconcile("cmd-uncertain").status, "uncertain")
        with self.assertRaises(TaskError):
            adapter.execute(uncertain)

    def test_fake_worker_receives_and_confirms_a_task(self) -> None:
        harness = self._new_harness()
        task = self._create(harness)
        worker = FakeWorker(self.gateway, self.recipient.id)
        envelope = worker.receive(task)
        self.assertEqual(envelope["task_id"], task.id)
        self.assertEqual(worker.confirm(task).state, "ACCEPTED")

    def test_recorded_cancellation_replay_is_a_noop(self) -> None:
        harness = self._new_harness()
        task = self._create(harness)
        harness.deliver_task(task.id)
        harness.confirm_task(task.id)
        harness.start_task(task.id)
        cancelled = harness.cancel_task(task.id, event_id="cancel-1")
        replay = harness.cancel_task(task.id, event_id="cancel-1")
        self.assertEqual(cancelled.state, "CANCELLED")
        self.assertEqual(cancelled.state_version, replay.state_version)

    def test_monitoring_events_have_stable_contract(self) -> None:
        harness = self._new_harness()
        task = self._create(harness)
        harness.deliver_task(task.id)
        event = harness.monitoring_events[-1].as_dict()
        self.assertEqual(
            set(event),
            {"schema_version", "event_type", "task_id", "severity", "worker_id", "round", "details"},
        )
        self.assertEqual(event["event_type"], "task_backlog")
        self.assertEqual(event["details"]["queue_depth"], 1)
        harness.confirm_task(task.id)
        harness.start_task(task.id)
        evidence = harness.execute_round(task.id, round_number=1)
        harness.complete_task(task.id, evidence=evidence)
        names = {item.event_type for item in harness.monitoring_events}
        self.assertIn("execution_evidence", names)
        self.assertIn("task_failure_rate", names)


if __name__ == "__main__":
    unittest.main()
