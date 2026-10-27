import time
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gateway_worker.errors import (
    ConfirmationError,
    FencingError,
    StateConflictError,
    TaskExpired,
    TerminalTaskError,
)
from gateway_worker import compute_task_hash
from gateway_worker.gateway import Gateway
from gateway_worker.protocol import b64url_encode, signable
from gateway_worker.store import SQLiteStore


class TaskAuthorizationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = SQLiteStore(":memory:")
        self.addCleanup(self.store.close)
        self.gateway = Gateway(self.store)
        bootstrap = self.gateway.bootstrap(
            team_name="Example Team",
            user_name="Alice",
            agent_name="Alice's Agent",
        )
        self.team = bootstrap.team
        self.sender = bootstrap.agent
        self.recipient_user = self.store.create_user(self.team.id, "Bob")
        self.recipient = self.store.create_agent(self.team.id, self.recipient_user.id, "Bob's Agent")
        self.worker_key = Ed25519PrivateKey.generate()
        pairing = self.gateway.create_pairing_code(
            team_id=self.team.id,
            agent_id=self.recipient.id,
        )
        public_key = self.worker_key.public_key().public_bytes_raw()
        pair_fields = {
            "pairing_code": pairing.code,
            "team_id": self.team.id,
            "agent_id": self.recipient.id,
            "worker_id": "worker-bob",
            "public_key": b64url_encode(public_key),
            "nonce": "pairing-nonce",
            "timestamp": time.time(),
            "protocol_version": 1,
        }
        self.worker = self.gateway.pair_worker(
            **pair_fields,
            signature=self.worker_key.sign(signable("pair", pair_fields)),
        )

    def create_task(self, **overrides):
        values = {
            "team_id": self.team.id,
            "sender_agent_id": self.sender.id,
            "recipient_agent_id": self.recipient.id,
            "template_id": "research_summary",
            "template_version": "1",
            "input_data": {"b": 2, "a": 1},
            "scope": {"tools": [], "resources": []},
            "permissions": ["read"],
            "expires_at": time.time() + 3600,
        }
        values.update(overrides)
        return self.gateway.create_task(**values)

    def lease_fields(self, task):
        return {
            "worker_id": task.worker_id,
            "worker_epoch": task.worker_epoch,
            "fencing_token": task.fencing_token,
        }

    def test_task_hash_is_stable_for_equivalent_json_and_binds_authorization_fields(self) -> None:
        expiry = time.time() + 3600
        first = self.create_task(expires_at=expiry, input_data={"b": 2, "a": 1})
        equivalent = self.create_task(expires_at=expiry, input_data={"a": 1, "b": 2})

        self.assertEqual(first.task_hash, equivalent.task_hash)
        self.assertTrue(first.task_hash.startswith("sha256:"))
        self.assertEqual(
            first.task_hash,
            compute_task_hash(
                sender_agent_id=self.sender.id,
                recipient_agent_id=self.recipient.id,
                template_id="research_summary",
                template_version="1",
                input_data={"a": 1, "b": 2},
                scope={"tools": [], "resources": []},
                permissions=["read"],
                expires_at=expiry,
            ),
        )
        changed = self.create_task(expires_at=expiry, template_version="2")
        self.assertNotEqual(first.task_hash, changed.task_hash)
        changed = self.create_task(expires_at=expiry, permissions=["read", "export"])
        self.assertNotEqual(first.task_hash, changed.task_hash)

    def test_confirmation_binds_hash_nonce_expiry_identity_and_is_single_use(self) -> None:
        task = self.create_task()
        accepted = self.gateway.confirm_task(
            task.id,
            decision="accept",
            task_hash=task.task_hash,
            confirmation_nonce=task.confirmation_nonce,
            confirmation_expires_at=task.expires_at,
            recipient_agent_id=self.recipient.id,
            expected_state_version=task.state_version,
            **self.lease_fields(task),
        )

        self.assertEqual(accepted.state, "ACCEPTED")
        self.assertEqual(accepted.state_version, task.state_version + 1)
        with self.assertRaises(ConfirmationError):
            self.gateway.confirm_task(
                task.id,
                decision="accept",
                task_hash=task.task_hash,
                confirmation_nonce=task.confirmation_nonce,
                confirmation_expires_at=task.expires_at,
                recipient_agent_id=self.recipient.id,
                expected_state_version=task.state_version,
                **self.lease_fields(task),
            )

    def test_authorization_change_invalidates_previous_confirmation(self) -> None:
        task = self.create_task()
        old_hash = task.task_hash
        old_nonce = task.confirmation_nonce
        changed = self.gateway.update_task_authorization(
            task.id,
            expected_state_version=task.state_version,
            input_data={"a": 9, "b": 2},
        )

        self.assertNotEqual(changed.task_hash, old_hash)
        self.assertNotEqual(changed.confirmation_nonce, old_nonce)
        with self.assertRaises(ConfirmationError):
            self.gateway.confirm_task(
                task.id,
                decision="accept",
                task_hash=old_hash,
                confirmation_nonce=old_nonce,
                confirmation_expires_at=task.expires_at,
                recipient_agent_id=self.recipient.id,
                expected_state_version=changed.state_version,
                **self.lease_fields(changed),
            )

    def test_state_transitions_use_cas_and_terminal_tasks_cannot_reopen(self) -> None:
        task = self.create_task()
        accepted = self.gateway.confirm_task(
            task.id,
            decision="accept",
            task_hash=task.task_hash,
            confirmation_nonce=task.confirmation_nonce,
            confirmation_expires_at=task.expires_at,
            recipient_agent_id=self.recipient.id,
            expected_state_version=task.state_version,
            **self.lease_fields(task),
        )
        with self.assertRaises(StateConflictError):
            self.gateway.start_task(
                task.id,
                expected_state_version=task.state_version,
                **self.lease_fields(task),
            )
        running = self.gateway.start_task(
            task.id,
            expected_state_version=accepted.state_version,
            **self.lease_fields(task),
        )
        completed = self.gateway.complete_task(
            task.id,
            expected_state_version=running.state_version,
            result={"summary": "done"},
            **self.lease_fields(task),
        )
        self.assertEqual(completed.state, "COMPLETED")
        with self.assertRaises(TerminalTaskError):
            self.gateway.fail_task(
                task.id,
                expected_state_version=completed.state_version,
                **self.lease_fields(task),
            )
        self.assertEqual(self.store.get_task_events(task.id)[-1]["reason"], "late_event_rejected")

    def test_fencing_rejects_stale_worker_epoch_or_token(self) -> None:
        task = self.create_task()
        bad_lease = self.lease_fields(task)
        bad_lease["fencing_token"] = "stale-token"
        with self.assertRaises(FencingError):
            self.gateway.confirm_task(
                task.id,
                decision="accept",
                task_hash=task.task_hash,
                confirmation_nonce=task.confirmation_nonce,
                confirmation_expires_at=task.expires_at,
                recipient_agent_id=self.recipient.id,
                expected_state_version=task.state_version,
                **bad_lease,
            )
        bad_lease = self.lease_fields(task)
        bad_lease["worker_epoch"] += 1
        with self.assertRaises(FencingError):
            self.gateway.confirm_task(
                task.id,
                decision="accept",
                task_hash=task.task_hash,
                confirmation_nonce=task.confirmation_nonce,
                confirmation_expires_at=task.expires_at,
                recipient_agent_id=self.recipient.id,
                expected_state_version=task.state_version,
                **bad_lease,
            )

    def test_rejection_expiry_and_cancellation_are_terminal_paths(self) -> None:
        rejected = self.create_task()
        result = self.gateway.confirm_task(
            rejected.id,
            decision="reject",
            task_hash=rejected.task_hash,
            confirmation_nonce=rejected.confirmation_nonce,
            confirmation_expires_at=rejected.expires_at,
            recipient_agent_id=self.recipient.id,
            expected_state_version=rejected.state_version,
            **self.lease_fields(rejected),
        )
        self.assertEqual(result.state, "REJECTED")

        expired = self.create_task(expires_at=time.time() - 1)
        with self.assertRaises(TaskExpired):
            self.gateway.confirm_task(
                expired.id,
                decision="accept",
                task_hash=expired.task_hash,
                confirmation_nonce=expired.confirmation_nonce,
                confirmation_expires_at=expired.expires_at,
                recipient_agent_id=self.recipient.id,
                expected_state_version=expired.state_version,
                **self.lease_fields(expired),
            )
        self.assertEqual(self.gateway.get_task(expired.id).state, "EXPIRED")

        cancellable = self.create_task()
        accepted = self.gateway.confirm_task(
            cancellable.id,
            decision="accept",
            task_hash=cancellable.task_hash,
            confirmation_nonce=cancellable.confirmation_nonce,
            confirmation_expires_at=cancellable.expires_at,
            recipient_agent_id=self.recipient.id,
            expected_state_version=cancellable.state_version,
            **self.lease_fields(cancellable),
        )
        running = self.gateway.start_task(
            cancellable.id,
            expected_state_version=accepted.state_version,
            **self.lease_fields(cancellable),
        )
        requested = self.gateway.request_cancellation(
            cancellable.id,
            expected_state_version=running.state_version,
            **self.lease_fields(cancellable),
        )
        self.assertEqual(requested.state, "CANCEL_REQUESTED")
        cancelled = self.gateway.cancel_task(
            cancellable.id,
            expected_state_version=requested.state_version,
            **self.lease_fields(cancellable),
        )
        self.assertEqual(cancelled.state, "CANCELLED")


if __name__ == "__main__":
    unittest.main()
