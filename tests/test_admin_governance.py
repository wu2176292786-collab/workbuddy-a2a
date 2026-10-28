from __future__ import annotations

import json
import tempfile
import time
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gateway_worker import Gateway, SQLiteStore
from gateway_worker.admin import AdminPrincipal, AdminService
from gateway_worker.errors import AdminAuthorizationError, MFARequiredError, ResourceLimitError
from gateway_worker.isolation import TaskTemplate


class AdminGovernanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = SQLiteStore(str(Path(self.tmp.name) / "gateway.db"))
        self.gateway = Gateway(self.store)
        bootstrap = self.gateway.bootstrap(team_name="Team", user_name="Alice", agent_name="Alice Agent")
        self.team_id = bootstrap.team.id
        self.user = bootstrap.user
        self.agent = bootstrap.agent
        self.admin = AdminService(self.store)
        self.owner = self.admin.authenticate("admin-1", self.team_id, role="owner", mfa_code="test-mfa")
        self.viewer = self.admin.authenticate("viewer-1", self.team_id, role="viewer", mfa_code="test-mfa")

    def tearDown(self) -> None:
        self.store.close()
        self.tmp.cleanup()

    def test_mfa_and_rbac_gate_control_plane_actions(self) -> None:
        with self.assertRaises(MFARequiredError):
            self.admin.authenticate("admin-1", self.team_id, role="owner", mfa_code="wrong")
        with self.assertRaises(AdminAuthorizationError):
            self.admin.create_member(self.viewer, "Bob")
        member = self.admin.create_member(self.owner, "Bob")
        self.assertEqual(member.name, "Bob")

    def test_member_agent_and_worker_lifecycle_is_audited(self) -> None:
        member = self.admin.create_member(self.owner, "Bob")
        agent = self.admin.create_agent(self.owner, member.id, "Bob Agent")
        self.admin.suspend_member(self.owner, member.id)
        with self.assertRaises(AdminAuthorizationError):
            self.admin.create_agent(self.owner, member.id, "Second Agent")
        self.admin.remove_agent(self.owner, agent.id)
        code = self.admin.create_pairing_code(self.owner, self.agent.id)
        key = Ed25519PrivateKey.generate()
        worker = self.store.pair_worker(code=code.code, team_id=self.team_id, agent_id=self.agent.id, worker_id="worker-admin", public_key=key.public_key().public_bytes_raw())
        self.admin.revoke_worker(self.owner, worker.id)
        actions = [event["action"] for event in self.admin.audit_events(self.owner)]
        for action in ("member_created", "agent_created", "member_suspended", "agent_removed", "pairing_approved", "worker_revoked"):
            self.assertIn(action, actions)

    def test_template_management_and_audit_redaction(self) -> None:
        template = TaskTemplate("research_summary", "1", output_fields={"summary", "email"}, sensitive_fields={"email"}, sensitive_field_mode="approval")
        self.admin.publish_template(self.owner, template)
        listed = self.admin.list_templates(self.owner)
        self.assertEqual(listed[0]["status"], "ACTIVE")
        self.admin.suspend_template(self.owner, template.template_id, template.version)
        self.assertEqual(self.admin.list_templates(self.owner)[0]["status"], "SUSPENDED")
        self.admin._audit(self.owner, "synthetic_secret_test", metadata={"password": "pw", "token": "secret", "email": "a@example.test"})
        audit = self.admin.audit_events(self.owner, action="synthetic_secret_test")[0]
        self.assertEqual(audit["metadata"]["password"], "[REDACTED]")
        self.assertEqual(audit["metadata"]["token"], "[REDACTED]")
        self.assertEqual(audit["metadata"]["email"], "[REDACTED]")

    def test_task_export_delete_and_audit_retention(self) -> None:
        user2 = self.store.create_user(self.team_id, "Bob")
        agent2 = self.store.create_agent(self.team_id, user2.id, "Bob Agent")
        for agent_id, worker_id in ((self.agent.id, "worker-a"), (agent2.id, "worker-b")):
            code = self.store.create_pairing_code(self.team_id, agent_id)
            key = Ed25519PrivateKey.generate()
            self.store.pair_worker(code=code.code, team_id=self.team_id, agent_id=agent_id, worker_id=worker_id, public_key=key.public_key().public_bytes_raw())
        task = self.gateway.create_task(sender_agent_id=self.agent.id, recipient_agent_id=agent2.id, template={"id": "research_summary", "version": "1"}, input_data={"email": "sensitive@example.test"}, scope={"resource": "private"}, permissions=["read"])
        exported = self.admin.export_task(self.owner, task.id)
        self.assertEqual(exported["task"]["input_data"]["email"], "[REDACTED]")
        self.admin.delete_task_content(self.owner, task.id)
        row = self.store.connection.execute("SELECT payload, input_json FROM tasks WHERE id = ?", (task.id,)).fetchone()
        self.assertEqual(row["payload"], "[REDACTED]")
        self.assertEqual(json.loads(row["input_json"]), {"redacted": True})
        old_time = time.time() - 31 * 86400
        self.store.connection.execute("UPDATE admin_audit SET created_at = ? WHERE action = 'task_exported'", (old_time,))
        self.store.connection.commit()
        deleted = self.admin.purge_audit(self.owner)
        self.assertGreaterEqual(deleted, 1)

    def test_resource_limits_are_configurable_and_enforced(self) -> None:
        self.admin.configure_limits(self.owner, active_tasks=2, max_rounds=3, max_bytes=100, event_frequency=4, queue_depth=5)
        self.admin.check_limits(self.team_id, active_tasks=2, rounds=3, bytes_used=100, events=4, queue_depth=5)
        with self.assertRaises(ResourceLimitError):
            self.admin.check_limits(self.team_id, queue_depth=6)
        with self.assertRaises(AdminAuthorizationError):
            self.admin.configure_limits(self.viewer, active_tasks=1, max_rounds=1, max_bytes=1, event_frequency=1, queue_depth=1)


if __name__ == "__main__":
    unittest.main()
