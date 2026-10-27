import unittest
import time
import datetime as dt
import json
import ipaddress
import ssl
import subprocess
import sys
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID

from gateway_worker.credentials import InMemoryCredentialStore
from gateway_worker.errors import NoActiveWorker, PairingError, WorkerError
from gateway_worker.gateway import Gateway
from gateway_worker.protocol import b64url_encode, signable
from gateway_worker.store import SQLiteStore
from gateway_worker.worker import Worker


class BootstrapTests(unittest.TestCase):
    def test_bootstrap_creates_team_user_agent_and_allowlist_membership(self) -> None:
        store = SQLiteStore(":memory:")
        self.addCleanup(store.close)
        gateway = Gateway(store)

        result = gateway.bootstrap(
            team_name="Example Team",
            user_name="Alice",
            agent_name="Alice's Agent",
        )

        self.assertEqual(result.team.name, "Example Team")
        self.assertEqual(result.user.team_id, result.team.id)
        self.assertEqual(result.agent.user_id, result.user.id)
        self.assertEqual(result.agent.team_id, result.team.id)
        self.assertTrue(store.agent_is_allowed(result.agent.id, result.team.id))

    def test_pairing_code_is_high_entropy_and_bound_to_agent(self) -> None:
        store = SQLiteStore(":memory:")
        self.addCleanup(store.close)
        gateway = Gateway(store)
        bootstrap = gateway.bootstrap(
            team_name="Example Team",
            user_name="Alice",
            agent_name="Alice's Agent",
        )

        pairing = gateway.create_pairing_code(
            team_id=bootstrap.team.id,
            agent_id=bootstrap.agent.id,
        )

        self.assertGreaterEqual(len(pairing.code), 43)
        self.assertEqual(pairing.team_id, bootstrap.team.id)
        self.assertEqual(pairing.agent_id, bootstrap.agent.id)
        self.assertGreater(pairing.expires_at, 0)
        self.assertEqual(pairing.max_attempts, 5)

        with self.assertRaisesRegex(Exception, "agent is not a member"):
            gateway.create_pairing_code(team_id="wrong-team", agent_id=bootstrap.agent.id)

    def test_pairing_registers_only_public_key_and_consumes_code_once(self) -> None:
        store = SQLiteStore(":memory:")
        self.addCleanup(store.close)
        gateway = Gateway(store)
        bootstrap = gateway.bootstrap(
            team_name="Example Team",
            user_name="Alice",
            agent_name="Alice's Agent",
        )
        pairing = gateway.create_pairing_code(
            team_id=bootstrap.team.id,
            agent_id=bootstrap.agent.id,
        )
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key().public_bytes_raw()
        fields = {
            "pairing_code": pairing.code,
            "team_id": bootstrap.team.id,
            "agent_id": bootstrap.agent.id,
            "worker_id": "worker-1",
            "public_key": b64url_encode(public_key),
            "nonce": "nonce-1",
            "timestamp": time.time(),
            "protocol_version": 1,
        }

        record = gateway.pair_worker(
            **fields,
            signature=private_key.sign(signable("pair", fields)),
        )

        self.assertEqual(record.worker_epoch, 1)
        self.assertEqual(record.public_key, public_key)
        self.assertNotIn("private_key", store.workers_table_columns())
        with self.assertRaises(PairingError):
            gateway.pair_worker(
                **fields,
                signature=private_key.sign(signable("pair", fields)),
            )

    def test_pairing_attempt_limit_rejects_repeated_invalid_signatures(self) -> None:
        store = SQLiteStore(":memory:")
        self.addCleanup(store.close)
        gateway = Gateway(store)
        bootstrap = gateway.bootstrap(team_name="Team", user_name="Alice", agent_name="Agent")
        pairing = gateway.create_pairing_code(
            team_id=bootstrap.team.id,
            agent_id=bootstrap.agent.id,
            max_attempts=2,
        )
        wrong_key = Ed25519PrivateKey.generate()
        public_key = wrong_key.public_key().public_bytes_raw()
        fields = {
            "pairing_code": pairing.code,
            "team_id": bootstrap.team.id,
            "agent_id": bootstrap.agent.id,
            "worker_id": "attacker",
            "public_key": b64url_encode(public_key),
            "nonce": "nonce",
            "timestamp": time.time(),
            "protocol_version": 1,
        }
        for _ in range(2):
            with self.assertRaises(PairingError):
                gateway.pair_worker(**fields, signature=b"0" * 64)
        with self.assertRaises(PairingError):
            gateway.pair_worker(**fields, signature=wrong_key.sign(signable("pair", fields)))

    def test_worker_private_key_is_kept_in_credential_store(self) -> None:
        credentials = InMemoryCredentialStore()
        first = Worker(team_id="team", agent_id="agent", worker_id="worker", credential_store=credentials)
        stored = credentials.get(first.credential_alias)
        self.assertIsNotNone(stored)
        self.assertNotIn("private_key", first.__dict__)
        second = Worker(team_id="team", agent_id="agent", worker_id="worker", credential_store=credentials)
        self.assertEqual(first.public_key, second.public_key)


def make_tls_context(directory: Path) -> tuple[ssl.SSLContext, ssl.SSLContext]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=1))
        .not_valid_after(dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_path = directory / "cert.pem"
    key_path = directory / "key.pem"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption())
    )
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(cert_path, key_path)
    client = ssl._create_unverified_context()
    return server, client


class WSSPairingTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.store = SQLiteStore(":memory:")
        self.gateway = Gateway(self.store)
        self.bootstrap = self.gateway.bootstrap(
            team_name="Example Team",
            user_name="Alice",
            agent_name="Alice's Agent",
        )
        self.pairing = self.gateway.create_pairing_code(
            team_id=self.bootstrap.team.id,
            agent_id=self.bootstrap.agent.id,
        )
        self.tempdir = tempfile.TemporaryDirectory()
        self.server_ssl, self.client_ssl = make_tls_context(Path(self.tempdir.name))
        await self.gateway.start(host="127.0.0.1", port=0, ssl_context=self.server_ssl)

    async def asyncTearDown(self) -> None:
        await self.gateway.stop()
        self.store.close()
        self.tempdir.cleanup()

    async def test_worker_completes_signed_wss_handshake_heartbeat_and_reconnect(self) -> None:
        worker = Worker(
            team_id=self.bootstrap.team.id,
            agent_id=self.bootstrap.agent.id,
            worker_id="worker-1",
            credential_store=InMemoryCredentialStore(),
        )

        first = await worker.connect(self.gateway.worker_url, self.pairing.code, ssl_context=self.client_ssl)
        self.assertEqual(first["type"], "handshake_ack")
        self.assertEqual(worker.worker_epoch, 1)
        heartbeat = await worker.heartbeat()
        self.assertEqual(heartbeat["type"], "heartbeat_ack")

        await worker.close()
        second = await worker.connect(self.gateway.worker_url, ssl_context=self.client_ssl)
        self.assertEqual(second["type"], "handshake_ack")
        self.assertEqual(second["worker_epoch"], 1)
        await worker.close()

    async def test_revocation_blocks_new_tasks_and_reconnect(self) -> None:
        worker = Worker(
            team_id=self.bootstrap.team.id,
            agent_id=self.bootstrap.agent.id,
            worker_id="worker-1",
            credential_store=InMemoryCredentialStore(),
        )
        await worker.connect(self.gateway.worker_url, self.pairing.code, ssl_context=self.client_ssl)
        task = self.gateway.submit_task(self.bootstrap.agent.id, "read-only task")
        self.assertEqual(task.state, "QUEUED")

        await self.gateway.revoke_worker(worker.worker_id)
        with self.assertRaises(WorkerError):
            await worker.heartbeat()
        with self.assertRaises(NoActiveWorker):
            self.gateway.submit_task(self.bootstrap.agent.id, "should be rejected")

        await worker.close()
        with self.assertRaises(WorkerError):
            await worker.connect(self.gateway.worker_url, ssl_context=self.client_ssl)

    async def test_new_pairing_revokes_old_worker_and_increments_epoch(self) -> None:
        first_worker = Worker(
            team_id=self.bootstrap.team.id,
            agent_id=self.bootstrap.agent.id,
            worker_id="worker-1",
            credential_store=InMemoryCredentialStore(),
        )
        await first_worker.connect(self.gateway.worker_url, self.pairing.code, ssl_context=self.client_ssl)

        replacement_code = self.gateway.create_pairing_code(
            team_id=self.bootstrap.team.id,
            agent_id=self.bootstrap.agent.id,
        )
        second_worker = Worker(
            team_id=self.bootstrap.team.id,
            agent_id=self.bootstrap.agent.id,
            worker_id="worker-2",
            credential_store=InMemoryCredentialStore(),
        )
        second = await second_worker.connect(
            self.gateway.worker_url,
            replacement_code.code,
            ssl_context=self.client_ssl,
        )

        self.assertEqual(second["worker_epoch"], 2)
        self.assertEqual(self.store.get_worker("worker-1").status, "REVOKED")
        with self.assertRaises(WorkerError):
            await first_worker.heartbeat()
        await first_worker.close()
        await second_worker.close()


class CLITests(unittest.TestCase):
    def test_bootstrap_and_pairing_code_cli(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory) / "gateway.sqlite")
            bootstrap = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "gateway_worker.cli",
                    "bootstrap",
                    "--db",
                    database,
                    "--team-name",
                    "Team",
                    "--user-name",
                    "Alice",
                    "--agent-name",
                    "Agent",
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            result = json.loads(bootstrap.stdout)
            self.assertEqual(result["team"]["name"], "Team")
            pairing = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "gateway_worker.cli",
                    "pairing-code",
                    "--db",
                    database,
                    "--team-id",
                    result["team"]["id"],
                    "--agent-id",
                    result["agent"]["id"],
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertGreaterEqual(len(json.loads(pairing.stdout)["code"]), 43)


if __name__ == "__main__":
    unittest.main()
