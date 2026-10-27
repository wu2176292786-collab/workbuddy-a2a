from __future__ import annotations

import asyncio
import hmac
import json
import secrets
import time
from dataclasses import dataclass
from typing import Any

from aiohttp import WSMsgType, web
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .errors import (
    GatewayError,
    PairingError,
    UnauthorizedWorker,
    ValidationError,
    WorkerNotFound,
    WorkerRevoked,
)
from .models import BootstrapResult, PairingCode, TaskRecord, WorkerRecord
from .protocol import PROTOCOL_VERSION, b64url_decode, b64url_encode, signable, timestamp_is_fresh
from .store import SQLiteStore


@dataclass
class _Session:
    worker_id: str
    token: str
    socket: web.WebSocketResponse
    last_seen: float


class Gateway:
    """Gateway domain facade and WSS transport for the Worker pairing PoC."""

    def __init__(self, store: SQLiteStore, *, heartbeat_timeout: float = 30.0) -> None:
        self.store = store
        self.heartbeat_timeout = heartbeat_timeout
        self._runner: web.AppRunner | None = None
        self._site: web.TCPSite | None = None
        self._scheme = "http"
        self._host = "127.0.0.1"
        self._port = 0
        self._sessions: dict[str, _Session] = {}
        self._monitor_task: asyncio.Task[None] | None = None
        self._app = web.Application(client_max_size=64 * 1024)
        self._app.add_routes(
            [
                web.get("/healthz", self._http_health),
                web.post("/v1/admin/bootstrap", self._http_bootstrap),
                web.post("/v1/admin/pairing-codes", self._http_pairing_code),
                web.post("/v1/admin/workers/{worker_id}/revoke", self._http_revoke),
                web.post("/v1/tasks", self._http_task),
                web.get("/v1/worker/ws", self._worker_socket),
            ]
        )

    @property
    def worker_url(self) -> str:
        return f"{'wss' if self._scheme == 'https' else 'ws'}://{self._host}:{self._port}/v1/worker/ws"

    def bootstrap(self, *, team_name: str, user_name: str, agent_name: str) -> BootstrapResult:
        return self.store.bootstrap(team_name, user_name, agent_name)

    def create_pairing_code(
        self,
        *,
        team_id: str,
        agent_id: str,
        ttl_seconds: int = 600,
        max_attempts: int = 5,
    ) -> PairingCode:
        return self.store.create_pairing_code(team_id, agent_id, ttl_seconds, max_attempts)

    def create_task(
        self,
        *,
        sender_agent_id: str,
        recipient_agent_id: str,
        template_id: str | None = None,
        template_version: str | int | None = None,
        template: Any = None,
        input_data: Any = None,
        input: Any = None,
        scope: Any = None,
        permissions: Any = None,
        expires_at: Any = None,
        team_id: str | None = None,
        lease_ttl_seconds: int = 60,
    ) -> TaskRecord:
        sender = self.store.get_agent(sender_agent_id)
        if sender is None:
            raise ValidationError("sender Agent does not exist")
        if template is not None:
            if not isinstance(template, dict) or "id" not in template or "version" not in template:
                raise ValidationError("template must contain id and version")
            template_id = template["id"]
            template_version = template["version"]
        if input_data is None and input is not None:
            input_data = input
        if scope is None:
            scope = {}
        if permissions is None:
            permissions = []
        if expires_at is None:
            expires_at = time.time() + 24 * 60 * 60
        return self.store.create_authorized_task(
            team_id=team_id or sender.team_id,
            sender_agent_id=sender_agent_id,
            recipient_agent_id=recipient_agent_id,
            template_id=template_id,
            template_version=template_version,
            input_data=input_data,
            scope=scope,
            permissions=permissions,
            expires_at=expires_at,
            lease_ttl_seconds=lease_ttl_seconds,
        )

    def pair_worker(
        self,
        *,
        pairing_code: str,
        team_id: str,
        agent_id: str,
        worker_id: str,
        public_key: str,
        nonce: str,
        timestamp: float,
        protocol_version: int,
        signature: bytes,
    ) -> WorkerRecord:
        if not all(isinstance(value, str) and value for value in (pairing_code, team_id, agent_id, worker_id, public_key, nonce)):
            raise ValidationError("pairing identity fields are required")
        if not isinstance(signature, bytes):
            raise ValidationError("pairing signature must be bytes")
        if protocol_version != PROTOCOL_VERSION:
            raise ValidationError("unsupported protocol version")
        if not isinstance(timestamp, (int, float)) or not timestamp_is_fresh(float(timestamp)):
            raise ValidationError("pairing request is missing a fresh identity or timestamp")
        try:
            public_key_bytes = b64url_decode(public_key)
            if len(public_key_bytes) != 32:
                raise ValueError("Ed25519 public keys are 32 bytes")
            key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
            fields = {
                "pairing_code": pairing_code,
                "team_id": team_id,
                "agent_id": agent_id,
                "worker_id": worker_id,
                "public_key": b64url_encode(public_key_bytes),
                "nonce": nonce,
                "timestamp": timestamp,
                "protocol_version": protocol_version,
            }
            key.verify(signature, signable("pair", fields))
        except (ValueError, InvalidSignature) as error:
            self.store.record_pairing_failure(pairing_code)
            raise PairingError("pairing signature is invalid") from error
        return self.store.pair_worker(
            code=pairing_code,
            team_id=team_id,
            agent_id=agent_id,
            worker_id=worker_id,
            public_key=public_key_bytes,
        )

    def submit_task(self, recipient_agent_id: str, payload: str) -> TaskRecord:
        return self.store.create_legacy_task(recipient_agent_id, payload)

    def get_task(self, task_id: str) -> TaskRecord | None:
        return self.store.get_task(task_id)

    def confirm_task(
        self,
        task_id: str,
        *,
        confirmation_expires_at: Any = None,
        expires_at: Any = None,
        **kwargs: Any,
    ) -> TaskRecord:
        if confirmation_expires_at is None:
            confirmation_expires_at = expires_at
        if confirmation_expires_at is None:
            raise ValidationError("confirmation expiry is required")
        kwargs["confirmation_expires_at"] = confirmation_expires_at
        return self.store.confirm_task(task_id, **kwargs)

    def update_task_authorization(self, task_id: str, **kwargs: Any) -> TaskRecord:
        return self.store.update_task_authorization(task_id, **kwargs)

    def transition_task(self, task_id: str, **kwargs: Any) -> TaskRecord:
        return self.store.transition_task(task_id, **kwargs)

    def start_task(self, task_id: str, *, expected_state_version: int, worker_id: str, worker_epoch: int, fencing_token: str) -> TaskRecord:
        return self.transition_task(
            task_id,
            expected_state_version=expected_state_version,
            new_state="RUNNING",
            worker_id=worker_id,
            worker_epoch=worker_epoch,
            fencing_token=fencing_token,
        )

    def complete_task(self, task_id: str, *, expected_state_version: int, worker_id: str, worker_epoch: int, fencing_token: str, result: Any = None) -> TaskRecord:
        return self.transition_task(
            task_id,
            expected_state_version=expected_state_version,
            new_state="COMPLETED",
            worker_id=worker_id,
            worker_epoch=worker_epoch,
            fencing_token=fencing_token,
            reason="completed",
        )

    def fail_task(self, task_id: str, *, expected_state_version: int, worker_id: str, worker_epoch: int, fencing_token: str, result: Any = None) -> TaskRecord:
        return self.transition_task(
            task_id,
            expected_state_version=expected_state_version,
            new_state="FAILED",
            worker_id=worker_id,
            worker_epoch=worker_epoch,
            fencing_token=fencing_token,
            reason="failed",
        )

    def request_cancellation(self, task_id: str, *, expected_state_version: int, worker_id: str, worker_epoch: int, fencing_token: str) -> TaskRecord:
        return self.transition_task(
            task_id,
            expected_state_version=expected_state_version,
            new_state="CANCEL_REQUESTED",
            worker_id=worker_id,
            worker_epoch=worker_epoch,
            fencing_token=fencing_token,
            reason="cancellation_requested",
        )

    def cancel_task(self, task_id: str, *, expected_state_version: int, worker_id: str, worker_epoch: int, fencing_token: str) -> TaskRecord:
        return self.transition_task(
            task_id,
            expected_state_version=expected_state_version,
            new_state="CANCELLED",
            worker_id=worker_id,
            worker_epoch=worker_epoch,
            fencing_token=fencing_token,
            reason="cancelled_at_safe_stop",
        )

    def expire_task(self, task_id: str, *, expected_state_version: int) -> TaskRecord:
        return self.store.expire_task(task_id, expected_state_version=expected_state_version)

    async def start(self, *, host: str = "127.0.0.1", port: int = 8765, ssl_context: Any = None) -> None:
        if self._runner is not None:
            raise RuntimeError("Gateway is already running")
        self._host = host
        self._scheme = "https" if ssl_context is not None else "http"
        self._runner = web.AppRunner(self._app)
        await self._runner.setup()
        self._site = web.TCPSite(self._runner, host, port, ssl_context=ssl_context)
        await self._site.start()
        sockets = self._site._server.sockets if self._site._server else []
        if not sockets:
            raise RuntimeError("Gateway did not bind a socket")
        self._port = int(sockets[0].getsockname()[1])
        self._monitor_task = asyncio.create_task(self._monitor_heartbeats())

    async def stop(self) -> None:
        if self._monitor_task is not None:
            self._monitor_task.cancel()
            await asyncio.gather(self._monitor_task, return_exceptions=True)
            self._monitor_task = None
        for session in list(self._sessions.values()):
            await session.socket.close(code=1001, message=b"Gateway shutting down")
        self._sessions.clear()
        if self._runner is not None:
            await self._runner.cleanup()
            self._runner = None
            self._site = None

    async def revoke_worker(self, worker_id: str) -> WorkerRecord:
        record = self.store.revoke_worker(worker_id)
        session = self._sessions.pop(worker_id, None)
        if session is not None:
            try:
                await session.socket.send_json(
                    {"type": "error", "code": WorkerRevoked.code, "message": "Worker has been revoked"}
                )
            finally:
                await session.socket.close(code=4003, message=b"Worker revoked")
        return record

    async def _monitor_heartbeats(self) -> None:
        interval = max(0.1, self.heartbeat_timeout / 2)
        while True:
            await asyncio.sleep(interval)
            cutoff = time.time() - self.heartbeat_timeout
            for worker_id, session in list(self._sessions.items()):
                if session.last_seen < cutoff:
                    self._sessions.pop(worker_id, None)
                    try:
                        await session.socket.close(code=4004, message=b"Heartbeat timeout")
                    except (ConnectionError, RuntimeError):
                        pass

    async def _http_health(self, _request: web.Request) -> web.Response:
        return web.json_response({"status": "ok", "online_workers": len(self._sessions)})

    async def _http_bootstrap(self, request: web.Request) -> web.Response:
        try:
            body = await request.json()
            result = self.bootstrap(
                team_name=body["team_name"],
                user_name=body["user_name"],
                agent_name=body["agent_name"],
            )
            return web.json_response(
                {
                    "team": {"id": result.team.id, "name": result.team.name},
                    "user": {"id": result.user.id, "team_id": result.user.team_id, "name": result.user.name},
                    "agent": {"id": result.agent.id, "team_id": result.agent.team_id, "user_id": result.agent.user_id, "name": result.agent.name},
                },
                status=201,
            )
        except (KeyError, GatewayError, ValueError) as error:
            return web.json_response({"error": "INVALID_REQUEST", "message": str(error)}, status=400)

    async def _http_pairing_code(self, request: web.Request) -> web.Response:
        try:
            body = await request.json()
            code = self.create_pairing_code(
                team_id=body["team_id"],
                agent_id=body["agent_id"],
                ttl_seconds=body.get("ttl_seconds", 600),
                max_attempts=body.get("max_attempts", 5),
            )
            return web.json_response(
                {"code": code.code, "team_id": code.team_id, "agent_id": code.agent_id, "expires_at": code.expires_at, "max_attempts": code.max_attempts},
                status=201,
            )
        except (KeyError, GatewayError, ValueError) as error:
            return web.json_response({"error": "INVALID_REQUEST", "message": str(error)}, status=400)

    async def _http_revoke(self, request: web.Request) -> web.Response:
        try:
            record = await self.revoke_worker(request.match_info["worker_id"])
            return web.json_response({"worker_id": record.id, "status": record.status})
        except WorkerNotFound as error:
            return web.json_response({"error": error.code, "message": str(error)}, status=404)

    async def _http_task(self, request: web.Request) -> web.Response:
        try:
            body = await request.json()
            if "sender_agent_id" in body and ("template_id" in body or "template" in body):
                task = self.create_task(
                    team_id=body.get("team_id"),
                    sender_agent_id=body["sender_agent_id"],
                    recipient_agent_id=body["recipient_agent_id"],
                    template_id=body.get("template_id"),
                    template_version=body.get("template_version"),
                    template=body.get("template"),
                    input_data=body.get("input_data", body.get("input")),
                    scope=body.get("scope", {}),
                    permissions=body.get("permissions", []),
                    expires_at=body.get("expires_at"),
                    lease_ttl_seconds=body.get("lease_ttl_seconds", 60),
                )
            else:
                task = self.submit_task(body["recipient_agent_id"], body["payload"])
            return web.json_response({"task_id": task.id, "state": task.state}, status=201)
        except (KeyError, GatewayError, ValueError) as error:
            return web.json_response({"error": getattr(error, "code", "INVALID_REQUEST"), "message": str(error)}, status=409)

    async def _worker_socket(self, request: web.Request) -> web.StreamResponse:
        socket = web.WebSocketResponse(heartbeat=None, max_msg_size=64 * 1024)
        await socket.prepare(request)
        session: _Session | None = None
        try:
            async for message in socket:
                if message.type == WSMsgType.TEXT:
                    try:
                        data = json.loads(message.data)
                        if not isinstance(data, dict):
                            raise ValidationError("message must be a JSON object")
                        if session is None:
                            if data.get("type") == "pair":
                                session = await self._handle_pair(socket, data)
                            elif data.get("type") == "handshake":
                                session = await self._handle_handshake(socket, data)
                            else:
                                raise ValidationError("pair or handshake is required")
                        elif data.get("type") == "heartbeat":
                            await self._handle_heartbeat(session, data)
                        else:
                            raise ValidationError("unexpected message for an authenticated Worker")
                    except (GatewayError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
                        await socket.send_json(
                            {"type": "error", "code": getattr(error, "code", "INVALID_REQUEST"), "message": str(error)}
                        )
                        if isinstance(error, (WorkerRevoked, UnauthorizedWorker, WorkerNotFound, PairingError)):
                            await socket.close(code=4003, message=str(error).encode("utf-8")[:120])
                            break
                elif message.type in (WSMsgType.ERROR, WSMsgType.CLOSE, WSMsgType.CLOSED):
                    break
        finally:
            if session is not None and self._sessions.get(session.worker_id) is session:
                self._sessions.pop(session.worker_id, None)
        return socket

    async def _handle_pair(self, socket: web.WebSocketResponse, data: dict[str, Any]) -> None:
        required = ("pairing_code", "team_id", "agent_id", "worker_id", "public_key", "nonce", "timestamp", "protocol_version", "signature")
        if any(field not in data for field in required):
            raise ValidationError("pair message is missing required fields")
        old = self.store.get_active_worker(data["agent_id"])
        record = self.pair_worker(
            pairing_code=data["pairing_code"],
            team_id=data["team_id"],
            agent_id=data["agent_id"],
            worker_id=data["worker_id"],
            public_key=data["public_key"],
            nonce=data["nonce"],
            timestamp=float(data["timestamp"]),
            protocol_version=int(data["protocol_version"]),
            signature=b64url_decode(data["signature"]),
        )
        if old is not None and old.id != record.id:
            await self._close_session(old.id, "Worker replaced")
        await socket.send_json(
            {"type": "paired", "worker_id": record.id, "agent_id": record.agent_id, "worker_epoch": record.worker_epoch}
        )
        return None

    async def _handle_handshake(self, socket: web.WebSocketResponse, data: dict[str, Any]) -> _Session:
        required = ("worker_id", "agent_id", "worker_epoch", "nonce", "timestamp", "protocol_version", "signature")
        if any(field not in data for field in required):
            raise ValidationError("handshake is missing required fields")
        worker = self.store.get_worker(data["worker_id"])
        if worker is None:
            raise WorkerNotFound(data["worker_id"])
        if worker.status != "ACTIVE":
            raise WorkerRevoked(data["worker_id"])
        if worker.agent_id != data["agent_id"] or worker.worker_epoch != int(data["worker_epoch"]):
            raise UnauthorizedWorker("worker identity or epoch does not match")
        if not timestamp_is_fresh(float(data["timestamp"])):
            raise UnauthorizedWorker("handshake timestamp is stale")
        fields = {
            "worker_id": worker.id,
            "agent_id": worker.agent_id,
            "worker_epoch": worker.worker_epoch,
            "nonce": data["nonce"],
            "timestamp": float(data["timestamp"]),
            "protocol_version": int(data["protocol_version"]),
        }
        if fields["protocol_version"] != PROTOCOL_VERSION:
            raise ValidationError("unsupported protocol version")
        self._verify_signature(worker.public_key, data["signature"], signable("handshake", fields))
        old = self._sessions.pop(worker.id, None)
        if old is not None:
            await old.socket.close(code=4003, message=b"Worker reconnected")
        token = secrets.token_urlsafe(32)
        session = _Session(worker.id, token, socket, time.time())
        self._sessions[worker.id] = session
        self.store.touch_worker(worker.id, worker.worker_epoch)
        await socket.send_json(
            {
                "type": "handshake_ack",
                "worker_id": worker.id,
                "agent_id": worker.agent_id,
                "worker_epoch": worker.worker_epoch,
                "session_token": token,
            }
        )
        return session

    async def _handle_heartbeat(self, session: _Session, data: dict[str, Any]) -> None:
        required = ("worker_id", "agent_id", "worker_epoch", "session_token", "seq", "timestamp", "protocol_version", "signature")
        if any(field not in data for field in required):
            raise ValidationError("heartbeat is missing required fields")
        worker = self.store.get_worker(session.worker_id)
        if worker is None:
            raise WorkerNotFound(session.worker_id)
        if worker.status != "ACTIVE":
            raise WorkerRevoked(session.worker_id)
        if data["worker_id"] != session.worker_id or data["agent_id"] != worker.agent_id or int(data["worker_epoch"]) != worker.worker_epoch:
            raise UnauthorizedWorker("heartbeat identity or epoch does not match")
        if not hmac.compare_digest(str(data["session_token"]), session.token):
            raise UnauthorizedWorker("session token does not match")
        if not timestamp_is_fresh(float(data["timestamp"])):
            raise UnauthorizedWorker("heartbeat timestamp is stale")
        fields = {
            "worker_id": worker.id,
            "agent_id": worker.agent_id,
            "worker_epoch": worker.worker_epoch,
            "session_token": session.token,
            "seq": int(data["seq"]),
            "timestamp": float(data["timestamp"]),
            "protocol_version": int(data["protocol_version"]),
        }
        if fields["protocol_version"] != PROTOCOL_VERSION:
            raise ValidationError("unsupported protocol version")
        self._verify_signature(worker.public_key, data["signature"], signable("heartbeat", fields))
        session.last_seen = time.time()
        self.store.touch_worker(worker.id, worker.worker_epoch, session.last_seen)
        await session.socket.send_json({"type": "heartbeat_ack", "worker_id": worker.id, "seq": fields["seq"], "server_time": session.last_seen})

    @staticmethod
    def _verify_signature(public_key: bytes, encoded_signature: str, payload: bytes) -> None:
        try:
            Ed25519PublicKey.from_public_bytes(public_key).verify(b64url_decode(encoded_signature), payload)
        except (ValueError, InvalidSignature) as error:
            raise UnauthorizedWorker("signature verification failed") from error

    async def _close_session(self, worker_id: str, message: str) -> None:
        session = self._sessions.pop(worker_id, None)
        if session is not None:
            try:
                await session.socket.send_json({"type": "error", "code": "WORKER_REVOKED", "message": message})
            finally:
                await session.socket.close(code=4003, message=message.encode("utf-8")[:120])
