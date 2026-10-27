from __future__ import annotations

import asyncio
import json
import secrets
import time
import uuid
from typing import Any

from aiohttp import ClientSession, WSMsgType
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .credentials import CredentialStore, default_credential_store, load_or_create_private_key
from .errors import WorkerError
from .protocol import PROTOCOL_VERSION, b64url_encode, signable


class Worker:
    """Device-bound Worker that pairs and maintains a signed Gateway session."""

    def __init__(
        self,
        *,
        team_id: str,
        agent_id: str,
        worker_id: str | None = None,
        credential_store: CredentialStore | None = None,
        heartbeat_interval: float = 10.0,
    ) -> None:
        self.team_id = team_id
        self.agent_id = agent_id
        self.worker_id = worker_id or str(uuid.uuid4())
        self.heartbeat_interval = heartbeat_interval
        self.credential_store = credential_store or default_credential_store()
        self.credential_alias = f"worker/{self.worker_id}"
        self._private_key = load_or_create_private_key(self.credential_alias, self.credential_store)
        self._public_key = self._private_key.public_key().public_bytes_raw()
        self.worker_epoch: int | None = None
        self._session_token: str | None = None
        self._session: ClientSession | None = None
        self._socket: Any = None
        self._url: str | None = None
        self._ssl_context: Any = None
        self._sequence = 0

    @property
    def is_connected(self) -> bool:
        return self._socket is not None and not self._socket.closed

    @property
    def public_key(self) -> bytes:
        return self._public_key

    async def connect(self, url: str, pairing_code: str | None = None, *, ssl_context: Any = None) -> dict[str, Any]:
        if self.is_connected:
            await self.close()
        self._url = url
        self._ssl_context = ssl_context
        self._session = ClientSession()
        try:
            self._socket = await self._session.ws_connect(url, ssl=ssl_context, heartbeat=None, autoping=True)
            if pairing_code is not None:
                await self._send_pair(pairing_code)
                paired = await self._receive_expected("paired")
                self.worker_epoch = int(paired["worker_epoch"])
            if self.worker_epoch is None:
                raise WorkerError("Worker has not been paired")
            return await self._send_handshake()
        except WorkerError:
            await self.close()
            raise
        except Exception as error:
            await self.close()
            raise WorkerError(f"Gateway connection failed: {error}") from error

    async def reconnect(self) -> dict[str, Any]:
        if self._url is None:
            raise WorkerError("Worker has no previous Gateway URL")
        return await self.connect(self._url, ssl_context=self._ssl_context)

    async def close(self) -> None:
        socket = self._socket
        session = self._session
        self._socket = None
        self._session = None
        self._session_token = None
        if socket is not None and not socket.closed:
            await socket.close()
        if session is not None and not session.closed:
            await session.close()

    async def heartbeat(self) -> dict[str, Any]:
        if not self.is_connected or self.worker_epoch is None or self._session_token is None:
            raise WorkerError("Worker is not connected")
        self._sequence += 1
        fields = {
            "worker_id": self.worker_id,
            "agent_id": self.agent_id,
            "worker_epoch": self.worker_epoch,
            "session_token": self._session_token,
            "seq": self._sequence,
            "timestamp": time.time(),
            "protocol_version": PROTOCOL_VERSION,
        }
        message = {"type": "heartbeat", **fields, "signature": b64url_encode(self._sign("heartbeat", fields))}
        try:
            await self._socket.send_json(message)
            return await self._receive_expected("heartbeat_ack")
        except WorkerError:
            await self.close()
            raise
        except Exception as error:
            await self.close()
            raise WorkerError(f"Gateway connection failed: {error}") from error

    async def run_forever(
        self,
        url: str,
        *,
        pairing_code: str | None = None,
        ssl_context: Any = None,
        stop_event: asyncio.Event | None = None,
        reconnect_delay: float = 1.0,
    ) -> None:
        next_pairing_code = pairing_code
        while stop_event is None or not stop_event.is_set():
            try:
                await self.connect(url, next_pairing_code, ssl_context=ssl_context)
                next_pairing_code = None
                while self.is_connected and (stop_event is None or not stop_event.is_set()):
                    await asyncio.sleep(self.heartbeat_interval)
                    await self.heartbeat()
            except WorkerError:
                await self.close()
                if stop_event is not None and stop_event.is_set():
                    return
                await asyncio.sleep(reconnect_delay)

    async def _send_pair(self, pairing_code: str) -> None:
        fields = {
            "pairing_code": pairing_code,
            "team_id": self.team_id,
            "agent_id": self.agent_id,
            "worker_id": self.worker_id,
            "public_key": b64url_encode(self._public_key),
            "nonce": secrets.token_urlsafe(24),
            "timestamp": time.time(),
            "protocol_version": PROTOCOL_VERSION,
        }
        await self._socket.send_json({"type": "pair", **fields, "signature": b64url_encode(self._sign("pair", fields))})

    async def _send_handshake(self) -> dict[str, Any]:
        fields = {
            "worker_id": self.worker_id,
            "agent_id": self.agent_id,
            "worker_epoch": self.worker_epoch,
            "nonce": secrets.token_urlsafe(24),
            "timestamp": time.time(),
            "protocol_version": PROTOCOL_VERSION,
        }
        await self._socket.send_json(
            {"type": "handshake", **fields, "signature": b64url_encode(self._sign("handshake", fields))}
        )
        response = await self._receive_expected("handshake_ack")
        self._session_token = response["session_token"]
        return response

    async def _receive_expected(self, expected_type: str) -> dict[str, Any]:
        if self._socket is None:
            raise WorkerError("Worker socket is not open")
        message = await self._socket.receive()
        if message.type == WSMsgType.TEXT:
            try:
                payload = json.loads(message.data)
            except json.JSONDecodeError as error:
                raise WorkerError("Gateway returned invalid JSON") from error
            if not isinstance(payload, dict):
                raise WorkerError("Gateway returned a non-object JSON message")
            if payload.get("type") == "error":
                raise WorkerError(f"{payload.get('code', 'GATEWAY_ERROR')}: {payload.get('message', '')}")
            if payload.get("type") != expected_type:
                raise WorkerError(f"expected {expected_type}, received {payload.get('type')}")
            return payload
        if message.type in (WSMsgType.CLOSE, WSMsgType.CLOSED, WSMsgType.ERROR):
            raise WorkerError("Gateway closed the Worker connection")
        raise WorkerError("Gateway returned an unexpected WebSocket message")

    def _sign(self, message_type: str, fields: dict[str, Any]) -> bytes:
        return self._private_key.sign(signable(message_type, fields))
