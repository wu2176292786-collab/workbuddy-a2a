from __future__ import annotations

import base64
import json
import time
from collections.abc import Mapping
from typing import Any

PROTOCOL_VERSION = 1
MAX_CLOCK_SKEW_SECONDS = 60


def canonical_json(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def b64url_decode(value: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise ValueError("expected a non-empty base64url value")
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def timestamp_is_fresh(timestamp: float, now: float | None = None) -> bool:
    now = time.time() if now is None else now
    return abs(now - timestamp) <= MAX_CLOCK_SKEW_SECONDS


def signable(message_type: str, fields: Mapping[str, Any]) -> bytes:
    return canonical_json({"message_type": message_type, **dict(fields)})
