from __future__ import annotations

import datetime as dt
import hashlib
import json
import math
from collections.abc import Mapping
from typing import Any


def normalize_json(value: Any) -> Any:
    """Return JSON-compatible data with deterministic object and number rules."""
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("JSON numbers must be finite")
        return value
    if isinstance(value, Mapping):
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("JSON object keys must be strings")
            normalized[key] = normalize_json(item)
        return normalized
    if isinstance(value, (list, tuple)):
        return [normalize_json(item) for item in value]
    raise ValueError(f"value of type {type(value).__name__} is not JSON-compatible")


def normalize_expiry(value: Any) -> float:
    if isinstance(value, dt.datetime):
        if value.tzinfo is None:
            raise ValueError("expiry datetime must include a timezone")
        return value.astimezone(dt.timezone.utc).timestamp()
    if isinstance(value, str):
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        return normalize_expiry(parsed)
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if not math.isfinite(float(value)):
            raise ValueError("expiry must be finite")
        return float(value)
    raise ValueError("expiry must be a Unix timestamp or timezone-aware ISO datetime")


def canonical_task_fields(
    *,
    sender_agent_id: str,
    recipient_agent_id: str,
    template_id: str,
    template_version: str,
    input_data: Any,
    scope: Any,
    permissions: Any,
    expires_at: Any,
) -> dict[str, Any]:
    return {
        "sender": sender_agent_id,
        "recipient": recipient_agent_id,
        "template": {"id": template_id, "version": str(template_version)},
        "input": normalize_json(input_data),
        "scope": normalize_json(scope),
        "permissions": normalize_json(permissions),
        "expires_at": normalize_expiry(expires_at),
    }


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        normalize_json(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def compute_task_hash(**fields: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(canonical_task_fields(**fields))).hexdigest()


def hash_capability(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()
