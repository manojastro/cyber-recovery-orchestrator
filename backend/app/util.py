"""Shared utilities: time, ids, canonical json, secret redaction."""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Iterable

DETERMINISTIC_NS = uuid.uuid5(uuid.NAMESPACE_URL, "urn:cyber-recovery-orchestrator")

SECRET_KEY_PATTERN = re.compile(
    r"(secret|password|passwd|token|api[_-]?key|authorization|credential_value)",
    re.IGNORECASE,
)


def utcnow() -> datetime:
    """Naive UTC timestamp (consistent across DB round-trips on SQLite)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def deterministic_id(*parts: str) -> str:
    """Stable UUIDv5-derived id so identical runs yield identical public ids."""
    return str(uuid.uuid5(DETERMINISTIC_NS, "|".join(parts)))


def new_id(prefix: str = "") -> str:
    raw = uuid.uuid4().hex
    return f"{prefix}{raw}" if prefix else raw


def canonical_json(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def sha256_of(payload: Any) -> str:
    if isinstance(payload, (bytes, bytearray)):
        return hashlib.sha256(bytes(payload)).hexdigest()
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def redact_secrets(value: Any) -> Any:
    """Recursively redact values whose keys look secret-bearing. Never log secrets."""
    if isinstance(value, dict):
        out = {}
        for key, val in value.items():
            if isinstance(key, str) and SECRET_KEY_PATTERN.search(key):
                out[key] = "***REDACTED***"
            else:
                out[key] = redact_secrets(val)
        return out
    if isinstance(value, list):
        return [redact_secrets(v) for v in value]
    return value


def truncate_result(value: Any, limit: int = 2000) -> Any:
    text = value if isinstance(value, str) else canonical_json(value)
    if len(text) <= limit:
        return text if isinstance(value, str) else value
    return {"truncated": True, "preview": text[:limit]}


def chunked(items: Iterable[Any], size: int) -> Iterable[list]:
    batch: list = []
    for item in items:
        batch.append(item)
        if len(batch) >= size:
            yield batch
            batch = []
    if batch:
        yield batch
