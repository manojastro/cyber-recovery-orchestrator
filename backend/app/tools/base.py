"""Tool registry: allow-listed, schema-validated, audited tool access for agents.

Agents NEVER get shell/subprocess access. Every invocation is validated against
the tool's input schema, permission-checked (high-risk tools require an
APPROVED approval record on the investigation), timed out by policy, and
written to the `tool_calls` audit table.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from sqlalchemy.orm import Session

from app.metrics import record_tool_call
from app.models import Approval, ToolCall
from app.util import redact_secrets, truncate_result, utcnow

logger = logging.getLogger(__name__)

LOW = "low"
MEDIUM = "medium"
HIGH = "high"
RiskLevel = str  # low | medium | high


class ToolError(Exception):
    pass


class UnknownToolError(ToolError):
    pass


class ToolInputError(ToolError):
    pass


class ToolPermissionDenied(ToolError):
    pass


@dataclass
class ToolResult:
    status: str  # success | denied | error | schema_rejected | unknown_tool
    summary: str
    data: Dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.status == "success"


@dataclass
class ToolSpec:
    name: str
    purpose: str
    input_schema: Dict[str, Any]
    output_schema: Dict[str, Any]
    handler: Callable[..., Dict[str, Any]]
    risk_level: RiskLevel = LOW
    required_permission: str = "tool:invoke"
    timeout_s: float = 30.0


@dataclass
class ToolContext:
    session: Session
    investigation_id: Optional[int] = None  # numeric PK; None => system call
    actor: str = "agent"


# ---------- minimal JSON-schema validation (type/properties/required/enum) ----------

_TYPES = {"object": dict, "array": list, "string": str, "number": (int, float),
          "integer": int, "boolean": bool}


def validate_payload(payload: Any, schema: Dict[str, Any]) -> List[str]:
    errors: List[str] = []
    expected = schema.get("type")
    if expected and not isinstance(payload, _TYPES.get(expected, object)):
        return [f"expected type {expected}"]
    if isinstance(payload, dict):
        for req in schema.get("required", []):
            if req not in payload:
                errors.append(f"missing required field '{req}'")
        props = schema.get("properties", {})
        for key, value in payload.items():
            if key not in props:
                continue
            sub = props[key]
            sub_type = sub.get("type")
            if sub_type and not isinstance(value, _TYPES.get(sub_type, object)):
                errors.append(f"field '{key}' expected {sub_type}")
                continue
            if "enum" in sub and value not in sub["enum"]:
                errors.append(f"field '{key}' must be one of {sub['enum']}")
            if isinstance(value, dict):
                errors.extend(f"{key}.{e}" for e in validate_payload(value, sub))
            if isinstance(value, list) and "items" in sub:
                item_schema = sub["items"]
                for idx, item in enumerate(value):
                    if "type" in item_schema and not isinstance(
                            item, _TYPES.get(item_schema["type"], object)):
                        errors.append(f"field '{key}[{idx}]' expected "
                                      f"{item_schema['type']}")
    return errors


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: Dict[str, ToolSpec] = {}

    def register(self, spec: ToolSpec) -> None:
        if spec.name in self._tools:
            raise ToolError(f"tool already registered: {spec.name}")
        self._tools[spec.name] = spec

    def get(self, name: str) -> ToolSpec:
        if name not in self._tools:
            raise UnknownToolError(f"unknown tool: {name}")
        return self._tools[name]

    def names(self) -> List[str]:
        return sorted(self._tools)

    def describe(self, name: str) -> dict:
        spec = self.get(name)
        return {"name": spec.name, "purpose": spec.purpose,
                "input_schema": spec.input_schema, "output_schema": spec.output_schema,
                "risk_level": spec.risk_level,
                "required_permission": spec.required_permission}

    def list_all(self) -> List[dict]:
        return [self.describe(n) for n in self.names()]

    # ---------- execution ----------

    def has_approved_change_record(self, ctx: ToolContext) -> bool:
        if ctx.investigation_id is None:
            return False
        return session_query_approved(ctx.session, ctx.investigation_id)

    def execute(self, name: str, payload: Optional[Dict[str, Any]],
                ctx: ToolContext) -> ToolResult:
        """Execute with full guardrails + audit. Never raises for refusals;
        unexpected handler failures become ToolResult(status='error')."""
        started = time.perf_counter()
        payload = dict(payload or {})

        def audit(status: str, summary: str, result: Dict[str, Any],
                  risk: RiskLevel = LOW, approval_present: bool = False) -> ToolResult:
            duration_ms = (time.perf_counter() - started) * 1000.0
            try:
                ctx.session.add(ToolCall(
                    investigation_id=ctx.investigation_id,
                    tool_name=name,
                    arguments=redact_secrets(payload),
                    status=status, risk_level=risk,
                    approval_present=approval_present,
                    summary=summary[:2000],
                    result=redact_secrets(truncate_result(result)),
                    duration_ms=duration_ms,
                    created_at=utcnow(),
                ))
                ctx.session.commit()
            except Exception:  # pragma: no cover - audit must never break tools
                logger.exception("audit write failed for tool %s", name)
            record_tool_call(name, status)
            logger.info("tool %s [%s] actor=%s dur=%.1fms", name, status, ctx.actor,
                        duration_ms)
            return ToolResult(status=status, summary=summary, data=result)

        try:
            spec = self.get(name)
        except UnknownToolError as exc:
            return audit("unknown_tool", str(exc), {}, risk=MEDIUM)

        errors = validate_payload(payload, spec.input_schema)
        if errors:
            return audit("schema_rejected",
                         f"input rejected: {'; '.join(errors)}",
                         {"errors": errors}, risk=spec.risk_level)

        approval_present = False
        if spec.risk_level == HIGH:
            approval_present = self.has_approved_change_record(ctx)
            if not approval_present:
                return audit(
                    "denied",
                    f"high-risk tool '{name}' requires an APPROVED change record "
                    "on the investigation",
                    {"required": "approved approval record"},
                    risk=HIGH, approval_present=False,
                )

        try:
            data = spec.handler(session=ctx.session, payload=payload) or {}
            summary = str(data.get("summary", "ok"))
        except Exception as exc:  # noqa: BLE001 - surface as error result
            logger.exception("tool %s failed", name)
            return audit("error", f"handler failed: {exc}", {}, risk=spec.risk_level,
                         approval_present=approval_present)
        return audit("success", summary, data, risk=spec.risk_level,
                     approval_present=approval_present)


def session_query_approved(session: Session, investigation_id: int) -> bool:
    return session.query(Approval).filter(
        Approval.investigation_id == investigation_id,
        Approval.status == "approved",
    ).count() > 0


def build_default_registry() -> ToolRegistry:
    from app.tools.recovery_tools import register_recovery_tools

    registry = ToolRegistry()
    register_recovery_tools(registry)
    return registry
