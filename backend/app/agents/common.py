"""Shared agent plumbing: stage context, evidence/decision persistence."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from app.config import Settings
from app.llm.provider import LLMProvider
from app.models import Decision, Evidence, Investigation
from app.tools.base import ToolContext, ToolRegistry, ToolResult
from app.util import deterministic_id, utcnow


@dataclass
class StageContext:
    session: Session
    investigation: Investigation
    settings: Settings
    llm: LLMProvider
    registry: ToolRegistry

    @property
    def investigation_id(self) -> int:
        return self.investigation.id

    def tool_ctx(self) -> ToolContext:
        return ToolContext(session=self.session,
                           investigation_id=self.investigation.id, actor="agent")

    def call_tool(self, name: str, payload: Optional[dict] = None) -> ToolResult:
        return self.registry.execute(name, payload or {}, self.tool_ctx())

    def reason(self, stage: str, conclusion: str, facts: Dict[str, Any]) -> Dict[str, Any]:
        """LLM reasoning summary over facts only. Returns {content, latency_ms}."""
        response = self.llm.generate(
            prompt=f"Summarize the {stage} conclusion for the recovery team.",
            facts={"stage": stage, "scenario": self.investigation.scenario,
                   "conclusion": conclusion, **facts},
        )
        return {"content": response.content, "latency_ms": response.latency_ms,
                "mode": response.mode}


def add_evidence(session: Session, investigation: Investigation, source: str,
                 timestamp, fact: str, reliability: str = "high",
                 raw_reference: str = "") -> Evidence:
    row = Evidence(investigation_id=investigation.id, source=source,
                   timestamp=_as_datetime(timestamp), fact=fact,
                   reliability=reliability, raw_reference=raw_reference,
                   created_at=utcnow())
    session.add(row)
    session.flush()
    return row


def _as_datetime(value):
    """Accept datetime or ISO string (tool payloads serialize timestamps)."""
    if isinstance(value, str):
        return datetime_from_iso(value)
    return value


def datetime_from_iso(value: str):
    from datetime import datetime as _dt
    parsed = _dt.fromisoformat(value)
    if parsed.tzinfo is not None:
        parsed = parsed.replace(tzinfo=None)
    return parsed


def add_decision(session: Session, investigation: Investigation, stage: str,
                 kind: str, decision_text: str, confidence: float,
                 evidence_rows: List[Evidence], alternatives: List[dict],
                 risk_level: str, requires_approval: bool, payload: dict,
                 reasoning: str) -> Decision:
    evidence_ids = [str(row.id) for row in evidence_rows]
    decision = Decision(
        public_id=deterministic_id("decision", investigation.public_id, kind),
        investigation_id=investigation.id, stage=stage, kind=kind,
        decision=decision_text, confidence=confidence, evidence_ids=evidence_ids,
        alternatives=alternatives, risk_level=risk_level,
        requires_approval=requires_approval, payload=payload, reasoning=reasoning,
        created_at=utcnow(),
    )
    session.add(decision)
    session.flush()
    return decision
