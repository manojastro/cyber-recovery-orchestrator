"""Pydantic v2 API schemas (inputs validated everywhere; outputs for the SPA)."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

ScenarioName = Literal["standard", "corrupted_latest"]


# ---------- Required canonical shapes ----------


class Evidence(BaseModel):
    """Evidence{source,timestamp,fact,reliability,raw_reference}."""

    source: str
    timestamp: datetime
    fact: str
    reliability: Literal["high", "medium", "low"] = "high"
    raw_reference: str = ""


class Decision(BaseModel):
    """Decision{decision,confidence,evidence_ids,alternatives,risk_level,requires_approval}."""

    decision: str
    confidence: float = Field(ge=0.0, le=1.0)
    evidence_ids: List[str] = []
    alternatives: List[Dict[str, Any]] = []
    risk_level: Literal["low", "medium", "high"] = "medium"
    requires_approval: bool = False


# ---------- Requests ----------


class SeedRequest(BaseModel):
    scenario: ScenarioName = "standard"


class TriggerIncidentRequest(BaseModel):
    scenario: ScenarioName = "standard"
    note: Optional[str] = None


class ApprovalRequest(BaseModel):
    decided_by: str = Field(min_length=2, max_length=80)
    note: Optional[str] = None


class EvaluationRunRequest(BaseModel):
    scenario: ScenarioName = "standard"


class FaultInjectionRequest(BaseModel):
    kind: Literal["post_validation_failure"]
    investigation_id: str = Field(min_length=4)


# ---------- Responses ----------


class MetaResponse(BaseModel):
    app: str
    version: str
    llm_mode: str
    mock: bool
    database: str
    cors_origins: List[str]
    time: datetime


class AssetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    public_id: str
    name: str
    asset_type: str
    tier: int
    state: str
    health: int
    version: str
    data_integrity_flag: bool
    criticality: str


class DependencyOut(BaseModel):
    from_asset: str
    to_asset: str
    dep_type: str


class SnapshotOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    public_id: str
    label: str
    taken_at: datetime
    integrity_status: str
    malicious_indicator_count: int
    completeness: float
    checksum: str


class EventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    public_id: str
    ts: datetime
    event_type: str
    source: str
    severity: str
    message: str
    payload: dict


class IncidentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    public_id: str
    scenario: str
    title: str
    severity: str
    status: str
    started_at: datetime
    detected_at: datetime
    detected_by: str
    summary: str


class StageRunOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    stage: str
    seq: int
    from_state: str
    to_state: str
    status: str
    duration_ms: float
    llm_mode: str
    llm_latency_ms: float
    error: Optional[str] = None


class EvidenceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    source: str
    timestamp: datetime
    fact: str
    reliability: str
    raw_reference: str


class HypothesisOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    statement: str
    confidence: float
    status: str
    rationale: str


class DecisionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    public_id: str
    stage: str
    kind: str
    decision: str
    confidence: float
    evidence_ids: list
    alternatives: list
    risk_level: str
    requires_approval: bool
    payload: dict
    reasoning: str
    created_at: datetime


class RiskAssessmentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    score: int
    band: str
    rationale: str
    factors: dict


class ApprovalOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    public_id: str
    status: str
    requested_by: str
    decided_by: Optional[str]
    note: Optional[str]
    requested_at: datetime
    decided_at: Optional[datetime]


class ActionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    public_id: str
    seq: int
    action_type: str
    tool_name: str
    target_asset: str
    tier: int
    source_snapshot_label: Optional[str]
    estimated_rto_seconds: float
    validation_test: str
    risk_level: str
    rollback_option: str
    status: str
    detail: dict


class ValidationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    phase: str
    name: str
    target: Optional[str]
    passed: bool
    detail: dict
    created_at: datetime


class OutcomeOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    result: str
    measured_rto_seconds: Optional[float]
    planned_rto_seconds: Optional[float]
    measured_rpo_seconds: Optional[float]
    clean_point_label: Optional[str]
    dependency_order_correct: bool
    details: dict
    created_at: datetime


class InvestigationBundle(BaseModel):
    investigation_id: str
    incident: IncidentOut
    current_state: str
    failure_reason: Optional[str]
    scenario: str
    created_at: datetime
    updated_at: datetime
    stages: List[StageRunOut]
    evidence: List[EvidenceOut]
    hypotheses: List[HypothesisOut]
    decisions: List[DecisionOut]
    risk_assessment: Optional[RiskAssessmentOut]
    approvals: List[ApprovalOut]
    actions: List[ActionOut]
    validations: List[ValidationOut]
    outcomes: List[OutcomeOut]
    timeline: List[EventOut]
    affected_assets: List[AssetOut]


class ToolCallOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    tool_name: str
    arguments: dict
    status: str
    risk_level: str
    approval_present: bool
    summary: str
    duration_ms: float
    created_at: datetime


class MetricsSummary(BaseModel):
    investigations_total: int
    recoveries_completed: int
    recoveries_failed: int
    recoveries_rolled_back: int
    rejections: int
    avg_stage_duration_ms: float
    tool_calls_total: int
    tool_errors_total: int
    llm_mode: str
    last_outcome: Optional[dict] = None
    clean_point_accuracy_last_evaluation: Optional[float] = None


class EvaluationResult(BaseModel):
    evaluation_id: str
    scenario: str
    passed: bool
    detection_correct: bool
    clean_point_correct: bool
    ordering_correct: bool
    rpo_within_bound: bool
    achieved_rpo_seconds: Optional[float]
    achieved_rto_seconds: Optional[float]
    results: dict
