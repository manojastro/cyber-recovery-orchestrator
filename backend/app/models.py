"""Persistence model: lab state, backup catalog, incident case file, workflow, audit."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base


class Asset(Base):
    """A lab asset: service, database, storage bucket, identity provider, config store."""

    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    public_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    asset_type: Mapped[str] = mapped_column(String(40))  # service|database|storage|identity|config|network
    tier: Mapped[int] = mapped_column(Integer)  # 0 infra, 1 core business, 2 supporting
    state: Mapped[str] = mapped_column(String(20), default="running")  # running|degraded|down
    health: Mapped[int] = mapped_column(Integer, default=100)
    version: Mapped[str] = mapped_column(String(40), default="1.0.0")
    data_integrity_flag: Mapped[bool] = mapped_column(Boolean, default=True)  # False => suspect data
    criticality: Mapped[str] = mapped_column(String(20), default="high")
    owner: Mapped[str] = mapped_column(String(80), default="platform-team")
    extra: Mapped[dict] = mapped_column(JSON, default=dict)


class Dependency(Base):
    """Typed dependency edge between two assets (from depends on to)."""

    __tablename__ = "dependencies"
    __table_args__ = (UniqueConstraint("from_asset", "to_asset", "dep_type", name="uq_dep"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    from_asset: Mapped[str] = mapped_column(String(120), index=True)
    to_asset: Mapped[str] = mapped_column(String(120), index=True)
    dep_type: Mapped[str] = mapped_column(String(60))
    # SERVICE_DEPENDS_ON_DATABASE | SERVICE_REQUIRES_IDENTITY | SERVICE_REQUIRES_STORAGE
    # SERVICE_CALLS_SERVICE | SERVICE_REQUIRES_CONFIG


class DbRecord(Base):
    """Simulated database row. `payload` is the pristine value; flags carry damage."""

    __tablename__ = "db_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    table_name: Mapped[str] = mapped_column(String(60), index=True)
    record_key: Mapped[str] = mapped_column(String(80), default="")
    payload: Mapped[str] = mapped_column(Text, default="")
    encrypted: Mapped[bool] = mapped_column(Boolean, default=False)
    corrupted: Mapped[bool] = mapped_column(Boolean, default=False)
    deleted: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime)
    mutated_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    def live_payload(self) -> str:
        if self.deleted:
            return "<deleted>"
        if self.encrypted:
            return f"ENC[{self.payload}]"
        if self.corrupted:
            return f"<corrupted>{self.payload}"
        return self.payload


class StorageObject(Base):
    """Versioned object in a MinIO-style bucket (modeled rows)."""

    __tablename__ = "storage_objects"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    bucket: Mapped[str] = mapped_column(String(60), index=True)
    obj_key: Mapped[str] = mapped_column(String(160), index=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    size_bytes: Mapped[int] = mapped_column(Integer, default=1024)
    content_digest: Mapped[str] = mapped_column(String(80), default="")
    encrypted: Mapped[bool] = mapped_column(Boolean, default=False)
    deleted: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime)
    mutated_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)


class ConfigEntry(Base):
    __tablename__ = "config_entries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    key: Mapped[str] = mapped_column(String(120), unique=True)
    baseline_value: Mapped[str] = mapped_column(Text, default="")
    value: Mapped[str] = mapped_column(Text, default="")
    integrity_ok: Mapped[bool] = mapped_column(Boolean, default=True)
    mutated_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)


class Credential(Base):
    __tablename__ = "credentials"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    principal: Mapped[str] = mapped_column(String(120), unique=True)
    kind: Mapped[str] = mapped_column(String(30), default="service")  # user|service|admin
    status: Mapped[str] = mapped_column(String(30), default="active")  # active|compromised
    generation: Mapped[int] = mapped_column(Integer, default=1)
    secret_hint: Mapped[str] = mapped_column(String(80), default="***")  # never logged verbatim
    compromised_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    rotated_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)


class BackupSnapshot(Base):
    """Consolidated recovery point covering db + storage + config.

    Hidden attributes live inside the manifest (e.g. samples carrying malicious
    markers); the checksum is computed over the canonical manifest so post-hoc
    tampering is detectable.
    """

    __tablename__ = "backup_snapshots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    public_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    label: Mapped[str] = mapped_column(String(60), unique=True)
    snapshot_type: Mapped[str] = mapped_column(String(40), default="consolidated")
    taken_at: Mapped[datetime] = mapped_column(DateTime, index=True)
    checksum_algorithm: Mapped[str] = mapped_column(String(20), default="sha256")
    checksum: Mapped[str] = mapped_column(String(80))
    manifest: Mapped[dict] = mapped_column(JSON)
    integrity_status: Mapped[str] = mapped_column(String(30), default="unverified")  # unverified|verified|failed
    integrity_detail: Mapped[dict] = mapped_column(JSON, default=dict)
    malicious_indicator_count: Mapped[int] = mapped_column(Integer, default=0)
    completeness: Mapped[float] = mapped_column(Float, default=1.0)
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    created_by: Mapped[str] = mapped_column(String(60), default="lab-generator")


class Event(Base):
    """Timeline entry: lab activity, incident injection, detection, agent findings."""

    __tablename__ = "events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    public_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    ts: Mapped[datetime] = mapped_column(DateTime, index=True)
    event_type: Mapped[str] = mapped_column(String(60), index=True)
    source: Mapped[str] = mapped_column(String(60), default="simulator")
    severity: Mapped[str] = mapped_column(String(20), default="info")  # info|warning|critical
    message: Mapped[str] = mapped_column(Text, default="")
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    incident_public_id: Mapped[Optional[str]] = mapped_column(String(64), index=True, nullable=True)


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    public_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    scenario: Mapped[str] = mapped_column(String(60))
    title: Mapped[str] = mapped_column(String(200), default="")
    severity: Mapped[str] = mapped_column(String(20), default="critical")
    status: Mapped[str] = mapped_column(String(30), default="open")  # open|contained|closed
    started_at: Mapped[datetime] = mapped_column(DateTime)  # compromise start (T0 window begin)
    detected_at: Mapped[datetime] = mapped_column(DateTime)
    detected_by: Mapped[str] = mapped_column(String(80), default="deterministic-rule-engine")
    summary: Mapped[str] = mapped_column(Text, default="")
    detection_stats: Mapped[dict] = mapped_column(JSON, default=dict)
    closed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)


class Investigation(Base):
    """One orchestrated cyber-recovery run; carries the workflow state machine."""

    __tablename__ = "investigations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    public_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    incident_public_id: Mapped[str] = mapped_column(String(64), index=True)
    scenario: Mapped[str] = mapped_column(String(60))
    current_state: Mapped[str] = mapped_column(String(30), default="DETECTED", index=True)
    failure_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    context: Mapped[dict] = mapped_column(JSON, default=dict)
    pre_state_json: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)  # rollback image
    created_at: Mapped[datetime] = mapped_column(DateTime)
    updated_at: Mapped[datetime] = mapped_column(DateTime)
    closed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)


class StageRun(Base):
    __tablename__ = "stage_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    investigation_id: Mapped[int] = mapped_column(ForeignKey("investigations.id"), index=True)
    seq: Mapped[int] = mapped_column(Integer)
    stage: Mapped[str] = mapped_column(String(60))
    from_state: Mapped[str] = mapped_column(String(30))
    to_state: Mapped[str] = mapped_column(String(30))
    status: Mapped[str] = mapped_column(String(20), default="completed")  # completed|failed
    started_at: Mapped[datetime] = mapped_column(DateTime)
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    duration_ms: Mapped[float] = mapped_column(Float, default=0.0)
    output: Mapped[dict] = mapped_column(JSON, default=dict)
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    llm_mode: Mapped[str] = mapped_column(String(30), default="mock")
    llm_latency_ms: Mapped[float] = mapped_column(Float, default=0.0)


class Evidence(Base):
    __tablename__ = "evidence"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    investigation_id: Mapped[int] = mapped_column(ForeignKey("investigations.id"), index=True)
    source: Mapped[str] = mapped_column(String(60))
    timestamp: Mapped[datetime] = mapped_column(DateTime)
    fact: Mapped[str] = mapped_column(Text)
    reliability: Mapped[str] = mapped_column(String(20), default="high")  # high|medium|low
    raw_reference: Mapped[str] = mapped_column(String(120), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime)


class Hypothesis(Base):
    __tablename__ = "hypotheses"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    investigation_id: Mapped[int] = mapped_column(ForeignKey("investigations.id"), index=True)
    statement: Mapped[str] = mapped_column(Text)
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    status: Mapped[str] = mapped_column(String(20), default="proposed")  # proposed|confirmed|rejected
    rationale: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime)


class Decision(Base):
    """Structured agent decision with evidence lineage and alternatives."""

    __tablename__ = "decisions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    public_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    investigation_id: Mapped[int] = mapped_column(ForeignKey("investigations.id"), index=True)
    stage: Mapped[str] = mapped_column(String(60))
    kind: Mapped[str] = mapped_column(String(60))  # e.g. recovery_point_selection
    decision: Mapped[str] = mapped_column(Text)
    confidence: Mapped[float] = mapped_column(Float, default=0.8)
    evidence_ids: Mapped[list] = mapped_column(JSON, default=list)  # evidence public refs (ints as str)
    alternatives: Mapped[list] = mapped_column(JSON, default=list)
    risk_level: Mapped[str] = mapped_column(String(20), default="medium")
    requires_approval: Mapped[bool] = mapped_column(Boolean, default=False)
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    reasoning: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime)


class RiskAssessment(Base):
    __tablename__ = "risk_assessments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    investigation_id: Mapped[int] = mapped_column(ForeignKey("investigations.id"), index=True)
    score: Mapped[int] = mapped_column(Integer)  # 0..100
    band: Mapped[str] = mapped_column(String(20))  # low|medium|high|critical
    rationale: Mapped[str] = mapped_column(Text, default="")
    factors: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime)


class Approval(Base):
    __tablename__ = "approvals"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    public_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    investigation_id: Mapped[int] = mapped_column(ForeignKey("investigations.id"), index=True)
    decision_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="pending")  # pending|approved|rejected
    requested_by: Mapped[str] = mapped_column(String(80), default="system:recovery-planner")
    decided_by: Mapped[Optional[str]] = mapped_column(String(80), nullable=True)
    note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    requested_at: Mapped[datetime] = mapped_column(DateTime)
    decided_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)


class Action(Base):
    """Ordered recovery plan step."""

    __tablename__ = "actions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    investigation_id: Mapped[int] = mapped_column(ForeignKey("investigations.id"), index=True)
    public_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    seq: Mapped[int] = mapped_column(Integer)
    action_type: Mapped[str] = mapped_column(String(60))
    tool_name: Mapped[str] = mapped_column(String(60))
    target_asset: Mapped[str] = mapped_column(String(120))
    tier: Mapped[int] = mapped_column(Integer, default=0)
    source_snapshot_label: Mapped[Optional[str]] = mapped_column(String(60), nullable=True)
    estimated_rto_seconds: Mapped[float] = mapped_column(Float, default=0.0)
    expected_rpo_seconds: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    validation_test: Mapped[str] = mapped_column(String(80), default="")
    risk_level: Mapped[str] = mapped_column(String(20), default="high")
    rollback_option: Mapped[str] = mapped_column(String(200), default="")
    status: Mapped[str] = mapped_column(String(20), default="pending")  # pending|executed|failed|skipped|cancelled
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    detail: Mapped[dict] = mapped_column(JSON, default=dict)


class Outcome(Base):
    __tablename__ = "outcomes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    investigation_id: Mapped[int] = mapped_column(ForeignKey("investigations.id"), index=True)
    result: Mapped[str] = mapped_column(String(30))  # completed|failed|rolled_back|rejected
    measured_rto_seconds: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    planned_rto_seconds: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    measured_rpo_seconds: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    clean_point_label: Mapped[Optional[str]] = mapped_column(String(60), nullable=True)
    dependency_order_correct: Mapped[bool] = mapped_column(Boolean, default=False)
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime)
    updated_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)


class Validation(Base):
    __tablename__ = "validations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    investigation_id: Mapped[int] = mapped_column(ForeignKey("investigations.id"), index=True)
    phase: Mapped[str] = mapped_column(String(30))  # dry_run|post_restore
    name: Mapped[str] = mapped_column(String(80))
    target: Mapped[Optional[str]] = mapped_column(String(120), nullable=True)
    passed: Mapped[bool] = mapped_column(Boolean, default=False)
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime)


class MetricSnapshot(Base):
    __tablename__ = "metric_snapshots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    investigation_id: Mapped[int] = mapped_column(ForeignKey("investigations.id"), index=True)
    name: Mapped[str] = mapped_column(String(80), index=True)
    value: Mapped[float] = mapped_column(Float)
    unit: Mapped[str] = mapped_column(String(20), default="s")
    labels: Mapped[dict] = mapped_column(JSON, default=dict)
    recorded_at: Mapped[datetime] = mapped_column(DateTime)


class EvaluationRun(Base):
    __tablename__ = "evaluation_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    public_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    scenario: Mapped[str] = mapped_column(String(60))
    passed: Mapped[bool] = mapped_column(Boolean, default=False)
    detection_correct: Mapped[bool] = mapped_column(Boolean, default=False)
    clean_point_correct: Mapped[bool] = mapped_column(Boolean, default=False)
    ordering_correct: Mapped[bool] = mapped_column(Boolean, default=False)
    rpo_within_bound: Mapped[bool] = mapped_column(Boolean, default=False)
    clean_point_accuracy: Mapped[float] = mapped_column(Float, default=0.0)
    ordering_accuracy: Mapped[float] = mapped_column(Float, default=0.0)
    achieved_rpo_seconds: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    achieved_rto_seconds: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    results: Mapped[dict] = mapped_column(JSON, default=dict)
    duration_ms: Mapped[float] = mapped_column(Float, default=0.0)
    created_at: Mapped[datetime] = mapped_column(DateTime)


class ToolCall(Base):
    """Audit trail for every registered-tool invocation (success or refusal)."""

    __tablename__ = "tool_calls"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    investigation_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("investigations.id"), index=True, nullable=True
    )
    tool_name: Mapped[str] = mapped_column(String(60), index=True)
    arguments: Mapped[dict] = mapped_column(JSON, default=dict)  # redacted before persist
    status: Mapped[str] = mapped_column(String(30))  # success|denied|error|schema_rejected|unknown_tool
    risk_level: Mapped[str] = mapped_column(String(20), default="low")
    approval_present: Mapped[bool] = mapped_column(Boolean, default=False)
    summary: Mapped[str] = mapped_column(Text, default="")
    result: Mapped[dict] = mapped_column(JSON, default=dict)
    duration_ms: Mapped[float] = mapped_column(Float, default=0.0)
    created_at: Mapped[datetime] = mapped_column(DateTime)
