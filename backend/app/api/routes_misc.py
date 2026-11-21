"""Evidence, decisions, validations, audit-trail and metrics-summary routes."""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.api.deps import get_app_settings, get_db
from app.models import (
    Decision,
    Evidence,
    Investigation,
    Outcome,
    ToolCall,
    Validation,
)
from app.schemas import DecisionOut, EvidenceOut, ToolCallOut, ValidationOut

router = APIRouter(prefix="/api/v1", tags=["case-file"])


@router.get("/evidence", response_model=list[EvidenceOut])
def list_evidence(investigation_id: str = Query(...),
                  session: Session = Depends(get_db)) -> list[EvidenceOut]:
    investigation = _inv(session, investigation_id)
    rows = session.query(Evidence).filter(
        Evidence.investigation_id == investigation.id).order_by(Evidence.id).all()
    return [EvidenceOut.model_validate(r) for r in rows]


@router.get("/decisions", response_model=list[DecisionOut])
def list_decisions(investigation_id: str = Query(...),
                   session: Session = Depends(get_db)) -> list[DecisionOut]:
    investigation = _inv(session, investigation_id)
    rows = session.query(Decision).filter(
        Decision.investigation_id == investigation.id).order_by(Decision.id).all()
    return [DecisionOut.model_validate(r) for r in rows]


@router.get("/validations", response_model=list[ValidationOut])
def list_validations(investigation_id: Optional[str] = Query(None),
                     phase: Optional[str] = Query(None),
                     session: Session = Depends(get_db)) -> list[ValidationOut]:
    query = session.query(Validation)
    if investigation_id:
        investigation = _inv(session, investigation_id)
        query = query.filter(Validation.investigation_id == investigation.id)
    if phase in ("dry_run", "post_restore"):
        query = query.filter(Validation.phase == phase)
    rows = query.order_by(Validation.id).all()
    return [ValidationOut.model_validate(r) for r in rows]


@router.get("/tool-calls", response_model=list[ToolCallOut])
def list_tool_calls(investigation_id: Optional[str] = Query(None),
                    limit: int = Query(200, ge=1, le=1000),
                    session: Session = Depends(get_db)) -> list[ToolCallOut]:
    query = session.query(ToolCall)
    if investigation_id:
        investigation = _inv(session, investigation_id)
        query = query.filter(ToolCall.investigation_id == investigation.id)
    rows = query.order_by(ToolCall.id.desc()).limit(limit).all()
    return [ToolCallOut.model_validate(r) for r in rows]


@router.get("/metrics/summary")
def metrics_summary(session: Session = Depends(get_db),
                    settings=Depends(get_app_settings)) -> dict:
    from app.models import Approval
    investigations_total = session.query(Investigation).count()
    outcomes = session.query(Outcome).order_by(Outcome.id.desc()).all()

    completed = sum(1 for o in outcomes if o.result == "completed")
    failed = sum(1 for o in outcomes if o.result == "failed")
    rolled_back = sum(1 for o in outcomes if o.result == "rolled_back")
    rejected = sum(1 for o in outcomes if o.result == "rejected")

    stage_rows = None  # computed below via StageRun import
    from app.models import StageRun as _StageRun
    stage_durations = [s.duration_ms for s in
                       session.query(_StageRun).all() if s.duration_ms]
    avg_stage_ms = (sum(stage_durations) / len(stage_durations)) if stage_durations else 0.0

    tool_calls = session.query(ToolCall).all()
    tool_errors = sum(1 for t in tool_calls if t.status != "success")

    last_outcome = None
    latest_eval_accuracy = None
    from app.models import EvaluationRun as _Eval
    latest_eval = session.query(_Eval).order_by(_Eval.id.desc()).first()
    if latest_eval:
        latest_eval_accuracy = latest_eval.clean_point_accuracy

    if outcomes:
        head = outcomes[0]
        last_outcome = {
            "result": head.result,
            "measured_rto_seconds": head.measured_rto_seconds,
            "planned_rto_seconds": head.planned_rto_seconds,
            "measured_rpo_seconds": head.measured_rpo_seconds,
            "clean_point_label": head.clean_point_label,
            "dependency_order_correct": head.dependency_order_correct,
            "details": head.details,
        }

    llm_latencies = [s.llm_latency_ms for s in session.query(_StageRun).all()]
    return {
        "investigations_total": investigations_total,
        "recoveries_completed": completed,
        "recoveries_failed": failed,
        "recoveries_rolled_back": rolled_back,
        "rejections": rejected,
        "avg_stage_duration_ms": round(avg_stage_ms, 2),
        "tool_calls_total": len(tool_calls),
        "tool_errors_total": tool_errors,
        "llm_mode": settings.llm_mode,
        "llm_avg_latency_ms": (round(sum(llm_latencies) / len(llm_latencies), 2)
                                if llm_latencies else 0.0),
        "clean_point_accuracy_last_evaluation": latest_eval_accuracy,
        "last_outcome": last_outcome,
    }


def _inv(session: Session, public_id: str) -> Investigation:
    investigation = session.query(Investigation).filter(
        Investigation.public_id == public_id).first()
    if investigation is None:
        raise HTTPException(status_code=404,
                            detail=f"unknown investigation: {public_id}")
    return investigation
