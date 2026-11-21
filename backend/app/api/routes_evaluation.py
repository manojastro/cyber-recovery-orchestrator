"""Evaluation + debug routes."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.api.deps import get_app_settings, get_db
from app.evaluation.runner import load_ground_truth, run_evaluation
from app.models import EvaluationRun, Investigation
from app.schemas import EvaluationRunRequest

router = APIRouter(prefix="/api/v1", tags=["evaluation"])


@router.post("/evaluation/run")
def evaluation_run(request: EvaluationRunRequest,
                   session: Session = Depends(get_db),
                   settings=Depends(get_app_settings)) -> dict:
    """Replay a labeled scenario end-to-end and score against ground truth.

    Note: reseeds the lab (destructive to current lab state).
    """
    result = run_evaluation(session, settings, scenario=request.scenario)
    return result


@router.get("/evaluation/runs")
def evaluation_runs(session: Session = Depends(get_db)) -> list[dict]:
    runs = session.query(EvaluationRun).order_by(EvaluationRun.id.desc()).all()
    return [{"evaluation_id": r.public_id, "scenario": r.scenario,
             "passed": r.passed, "detection_correct": r.detection_correct,
             "clean_point_correct": r.clean_point_correct,
             "ordering_correct": r.ordering_correct,
             "rpo_within_bound": r.rpo_within_bound,
             "achieved_rpo_seconds": r.achieved_rpo_seconds,
             "created_at": r.created_at} for r in runs]


@router.get("/evaluation/ground-truth")
def ground_truth() -> dict:
    return load_ground_truth()


# ------------------------------------------------------------- debug routes

debug_router = APIRouter(prefix="/api/v1/debug", tags=["debug"])


@debug_router.post("/faults")
def inject_fault(request: dict, session: Session = Depends(get_db),
                 request_starlette: Request = None) -> dict:
    """Fault injection for failure-path tests/demos. Only available when
    ENABLE_FAULT_INJECTION=true (route not registered otherwise)."""
    kind = request.get("kind")
    investigation_id = request.get("investigation_id")
    if kind != "post_validation_failure":
        raise HTTPException(status_code=422, detail="unsupported fault kind")
    investigation = session.query(Investigation).filter(
        Investigation.public_id == investigation_id).first()
    if investigation is None:
        raise HTTPException(status_code=404,
                            detail=f"unknown investigation: {investigation_id}")
    faults = investigation.context.get("fault_inject") or {}
    faults["post_validation_failure"] = True
    investigation.context = {**investigation.context, "fault_inject": faults}
    session.commit()
    return {"status": "armed",
            "fault": "post_validation_failure will fail the business-transaction "
                     "check on next verification"}
