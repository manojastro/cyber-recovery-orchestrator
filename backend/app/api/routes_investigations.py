"""Investigation routes: list, full bundle, stage run, execute, rollback."""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import get_app_settings, get_db
from app.models import (
    Action,
    Approval,
    Asset,
    Decision,
    Event,
    Evidence,
    Hypothesis,
    Incident,
    Investigation,
    Outcome,
    RiskAssessment,
    StageRun,
    Validation,
)
from app.schemas import (
    ActionOut,
    ApprovalOut,
    AssetOut,
    DecisionOut,
    EventOut,
    EvidenceOut,
    HypothesisOut,
    IncidentOut,
    InvestigationBundle,
    OutcomeOut,
    RiskAssessmentOut,
    StageRunOut,
    ValidationOut,
)
from app.workflow.engine import (
    InvalidTransition,
    WorkflowEngine,
    get_investigation,
)

router = APIRouter(prefix="/api/v1/investigations", tags=["investigations"])


@router.get("")
def list_investigations(session: Session = Depends(get_db)) -> list[dict]:
    investigations = session.query(Investigation).order_by(
        Investigation.id.desc()).all()
    return [{"public_id": i.public_id, "incident": i.incident_public_id,
             "scenario": i.scenario, "state": i.current_state,
             "created_at": i.created_at} for i in investigations]


@router.get("/{investigation_id}", response_model=InvestigationBundle)
def get_investigation_bundle(investigation_id: str,
                             session: Session = Depends(get_db)) -> InvestigationBundle:
    investigation = _get(session, investigation_id)
    incident = session.query(Incident).filter(
        Incident.public_id == investigation.incident_public_id).first()
    if incident is None:
        raise HTTPException(status_code=500, detail="orphaned investigation")
    stages = session.query(StageRun).filter(
        StageRun.investigation_id == investigation.id).order_by(StageRun.seq).all()
    evidence = session.query(Evidence).filter(
        Evidence.investigation_id == investigation.id).order_by(Evidence.id).all()
    hypotheses = session.query(Hypothesis).filter(
        Hypothesis.investigation_id == investigation.id).order_by(Hypothesis.id).all()
    decisions = session.query(Decision).filter(
        Decision.investigation_id == investigation.id).order_by(Decision.id).all()
    risk = session.query(RiskAssessment).filter(
        RiskAssessment.investigation_id == investigation.id
    ).order_by(RiskAssessment.id.desc()).first()
    approvals = session.query(Approval).filter(
        Approval.investigation_id == investigation.id).order_by(Approval.id).all()
    actions = session.query(Action).filter(
        Action.investigation_id == investigation.id).order_by(Action.seq).all()
    validations = session.query(Validation).filter(
        Validation.investigation_id == investigation.id
    ).order_by(Validation.id).all()
    outcomes = session.query(Outcome).filter(
        Outcome.investigation_id == investigation.id).order_by(Outcome.id).all()
    timeline = session.query(Event).filter(
        (Event.incident_public_id == incident.public_id) |
        (Event.event_type.in_(["restore_database_snapshot",
                               "restore_storage_objects", "rotate_compromised_credentials"]))
    ).order_by(Event.ts).all()

    affected_names = set(investigation.context.get("affected_assets") or [])
    affected_assets = [AssetOut.model_validate(a) for a in session.query(Asset).filter(
        Asset.name.in_(affected_names)).order_by(Asset.tier, Asset.name).all()] \
        if affected_names else []

    return InvestigationBundle(
        investigation_id=investigation.public_id,
        incident=IncidentOut.model_validate(incident),
        current_state=investigation.current_state,
        failure_reason=investigation.failure_reason,
        scenario=investigation.scenario,
        created_at=investigation.created_at,
        updated_at=investigation.updated_at,
        stages=[StageRunOut.model_validate(s) for s in stages],
        evidence=[EvidenceOut.model_validate(e) for e in evidence],
        hypotheses=[HypothesisOut.model_validate(h) for h in hypotheses],
        decisions=[DecisionOut.model_validate(d) for d in decisions],
        risk_assessment=RiskAssessmentOut.model_validate(risk) if risk else None,
        approvals=[ApprovalOut.model_validate(a) for a in approvals],
        actions=[ActionOut.model_validate(a) for a in actions],
        validations=[ValidationOut.model_validate(v) for v in validations],
        outcomes=[OutcomeOut.model_validate(o) for o in outcomes],
        timeline=[EventOut.model_validate(e) for e in timeline],
        affected_assets=affected_assets,
    )


@router.post("/{investigation_id}/run")
def run_stages(investigation_id: str, session: Session = Depends(get_db),
               settings=Depends(get_app_settings)) -> dict:
    """Advance the workflow through all analysis stages to AWAITING_APPROVAL."""
    investigation = _get(session, investigation_id)
    engine = WorkflowEngine(session, settings)
    try:
        result = engine.run_to_approval(investigation)
    except InvalidTransition as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {"status": "awaiting_approval",
            "approval_public_id": result["approval_public_id"],
            "stages_completed": sorted(result["stages"].keys())}


@router.post("/{investigation_id}/execute")
def execute(investigation_id: str, session: Session = Depends(get_db),
            settings=Depends(get_app_settings)) -> dict:
    """Execute the approved plan and run post-restore verification."""
    investigation = _get(session, investigation_id)
    engine = WorkflowEngine(session, settings)
    try:
        result = engine.execute_and_verify(investigation)
    except InvalidTransition as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {"status": result["state"], **{k: v for k, v in result.items()
                                          if k != "state"}}


@router.post("/{investigation_id}/rollback")
def rollback(investigation_id: str, session: Session = Depends(get_db),
             settings=Depends(get_app_settings)) -> dict:
    investigation = _get(session, investigation_id)
    engine = WorkflowEngine(session, settings)
    try:
        result = engine.rollback(investigation)
    except InvalidTransition as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {"status": result["state"], "restored_rows": result["restored_rows"]}


def _get(session: Session, public_id: str) -> Investigation:
    investigation = get_investigation(session, public_id)
    if investigation is None:
        raise HTTPException(status_code=404,
                            detail=f"unknown investigation: {public_id}")
    return investigation
