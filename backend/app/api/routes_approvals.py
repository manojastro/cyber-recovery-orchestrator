"""Approval routes: the mandatory human gate."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import get_app_settings, get_db
from app.models import Approval, Investigation
from app.schemas import ApprovalOut, ApprovalRequest
from app.workflow.engine import WorkflowEngine

router = APIRouter(prefix="/api/v1/approvals", tags=["approvals"])


@router.get("", response_model=list[ApprovalOut])
def list_approvals(session: Session = Depends(get_db)) -> list[ApprovalOut]:
    approvals = session.query(Approval).order_by(Approval.id.desc()).all()
    return [ApprovalOut.model_validate(a) for a in approvals]


@router.get("/{approval_public_id}", response_model=ApprovalOut)
def get_approval(approval_public_id: str,
                 session: Session = Depends(get_db)) -> ApprovalOut:
    approval = _get(session, approval_public_id)
    return ApprovalOut.model_validate(approval)


@router.post("/{approval_public_id}/approve")
def approve(approval_public_id: str, request: ApprovalRequest,
            session: Session = Depends(get_db),
            settings=Depends(get_app_settings)) -> dict:
    approval = _get(session, approval_public_id)
    investigation = session.query(Investigation).filter(
        Investigation.id == approval.investigation_id).first()
    engine = WorkflowEngine(session, settings)
    engine.approve(investigation, decided_by=request.decided_by, note=request.note)
    return {"status": "approved", "approval": approval_public_id,
            "investigation_state": investigation.current_state}


@router.post("/{approval_public_id}/reject")
def reject(approval_public_id: str, request: ApprovalRequest,
           session: Session = Depends(get_db),
           settings=Depends(get_app_settings)) -> dict:
    approval = _get(session, approval_public_id)
    investigation = session.query(Investigation).filter(
        Investigation.id == approval.investigation_id).first()
    engine = WorkflowEngine(session, settings)
    engine.reject(investigation, decided_by=request.decided_by, note=request.note)
    return {"status": "rejected", "approval": approval_public_id,
            "investigation_state": investigation.current_state,
            "note": "execution terminated; no actions were run"}


def _get(session: Session, public_id: str) -> Approval:
    approval = session.query(Approval).filter(
        Approval.public_id == public_id).first()
    if approval is None:
        raise HTTPException(status_code=404,
                            detail=f"unknown approval: {public_id}")
    return approval
