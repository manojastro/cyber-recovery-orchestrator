"""Incident routes: scenario trigger, listing, detail, timeline events."""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import get_app_settings, get_db
from app.lab.detector import detect_incident
from app.lab.incident import inject_ransomware
from app.models import Event, Incident, Investigation
from app.schemas import EventOut, IncidentOut, TriggerIncidentRequest
from app.util import deterministic_id, utcnow
from app.workflow.engine import record_incident_detected

router = APIRouter(prefix="/api/v1/incidents", tags=["incidents"])


@router.post("/trigger")
def trigger_incident(request: TriggerIncidentRequest,
                     session: Session = Depends(get_db)) -> dict:
    """Inject the ransomware scenario, run deterministic detection, and create
    the investigation in state DETECTED."""
    incident = inject_ransomware(session, scenario=request.scenario)
    incident = detect_incident(session, incident)
    if incident.status != "open":
        raise HTTPException(
            status_code=409,
            detail="deterministic detector did NOT raise an incident for this "
                   "scenario; lab may be unseeded or already clean")

    existing = session.query(Investigation).filter(
        Investigation.incident_public_id == incident.public_id).first()
    if existing is None:
        investigation = Investigation(
            public_id=deterministic_id("investigation", incident.public_id),
            incident_public_id=incident.public_id,
            scenario=request.scenario, current_state="DETECTED",
            context={"affected_assets": [], "fault_inject": {},
                     "note": request.note},
            created_at=utcnow(), updated_at=utcnow())
        session.add(investigation)
        session.commit()
    else:
        investigation = existing
    record_incident_detected(request.scenario)

    return {
        "status": "detected",
        "incident_public_id": incident.public_id,
        "investigation_public_id": investigation.public_id,
        "state": investigation.current_state,
        "summary": incident.summary,
        "detection_stats": incident.detection_stats,
    }


@router.get("", response_model=list[IncidentOut])
def list_incidents(session: Session = Depends(get_db)) -> list[IncidentOut]:
    incidents = session.query(Incident).order_by(Incident.id.desc()).all()
    return [IncidentOut.model_validate(i) for i in incidents]


@router.get("/{incident_public_id}", response_model=IncidentOut)
def get_incident(incident_public_id: str,
                 session: Session = Depends(get_db)) -> IncidentOut:
    incident = _get(session, incident_public_id)
    return IncidentOut.model_validate(incident)


@router.get("/{incident_public_id}/events", response_model=list[EventOut])
def get_events(incident_public_id: str,
               session: Session = Depends(get_db)) -> list[EventOut]:
    _get(session, incident_public_id)
    events = session.query(Event).filter(
        (Event.incident_public_id == incident_public_id) |
        (Event.event_type.in_(["incident_detected", "backup_completed"]))
    ).order_by(Event.ts).all()
    return [EventOut.model_validate(e) for e in events]


def _get(session: Session, public_id: str) -> Incident:
    incident = session.query(Incident).filter(
        Incident.public_id == public_id).first()
    if incident is None:
        raise HTTPException(status_code=404,
                            detail=f"unknown incident: {public_id}")
    return incident
